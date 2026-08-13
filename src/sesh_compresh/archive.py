from __future__ import annotations

import errno
import functools
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterator

from .common import (
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    AppPaths,
    any_open,
    app_lock,
    atomic_json,
    cas_object_name_details,
    directory_identity_matches,
    ensure_private_subdirectory,
    ensure_safe_cas_shard,
    fsync_dir,
    identity_matches,
    iso_utc,
    load_json,
    new_run_id,
    open_file_paths,
    open_file_paths_for,
    parse_timestamp,
    prune_expired_plans,
    regular_directory_stat,
    regular_file_stat,
    safe_cas_object_path,
    safe_cas_root,
    safe_cas_shard,
    sha256_file,
    validate_run_id,
    utc_now,
    validate_private_subdirectory,
)
from .encryption import (
    cas_plaintext_sha256,
    encrypt_cas_payload,
    encryption_config,
    materialize_cas_payload,
    require_archive_identity,
)
from .history import record_history_after_success
from .dictionary_benchmark import (
    benchmark_dictionary_candidate,
    split_dictionary_corpus,
)


@dataclass(frozen=True)
class SessionUnit:
    provider: str
    session_id: str
    source_root: Path
    primary: Path
    retention_days: int


class SourceChangedError(RuntimeError):
    """An identity-pinned archive source changed before its commit."""


class UnsafeSessionTreeError(ValueError):
    """A provider or bundle tree contains an unsafe filesystem entry."""


def _assert_quarantine_device(paths: AppPaths, session: dict[str, Any]) -> None:
    state_device = paths.state.stat().st_dev
    source_device = Path(session["source_root"]).stat().st_dev
    if state_device != source_device:
        raise RuntimeError(
            f"quarantine device differs from source root: {session['source_root']}"
        )


def validate_planned_session(session: dict[str, Any]) -> None:
    required_strings = ("provider", "session_id", "source_root", "last_activity")
    if any(
        not isinstance(session.get(key), str) or not session[key]
        for key in required_strings
    ):
        raise ValueError("archive session has invalid required metadata")
    provider = session["provider"]
    if provider in {".", ".."} or "/" in provider or "\\" in provider:
        raise ValueError("archive session provider must be one path component")
    parse_timestamp(session["last_activity"])
    root = Path(session["source_root"])
    if not root.is_absolute():
        raise ValueError("archive session source root must be absolute")
    files = session.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("archive session must contain files")
    directories = session.get("directories", [])
    if not isinstance(directories, list):
        raise ValueError("archive session directories must be a list")
    seen: set[Path] = set()
    entries = [
        (member, "file", ("device", "inode", "size", "mtime_ns", "mode"))
        for member in files
    ] + [
        (member, "directory", ("device", "inode", "mtime_ns", "mode"))
        for member in directories
    ]
    for member, kind, identity_keys in entries:
        if not isinstance(member, dict):
            raise ValueError(f"archive session {kind} member must be an object")
        path_value = member.get("path")
        relative_value = member.get("relative")
        if not isinstance(path_value, str) or not isinstance(relative_value, str):
            raise ValueError(f"archive session {kind} path metadata is invalid")
        relative = Path(relative_value)
        path = Path(path_value)
        if (
            not relative.parts
            or relative.is_absolute()
            or ".." in relative.parts
            or path != root / relative
        ):
            raise ValueError(f"archive session {kind} escaped its source root")
        if path in seen:
            raise ValueError(f"archive session contains a duplicate path: {path}")
        seen.add(path)
        if any(not isinstance(member.get(key), int) for key in identity_keys):
            raise ValueError(f"archive session {kind} identity is invalid")


def _max_jsonl_timestamp(path: Path) -> datetime:
    latest: datetime | None = None
    with path.open(encoding="utf-8", errors="strict") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed JSONL at record {number}") from exc
            if not isinstance(item, dict) or "timestamp" not in item:
                continue
            value = item["timestamp"]
            if not isinstance(value, str):
                raise ValueError(f"non-string timestamp at record {number}")
            parsed = parse_timestamp(value)
            latest = parsed if latest is None or parsed > latest else latest
    if latest is None:
        raise ValueError("no valid top-level timestamp")
    return latest


def _regular_directory_chain_exists(directory: Path) -> bool:
    target_exists = True
    current = directory
    while True:
        try:
            regular_directory_stat(current)
        except FileNotFoundError:
            if current == directory:
                target_exists = False
        if current.parent == current:
            return target_exists
        current = current.parent


def _scan_session_bundle(
    source_root: Path, primary: Path
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Scan one primary and its exact sibling companion without following links."""

    try:
        primary.relative_to(source_root)
    except ValueError as exc:
        raise UnsafeSessionTreeError(
            f"session primary escaped its source root: {primary}"
        ) from exc
    try:
        parent_exists = _regular_directory_chain_exists(primary.parent)
    except (OSError, ValueError) as exc:
        raise UnsafeSessionTreeError(
            f"cannot scan session parent: {primary.parent}: {exc}"
        ) from exc
    if not parent_exists:
        raise UnsafeSessionTreeError(
            f"session primary parent is missing: {primary.parent}"
        )

    try:
        files = [
            {
                "path": str(primary),
                "relative": str(primary.relative_to(source_root)),
                **regular_file_stat(primary),
            }
        ]
    except (OSError, ValueError) as exc:
        raise UnsafeSessionTreeError(
            f"cannot scan session primary: {primary}: {exc}"
        ) from exc
    directories: list[dict[str, Any]] = []
    companion = primary.with_suffix("")
    try:
        companion_info = companion.lstat()
    except FileNotFoundError:
        return files, directories
    except OSError as exc:
        raise UnsafeSessionTreeError(
            f"cannot scan session companion: {companion}: {exc}"
        ) from exc
    if stat.S_ISLNK(companion_info.st_mode) or not stat.S_ISDIR(companion_info.st_mode):
        raise UnsafeSessionTreeError(
            f"session companion is not a safe directory: {companion}"
        )

    def visit(directory: Path) -> None:
        directories.append(
            {
                "path": str(directory),
                "relative": str(directory.relative_to(source_root)),
                **regular_directory_stat(directory),
            }
        )
        with os.scandir(directory) as entries:
            children = sorted(entries, key=lambda entry: entry.name)
        for entry in children:
            child = Path(entry.path)
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                raise UnsafeSessionTreeError(
                    f"session bundle contains a symlink: {child}"
                )
            if stat.S_ISDIR(info.st_mode):
                visit(child)
            elif stat.S_ISREG(info.st_mode):
                files.append(
                    {
                        "path": str(child),
                        "relative": str(child.relative_to(source_root)),
                        **regular_file_stat(child),
                    }
                )
            else:
                raise UnsafeSessionTreeError(
                    f"session bundle contains a special file: {child}"
                )

    try:
        visit(companion)
    except (OSError, ValueError) as exc:
        raise UnsafeSessionTreeError(
            f"cannot scan session companion: {companion}: {exc}"
        ) from exc
    return files, directories


def _safe_jsonl_files(root: Path, *, recursive: bool) -> Iterator[Path]:
    exists = _regular_directory_chain_exists(root)
    if not exists:
        return

    def visit(directory: Path) -> Iterator[Path]:
        with os.scandir(directory) as entries:
            children = sorted(entries, key=lambda entry: entry.name)
        for entry in children:
            child = Path(entry.path)
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                raise UnsafeSessionTreeError(
                    f"session provider contains a symlink: {child}"
                )
            if stat.S_ISDIR(info.st_mode):
                if recursive:
                    yield from visit(child)
            elif stat.S_ISREG(info.st_mode):
                if child.suffix == ".jsonl":
                    yield child
            else:
                raise UnsafeSessionTreeError(
                    f"session provider contains a special file: {child}"
                )

    yield from visit(root)


def discover_sessions(paths: AppPaths) -> Iterator[SessionUnit]:
    # Import lazily because observer maintenance reuses the archive
    # transaction primitives from this module.
    from .observer import ClaudeMemPaths

    observer = ClaudeMemPaths.discover(paths).observer_project
    claude_projects = paths.home / ".claude/projects"
    projects_exist = _regular_directory_chain_exists(claude_projects)
    if projects_exist:
        with os.scandir(claude_projects) as entries:
            projects = sorted(entries, key=lambda entry: entry.name)
        for entry in projects:
            project = Path(entry.path)
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                raise UnsafeSessionTreeError(
                    f"session provider contains a symlink: {project}"
                )
            if not stat.S_ISDIR(info.st_mode):
                if not stat.S_ISREG(info.st_mode):
                    raise UnsafeSessionTreeError(
                        f"session provider contains a special file: {project}"
                    )
                continue
            if project == observer:
                continue
            for primary in _safe_jsonl_files(project, recursive=False):
                yield SessionUnit(
                    "claude",
                    f"{project.name}:{primary.stem}",
                    project,
                    primary,
                    30,
                )

    for label, root in (
        ("codex", paths.home / ".codex/sessions"),
        ("codex-archived", paths.home / ".codex/archived_sessions"),
    ):
        sources = list(_safe_jsonl_files(root, recursive=True))
        companions = {source.with_suffix("") for source in sources}
        for source in sources:
            if any(parent in companions for parent in source.parents):
                continue
            yield SessionUnit(label, source.stem, root, source, 30)


def create_archive_plan(
    paths: AppPaths,
    now: datetime | None = None,
    *,
    source_device: int | None = None,
    run_id: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    if source_device is not None and (
        type(source_device) is not int or source_device < 0
    ):
        raise ValueError("archive source device must be a non-negative integer")
    paths.ensure_private()
    current = (now or utc_now()).astimezone(UTC)
    opened = open_file_paths()
    selected: list[dict[str, Any]] = []
    skipped: dict[str, int] = {}
    logical_bytes = 0

    for unit in discover_sessions(paths):
        try:
            members, directories = _scan_session_bundle(unit.source_root, unit.primary)
            if source_device is not None and any(
                item["device"] != source_device for item in [*members, *directories]
            ):
                raise RuntimeError("different filesystem")
            bundle_paths = [Path(item["path"]) for item in [*members, *directories]]
            if any_open(bundle_paths, opened):
                raise RuntimeError("open")
            timestamps = [
                _max_jsonl_timestamp(Path(member["path"]))
                for member in members
                if Path(member["path"]).suffix == ".jsonl"
            ]
            if not timestamps:
                raise ValueError("session bundle has no JSONL member")
            activity = max(timestamps)
            if activity > current - timedelta(days=unit.retention_days):
                raise RuntimeError("recent")
            unit_bytes = sum(member["size"] for member in members)
            selected.append(
                {
                    "provider": unit.provider,
                    "session_id": unit.session_id,
                    "source_root": str(unit.source_root),
                    "retention_days": unit.retention_days,
                    "last_activity": iso_utc(activity),
                    "files": members,
                    "directories": directories,
                }
            )
            logical_bytes += unit_bytes
        except UnsafeSessionTreeError:
            raise
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            reason = str(exc) or exc.__class__.__name__
            skipped[reason] = skipped.get(reason, 0) + 1

    run_id = new_run_id(current) if run_id is None else validate_run_id(run_id)
    plan = {
        "schema_version": SCHEMA_VERSION,
        "kind": "archive-plan",
        "run_id": run_id,
        "created_at": iso_utc(current),
        "expires_at": iso_utc(max(current, utc_now()) + timedelta(hours=2)),
        "logical_bytes": logical_bytes,
        "sessions": selected,
        "skipped": skipped,
    }
    plan_path = paths.state / "plans" / f"archive-{run_id}.json"
    prune_expired_plans(paths)
    atomic_json(plan_path, plan, replace=False)
    return plan_path, plan


def _zstd_binary() -> str:
    binary = shutil.which("zstd")
    if binary is None:
        for candidate in ("/opt/homebrew/bin/zstd", "/usr/local/bin/zstd"):
            if Path(candidate).is_file():
                return candidate
        raise RuntimeError("zstd is required")
    return binary


@functools.lru_cache(maxsize=None)
def _zstd_version(binary: str) -> str:
    result = subprocess.run(
        [binary, "--version"], capture_output=True, text=True, check=True
    )
    output = result.stdout.strip() or result.stderr.strip()
    return output.splitlines()[0] if output else "unknown"


def _verify_zstd(
    binary: str,
    object_path: Path,
    raw_hash: str,
    *,
    reference: Path | None = None,
    dictionary: Path | None = None,
    capture: Path | None = None,
) -> None:
    extra = [f"--patch-from={reference}"] if reference is not None else []
    if dictionary is not None:
        extra += ["-D", str(dictionary)]
    subprocess.run([binary, "-q", "-t", *extra, str(object_path)], check=True)
    process = subprocess.Popen(
        [binary, "-q", "-d", "--stdout", *extra, str(object_path)],
        stdout=subprocess.PIPE,
    )
    assert process.stdout is not None
    digest = hashlib.sha256()
    with process.stdout:
        if capture is None:
            while chunk := process.stdout.read(4 * 1024 * 1024):
                digest.update(chunk)
        else:
            with capture.open("wb") as out:
                while chunk := process.stdout.read(4 * 1024 * 1024):
                    digest.update(chunk)
                    out.write(chunk)
    status = process.wait()
    if status != 0:
        raise RuntimeError(f"zstd decode failed with status {status}")
    if digest.hexdigest() != raw_hash:
        raise RuntimeError("archive raw SHA-256 mismatch")


def _cas_frame_path(paths: AppPaths, relative: str) -> Path:
    return safe_cas_object_path(
        paths.archive,
        relative,
        kind="zstd",
        content_validation=encryption_config(paths) is None,
    )


@contextmanager
def materialize_archive_frame(
    paths: AppPaths,
    relative: str,
    *,
    expected_compressed_sha256: str | None = None,
) -> Iterator[Path]:
    stored = _cas_frame_path(paths, relative)
    with materialize_cas_payload(
        paths,
        stored,
        expected_sha256=expected_compressed_sha256,
    ) as frame:
        yield frame


def _publish_frame_payload(paths: AppPaths, frame: Path, target: Path) -> bool:
    publication = frame
    encrypted: Path | None = None
    if encryption_config(paths) is None:
        pass
    else:
        fd, raw = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".age", dir=target.parent
        )
        os.close(fd)
        encrypted = Path(raw)
        try:
            encrypted.unlink()
            encrypt_cas_payload(paths, frame, encrypted)
            with encrypted.open("rb") as handle:
                os.fsync(handle.fileno())
            publication = encrypted
        except BaseException:
            encrypted.unlink(missing_ok=True)
            raise
    try:
        os.link(publication, target, follow_symlinks=False)
    except FileExistsError:
        return False
    finally:
        if encrypted is not None:
            encrypted.unlink(missing_ok=True)
    target.chmod(0o600)
    fsync_dir(target.parent)
    return True


SIZE_TIER_MID = 1024**2
SIZE_TIER_LARGE = 8 * 1024**2
CHUNK_TARGET_BYTES = 1024**2
_CANARY_PROTOCOL = 1
_CANARY_BYTES = b'{"timestamp":"2000-01-01T00:00:00Z","type":"canary"}\n'
_CANARY_MODE = 0o640
_CANARY_MTIME_NS = 946_684_800_123_456_789
CHUNK_HASH_ALPHABET = frozenset("0123456789abcdef")


def _chunk_object_relative(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in CHUNK_HASH_ALPHABET for character in value)
    ):
        raise ValueError(f"archive chunk hash is invalid: {value}")
    return f"objects/sha256/{value[:2]}/{value}.zst"


def _chunk_records(
    source: Path, target: int = CHUNK_TARGET_BYTES, *, start: int = 0
) -> Iterator[bytes]:
    """Yield newline-aligned record groups of at least target bytes.

    A single record larger than the target becomes its own legal chunk, so a
    line is never split.
    """

    with source.open("rb") as handle:
        handle.seek(start)
        buffer = bytearray()
        for line in handle:
            buffer.extend(line)
            if len(buffer) >= target:
                yield bytes(buffer)
                buffer.clear()
        if buffer:
            yield bytes(buffer)


def _validate_jsonl_append(source: Path, start: int) -> None:
    """Require every byte after start to contain complete UTF-8 JSONL records."""

    with source.open("rb") as handle:
        handle.seek(start)
        for number, line in enumerate(handle, start=1):
            if not line.endswith(b"\n"):
                raise SourceChangedError(
                    f"append ends with an incomplete JSONL record: {source}"
                )
            try:
                json.loads(line.decode("utf-8", errors="strict"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise SourceChangedError(
                    f"append contains malformed JSONL at new record {number}: {source}"
                ) from exc


def _inherited_append_chunks(
    paths: AppPaths,
    source: Path,
    member: dict[str, Any],
    previous_manifest: dict[str, Any] | None,
    zstd: str,
) -> list[dict[str, Any]] | None:
    """Validate and return the immutable chunk prefix for one JSONL append."""

    if previous_manifest is None or source.suffix != ".jsonl":
        return None
    previous_member = previous_manifest["files"][0]
    chunks = previous_member.get("chunks")
    if not isinstance(chunks, list):
        return None

    previous_size = previous_member["size"]
    if member["size"] < previous_size:
        raise SourceChangedError(f"chunked JSONL source was truncated: {source}")

    prefix = hashlib.sha256()
    last_byte = b""
    remaining = previous_size
    with source.open("rb") as handle:
        while remaining:
            block = handle.read(min(4 * 1024 * 1024, remaining))
            if not block:
                raise SourceChangedError(
                    f"chunked JSONL source was truncated: {source}"
                )
            prefix.update(block)
            last_byte = block[-1:]
            remaining -= len(block)
    if prefix.hexdigest() != previous_member["raw_sha256"]:
        raise SourceChangedError(f"chunked JSONL source prefix was rewritten: {source}")
    if previous_size and last_byte != b"\n":
        raise SourceChangedError(
            f"prior chunked JSONL ends with an incomplete record: {source}"
        )

    with source.open("rb") as handle:
        for chunk in chunks:
            chunk_digest = hashlib.sha256()
            chunk_last_byte = b""
            remaining = chunk["size"]
            while remaining:
                block = handle.read(min(4 * 1024 * 1024, remaining))
                if not block:
                    raise RuntimeError(
                        "prior chunked archive does not match the live prefix"
                    )
                chunk_digest.update(block)
                chunk_last_byte = block[-1:]
                remaining -= len(block)
            if chunk_digest.hexdigest() != chunk["sha256"] or chunk_last_byte != b"\n":
                raise RuntimeError(
                    "prior chunked archive is not a record-aligned live prefix"
                )

    _validate_jsonl_append(source, previous_size)
    inherited = [dict(chunk) for chunk in chunks]
    with open(os.devnull, "wb") as sink:
        inherited_hash = _decode_chunks_to(paths, zstd, inherited, sink)
    if inherited_hash != previous_member["raw_sha256"]:
        raise RuntimeError("prior chunked archive raw SHA-256 mismatch")
    return inherited


def _ensure_chunk_object(paths: AppPaths, data: bytes, zstd: str) -> tuple[str, bool]:
    """Compress one chunk into the CAS, returning its path and new flag."""

    raw_hash = hashlib.sha256(data).hexdigest()
    shard = ensure_safe_cas_shard(paths.archive, raw_hash[:2])
    relative = f"objects/sha256/{raw_hash[:2]}/{raw_hash}.zst"
    target = shard / f"{raw_hash}.zst"
    if target.exists() or target.is_symlink():
        target = _cas_frame_path(paths, relative)
        try:
            with materialize_cas_payload(paths, target) as frame:
                _verify_zstd(zstd, frame, raw_hash)
        except (RuntimeError, subprocess.SubprocessError) as exc:
            raise RuntimeError(
                f"existing CAS object cannot be reused safely: {target}"
            ) from exc
        else:
            return relative, False

    fd, raw_tmp = tempfile.mkstemp(
        prefix=f".{raw_hash}.", suffix=".part", dir=target.parent
    )
    os.close(fd)
    tmp = Path(raw_tmp)
    try:
        tmp.chmod(0o600)
        with tmp.open("wb") as out:
            process = subprocess.Popen(
                [zstd, "-q", *_compression_flags(len(data)), "--check", "-T0"],
                stdin=subprocess.PIPE,
                stdout=out,
            )
            assert process.stdin is not None
            with process.stdin:
                process.stdin.write(data)
            if process.wait() != 0:
                raise RuntimeError(f"zstd chunk compression failed for {relative}")
        with tmp.open("rb") as handle:
            os.fsync(handle.fileno())
        _verify_zstd(zstd, tmp, raw_hash)
        ensure_safe_cas_shard(paths.archive, raw_hash[:2])
        created = _publish_frame_payload(paths, tmp, target)
        if not created:
            target = _cas_frame_path(paths, relative)
            with materialize_cas_payload(paths, target) as frame:
                _verify_zstd(zstd, frame, raw_hash)
        return relative, created
    finally:
        tmp.unlink(missing_ok=True)


def _compression_flags(size: int, *, referenced: bool = False) -> tuple[str, ...]:
    """Select zstd effort for one compression unit.

    Window log 27 stays within the zstd CLI's default decode memory limit, so
    restore and verify need no extra flags for long-mode frames.  Referenced
    units skip long mode because their window is dominated by the reference.
    """

    if size >= SIZE_TIER_LARGE:
        return ("-19",) if referenced else ("-19", "--long=27")
    if size >= SIZE_TIER_MID:
        return ("-12",)
    return ("-6",)


def load_provider_dictionary(
    paths: AppPaths, provider: str, *, warn: bool = True
) -> Path | None:
    """Resolve a provider's trained dictionary, or None when unusable.

    A missing or unverifiable dictionary only costs ratio, never integrity:
    compression falls back to plain frames.
    """

    if encryption_config(paths) is not None:
        return None
    pointer = paths.archive / "dictionaries" / f"{provider}.json"
    try:
        if pointer.is_symlink() or not pointer.is_file():
            return None
        payload = load_json(pointer)
        if (
            type(payload.get("schema_version")) is not int
            or payload["schema_version"] not in SUPPORTED_SCHEMA_VERSIONS
            or payload.get("kind") != "compression-dictionary"
            or payload.get("provider") != provider
        ):
            raise ValueError("dictionary pointer mismatch")
        relative = payload.get("object")
        raw_sha256 = payload.get("raw_sha256")
        if (
            not isinstance(relative, str)
            or not isinstance(raw_sha256, str)
            or Path(relative).name != f"{raw_sha256}.dict"
        ):
            raise ValueError("dictionary pointer object is invalid")
        object_path = safe_cas_object_path(paths.archive, relative, kind="dictionary")
        if sha256_file(object_path) != raw_sha256:
            raise ValueError("dictionary object digest mismatch")
        return object_path
    except (OSError, ValueError, RuntimeError) as exc:
        if warn:
            print(
                f"sesh-compresh: ignoring dictionary for {provider}: {exc}",
                file=sys.stderr,
            )
        return None


def _ensure_object(
    paths: AppPaths,
    source: Path,
    raw_hash: str,
    zstd: str,
    *,
    reference: Path | None = None,
    dictionary: Path | None = None,
) -> tuple[Path, str, bool, str | None, bool]:
    """Compress source into the CAS.

    Returns the object path, its compressed hash, whether the stored frame
    decodes through reference content, the dictionary object it decodes
    through (if any), and whether this call published the object. Legacy
    raw-addressed frames remain reusable, but a frame that needs a different
    recipe is published under its raw and compressed hashes.
    """

    shard = ensure_safe_cas_shard(paths.archive, raw_hash[:2])
    legacy_relative = f"objects/sha256/{raw_hash[:2]}/{raw_hash}.zst"
    legacy_target = shard / f"{raw_hash}.zst"
    if legacy_target.exists() or legacy_target.is_symlink():
        legacy_target = _cas_frame_path(paths, legacy_relative)
        try:
            with materialize_cas_payload(paths, legacy_target) as frame:
                _verify_zstd(
                    zstd,
                    frame,
                    raw_hash,
                    reference=reference,
                    dictionary=dictionary,
                )
        except (RuntimeError, subprocess.SubprocessError):
            pass
        else:
            used_dictionary = (
                str(dictionary.relative_to(paths.archive))
                if dictionary is not None
                else None
            )
            return (
                legacy_target,
                cas_plaintext_sha256(paths, legacy_target),
                reference is not None,
                used_dictionary,
                False,
            )

    fd, raw_tmp = tempfile.mkstemp(prefix=f".{raw_hash}.", suffix=".part", dir=shard)
    os.close(fd)
    tmp = Path(raw_tmp)
    try:
        tmp.chmod(0o600)
        referenced = reference is not None
        flags = [*_compression_flags(source.stat().st_size, referenced=referenced)]
        if referenced:
            flags.append(f"--patch-from={reference}")
        if dictionary is not None:
            flags += ["-D", str(dictionary)]
        subprocess.run(
            [zstd, "-q", *flags, "--check", "-T0", "-f", str(source), "-o", str(tmp)],
            check=True,
        )
        with tmp.open("rb") as handle:
            os.fsync(handle.fileno())
        _verify_zstd(zstd, tmp, raw_hash, reference=reference, dictionary=dictionary)
        compressed_hash = sha256_file(tmp)
        relative = f"objects/sha256/{raw_hash[:2]}/{raw_hash}.{compressed_hash}.zst"
        target = shard / f"{raw_hash}.{compressed_hash}.zst"
        created = _publish_frame_payload(paths, tmp, target)
        target = _cas_frame_path(paths, relative)
        with materialize_cas_payload(
            paths, target, expected_sha256=compressed_hash
        ) as frame:
            _verify_zstd(
                zstd,
                frame,
                raw_hash,
                reference=reference,
                dictionary=dictionary,
            )
        used_dictionary = (
            str(dictionary.relative_to(paths.archive))
            if dictionary is not None
            else None
        )
        return target, compressed_hash, referenced, used_dictionary, created
    finally:
        tmp.unlink(missing_ok=True)


def _manifest_key(session: dict[str, Any]) -> str:
    # The primary member's relative path disambiguates sessions that share a
    # provider, root, and session id, such as same-stem Codex rollouts nested
    # in different date subdirectories.
    primary = session["files"][0]["relative"]
    seed = (
        f"{session['provider']}\0{session['source_root']}\0"
        f"{session['session_id']}\0{primary}"
    ).encode()
    return hashlib.sha256(seed).hexdigest()[:20]


_ARCHIVE_VERSION_ID = re.compile(
    r"^(?P<key>[0-9a-f]{20})-v(?P<version>[0-9]{16})-(?P<token>[0-9a-f]{32})$"
)
_LATEST_INDEX_KEYS = {
    "schema_version",
    "kind",
    "provider",
    "session_key",
    "version",
    "archive_id",
    "archived_at",
    "manifest",
}


def _manifest_session_key(manifest: dict[str, Any]) -> str:
    key = _manifest_key(manifest)
    archive_id = manifest.get("archive_id")
    match = (
        _ARCHIVE_VERSION_ID.fullmatch(archive_id)
        if isinstance(archive_id, str)
        else None
    )
    if archive_id != key and (match is None or match.group("key") != key):
        raise ValueError("archive id does not match its stable session key")
    return key


def _manifest_version(manifest: dict[str, Any]) -> int:
    archive_id = manifest["archive_id"]
    if archive_id == _manifest_key(manifest):
        return 0
    match = _ARCHIVE_VERSION_ID.fullmatch(archive_id)
    if match is None or match.group("key") != _manifest_key(manifest):
        raise ValueError("archive id does not contain a valid version")
    return int(match.group("version"))


def _next_archive_id(paths: AppPaths, session: dict[str, Any]) -> str:
    key = _manifest_key(session)
    versions = []
    for manifest_path in iter_manifests(paths):
        manifest = validate_manifest(manifest_path)
        try:
            if (
                manifest["provider"] == session["provider"]
                and _manifest_session_key(manifest) == key
            ):
                versions.append(_manifest_version(manifest))
        except ValueError:
            continue
    version = max(versions, default=0) + 1
    if version > 9_999_999_999_999_999:
        raise OverflowError(f"archive version space is exhausted: {key}")
    token = new_run_id(utc_now()).rsplit("-", 1)[1]
    return f"{key}-v{version:016d}-{token}"


def _latest_session_manifest(
    paths: AppPaths, session: dict[str, Any]
) -> dict[str, Any] | None:
    """Return the authoritative latest manifest for one stable session key."""

    key = _manifest_key(session)
    versions: list[tuple[int, str, dict[str, Any]]] = []
    for manifest_path in iter_manifests(paths):
        manifest = validate_manifest(manifest_path)
        try:
            if (
                manifest["provider"] == session["provider"]
                and _manifest_session_key(manifest) == key
            ):
                versions.append(
                    (
                        _manifest_version(manifest),
                        manifest["archive_id"],
                        manifest,
                    )
                )
        except ValueError:
            continue
    return max(versions)[2] if versions else None


def _latest_index_path(paths: AppPaths, provider: str, session_key: str) -> Path:
    if (
        not provider
        or provider in {".", ".."}
        or "/" in provider
        or "\\" in provider
        or not re.fullmatch(r"[0-9a-f]{20}", session_key)
    ):
        raise ValueError("archive latest index identity is invalid")
    root = ensure_private_subdirectory(paths.state, "latest")
    return root / f"{provider}-{session_key}.json"


def _latest_index_payload(
    paths: AppPaths, manifest_path: Path, manifest: dict[str, Any]
) -> tuple[Path, dict[str, Any]]:
    session_key = _manifest_session_key(manifest)
    provider = manifest["provider"]
    expected = paths.archive / "manifests" / provider / f"{manifest['archive_id']}.json"
    if manifest_path != expected:
        raise ValueError("archive manifest path does not match its archive id")
    return _latest_index_path(paths, provider, session_key), {
        "schema_version": SCHEMA_VERSION,
        "kind": "archive-latest",
        "provider": provider,
        "session_key": session_key,
        "version": _manifest_version(manifest),
        "archive_id": manifest["archive_id"],
        "archived_at": manifest["archived_at"],
        "manifest": str(manifest_path.relative_to(paths.archive)),
    }


def _validate_latest_index(
    paths: AppPaths, index_path: Path
) -> tuple[dict[str, Any], Path]:
    regular_file_stat(index_path)
    index = load_json(index_path)
    if set(index) != _LATEST_INDEX_KEYS or (
        type(index.get("schema_version")) is not int
        or index["schema_version"] not in SUPPORTED_SCHEMA_VERSIONS
        or index.get("kind") != "archive-latest"
        or any(
            type(index.get(key)) is not str or not index[key] or "\0" in index[key]
            for key in (
                "provider",
                "session_key",
                "archive_id",
                "archived_at",
                "manifest",
            )
        )
    ):
        raise ValueError(f"archive latest index is invalid: {index_path}")
    if type(index.get("version")) is not int or index["version"] < 0:
        raise ValueError(f"archive latest index is invalid: {index_path}")
    expected_index = _latest_index_path(paths, index["provider"], index["session_key"])
    manifest_path = paths.archive / index["manifest"]
    expected_manifest = (
        paths.archive / "manifests" / index["provider"] / f"{index['archive_id']}.json"
    )
    if index_path != expected_index or manifest_path != expected_manifest:
        raise ValueError(f"archive latest index path is invalid: {index_path}")
    manifest = validate_manifest(manifest_path)
    if (
        manifest["archive_id"] != index["archive_id"]
        or manifest["provider"] != index["provider"]
        or manifest["archived_at"] != index["archived_at"]
        or _manifest_session_key(manifest) != index["session_key"]
        or _manifest_version(manifest) != index["version"]
    ):
        raise ValueError(f"archive latest index target is invalid: {index_path}")
    return index, manifest_path


def _publish_latest_index(
    paths: AppPaths,
    manifest_path: Path,
    manifest: dict[str, Any],
) -> Path:
    index_path, payload = _latest_index_payload(paths, manifest_path, manifest)
    if index_path.exists() or index_path.is_symlink():
        try:
            current, _ = _validate_latest_index(paths, index_path)
        except (FileNotFoundError, ValueError):
            if index_path.is_symlink():
                raise
        else:
            if current == payload:
                fsync_dir(index_path.parent)
                return index_path
    atomic_json(index_path, payload)
    return index_path


def resolve_latest_manifest(paths: AppPaths, provider: str, session_key: str) -> Path:
    """Resolve the latest immutable version for one stable session key."""

    with app_lock(paths):
        paths.ensure_private()
        index_path = _latest_index_path(paths, provider, session_key)
        versions = []
        for manifest_path in iter_manifests(paths):
            manifest = validate_manifest(manifest_path)
            if manifest["provider"] != provider:
                continue
            try:
                key = _manifest_session_key(manifest)
            except ValueError:
                continue
            if key == session_key:
                versions.append(
                    (
                        _manifest_version(manifest),
                        manifest["archive_id"],
                        manifest_path,
                        manifest,
                    )
                )
        if not versions:
            if index_path.exists() and not index_path.is_symlink():
                regular_file_stat(index_path)
                index_path.unlink()
                fsync_dir(index_path.parent)
            raise ValueError(
                f"no archive versions match latest reference: {provider}:{session_key}"
            )
        _, _, manifest_path, manifest = max(versions)
        try:
            _, current_path = _validate_latest_index(paths, index_path)
        except (FileNotFoundError, ValueError):
            current_path = None
        if current_path != manifest_path:
            _publish_latest_index(paths, manifest_path, manifest)
        return manifest_path


def _refresh_latest_indexes(
    paths: AppPaths, provider: str, session_keys: set[str]
) -> None:
    if not session_keys:
        return
    retained: dict[str, list[tuple[int, str, Path, dict[str, Any]]]] = {
        key: [] for key in session_keys
    }
    for manifest_path in iter_manifests(paths):
        manifest = validate_manifest(manifest_path)
        if manifest["provider"] != provider:
            continue
        try:
            key = _manifest_session_key(manifest)
        except ValueError:
            continue
        if key in retained:
            retained[key].append(
                (
                    _manifest_version(manifest),
                    manifest["archive_id"],
                    manifest_path,
                    manifest,
                )
            )
    for key, versions in retained.items():
        index_path = _latest_index_path(paths, provider, key)
        if versions:
            _, _, manifest_path, manifest = max(versions)
            try:
                _, current_target = _validate_latest_index(paths, index_path)
            except (FileNotFoundError, ValueError):
                current_target = None
            if current_target != manifest_path:
                _publish_latest_index(paths, manifest_path, manifest)
        elif index_path.exists() or index_path.is_symlink():
            regular_file_stat(index_path)
            index_path.unlink()
            fsync_dir(index_path.parent)


def _cleanup_published_quarantine(quarantine: Path) -> None:
    shutil.rmtree(quarantine / "files")
    (quarantine / "_manifest.json").unlink()
    (quarantine / "_restore.json").unlink()
    quarantine.rmdir()


def _archive_planned_session_locked(
    paths: AppPaths,
    session: dict[str, Any],
    *,
    zstd: str,
    quarantine_run: Path,
    before_move: Callable[[], None] | None = None,
    dictionary: Path | None = None,
) -> dict[str, Any]:
    """Archive one identity-pinned session transactionally.

    The caller owns policy checks such as age, references, and open files.
    This function owns the byte-integrity and source-to-quarantine transaction
    shared by ordinary archives and reference-aware observer maintenance.
    """

    validate_planned_session(session)
    if encryption_config(paths) is not None:
        # Resolve and authenticate the key before CAS writes, quarantine
        # creation, or source movement.
        require_archive_identity(paths)
        if dictionary is not None:
            raise RuntimeError(
                "archive dictionaries are disabled while encryption is enabled"
            )
    _assert_quarantine_device(paths, session)
    quarantine_root = paths.state / "quarantine"
    try:
        quarantine_relative = quarantine_run.relative_to(quarantine_root)
    except ValueError as exc:
        raise ValueError(
            f"quarantine run escaped the state root: {quarantine_run}"
        ) from exc
    if not quarantine_relative.parts:
        raise ValueError("quarantine run must be below the quarantine root")
    validate_private_subdirectory(paths.archive, "manifests", session["provider"])
    validate_private_subdirectory(paths.state, "quarantine", *quarantine_relative.parts)
    ensure_private_subdirectory(paths.archive, "manifests", session["provider"])
    ensure_private_subdirectory(paths.state, "quarantine", *quarantine_relative.parts)
    sources = [Path(member["path"]) for member in session["files"]]
    for source, member in zip(sources, session["files"], strict=True):
        if not identity_matches(source, member):
            raise SourceChangedError(f"source changed since plan: {source}")
    for member in session.get("directories", []):
        directory = Path(member["path"])
        if not directory_identity_matches(directory, member):
            raise SourceChangedError(
                f"bundle directory changed since plan: {directory}"
            )

    key = _manifest_key(session)
    archived_at = utc_now()
    archive_id = _next_archive_id(paths, session)
    previous_manifest = _latest_session_manifest(paths, session)
    for run in quarantine_root.iterdir():
        pending = run / key
        if pending.exists() or pending.is_symlink():
            raise RuntimeError(
                "quarantine item already exists; run archive recover before retrying: "
                f"{pending}"
            )
    quarantine = quarantine_run / key
    if quarantine.exists() or quarantine.is_symlink():
        raise RuntimeError(
            f"quarantine item already exists; run archive recover before retrying: {quarantine}"
        )
    manifest_path = (
        paths.archive / "manifests" / session["provider"] / f"{archive_id}.json"
    )
    if manifest_path.exists() or manifest_path.is_symlink():
        raise FileExistsError(f"archive manifest already exists: {manifest_path}")
    archived_members: list[dict[str, Any]] = []
    raw_bytes = 0
    cas_objects: list[dict[str, Any]] = []
    dictionary_objects: set[str] = set()
    for position, (source, member) in enumerate(
        zip(sources, session["files"], strict=True)
    ):
        raw_hash = sha256_file(source)
        if not identity_matches(source, member):
            raise SourceChangedError(f"source changed while hashing: {source}")
        reference = sources[0] if position else None
        inherited_chunks = (
            _inherited_append_chunks(paths, source, member, previous_manifest, zstd)
            if reference is None
            else None
        )
        if reference is None and (
            inherited_chunks is not None or member["size"] > CHUNK_TARGET_BYTES
        ):
            chunks = inherited_chunks or []
            for chunk in chunks:
                cas_objects.append(
                    {
                        "path": _chunk_object_relative(chunk["sha256"]),
                        "created": False,
                    }
                )
            inherited_bytes = sum(chunk["size"] for chunk in chunks)
            for data in _chunk_records(source, start=inherited_bytes):
                chunk_relative, created = _ensure_chunk_object(paths, data, zstd)
                chunks.append(
                    {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
                )
                cas_objects.append({"path": chunk_relative, "created": created})
            archived_members.append(
                {**member, "raw_sha256": raw_hash, "chunks": chunks}
            )
            raw_bytes += member["size"]
            continue
        active_dictionary = (
            dictionary if reference is None and member["size"] < SIZE_TIER_MID else None
        )
        (
            object_path,
            compressed_hash,
            used_reference,
            used_dictionary,
            created,
        ) = _ensure_object(
            paths,
            source,
            raw_hash,
            zstd,
            reference=reference,
            dictionary=active_dictionary,
        )
        entry = {
            **member,
            "raw_sha256": raw_hash,
            "compressed_sha256": compressed_hash,
            "object": str(object_path.relative_to(paths.archive)),
        }
        if used_reference:
            entry["reference"] = session["files"][0]["relative"]
        if used_dictionary is not None:
            entry["dictionary"] = used_dictionary
            dictionary_objects.add(used_dictionary)
        archived_members.append(entry)
        cas_objects.append(
            {
                "path": str(object_path.relative_to(paths.archive)),
                "created": created,
            }
        )
        raw_bytes += member["size"]

    extended = any(
        "reference" in member or "dictionary" in member or "chunks" in member
        for member in archived_members
    )
    manifest = {
        "schema_version": SCHEMA_VERSION if extended else 1,
        "kind": "session-archive",
        "archive_id": archive_id,
        "provider": session["provider"],
        "session_id": session["session_id"],
        "source_root": session["source_root"],
        "last_activity": session["last_activity"],
        "archived_at": iso_utc(archived_at),
        "zstd_version": _zstd_version(zstd),
        "files": archived_members,
        "directories": session.get("directories", []),
    }
    restore_record = quarantine / "_restore.json"
    staged_manifest = quarantine / "_manifest.json"
    resolved_source_root = Path(session["source_root"]).resolve(strict=True)
    source_root_info = resolved_source_root.stat()
    try:
        quarantine.mkdir(parents=True, mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise RuntimeError(
            f"quarantine item already exists; run archive recover before retrying: {quarantine}"
        ) from exc
    fsync_dir(quarantine.parent)
    atomic_json(staged_manifest, manifest)
    atomic_json(
        restore_record,
        {
            "schema_version": SCHEMA_VERSION,
            "source_root": session["source_root"],
            "source_root_identity": {
                "resolved_path": str(resolved_source_root),
                "device": source_root_info.st_dev,
                "inode": source_root_info.st_ino,
            },
            "manifest": str(manifest_path),
            "files": [member["relative"] for member in archived_members],
            "directories": [
                item["relative"] for item in session.get("directories", [])
            ],
        },
    )
    moved: list[tuple[Path, Path]] = []
    removed_directories: list[tuple[Path, dict[str, Any]]] = []
    manifest_write_started = False
    try:
        _ensure_archive_canary(paths, zstd)
        for source, member in zip(sources, archived_members, strict=True):
            if not identity_matches(source, member):
                raise SourceChangedError(f"source changed before quarantine: {source}")
        if before_move is not None:
            before_move()
        for member in session.get("directories", []):
            directory = Path(member["path"])
            if not directory_identity_matches(directory, member):
                raise SourceChangedError(
                    f"bundle directory changed before quarantine: {directory}"
                )
        for source, member in zip(sources, archived_members, strict=True):
            destination = quarantine / "files" / member["relative"]
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.replace(source, destination)
            moved.append((source, destination))
            parent = destination.parent
            while True:
                fsync_dir(parent)
                if parent == quarantine:
                    break
                parent = parent.parent
            fsync_dir(source.parent)
        for _, destination in moved:
            relative = str(destination.relative_to(quarantine / "files"))
            expected_hash = next(
                member["raw_sha256"]
                for member in archived_members
                if member["relative"] == relative
            )
            if sha256_file(destination) != expected_hash:
                raise RuntimeError("quarantined source hash mismatch")
        directory_items = sorted(
            session.get("directories", []),
            key=lambda item: len(Path(item["path"]).parts),
            reverse=True,
        )
        for item in directory_items:
            directory = Path(item["path"])
            try:
                current = regular_directory_stat(directory)
            except (FileNotFoundError, ValueError):
                raise SourceChangedError(
                    f"bundle directory changed before removal: {directory}"
                )
            if any(current[key] != item[key] for key in ("device", "inode")):
                raise SourceChangedError(
                    f"bundle directory changed before removal: {directory}"
                )
            try:
                directory.rmdir()
            except OSError as exc:
                raise SourceChangedError(
                    f"bundle directory is no longer empty: {directory}"
                ) from exc
            removed_directories.append((directory, item))
            fsync_dir(directory.parent)
        manifest_write_started = True
        atomic_json(manifest_path, manifest, replace=False)
        _publish_latest_index(paths, manifest_path, manifest)
    except BaseException as error:
        try:
            manifest_visible = (
                manifest_write_started
                and not isinstance(error, FileExistsError)
                and not manifest_path.is_symlink()
                and manifest_path.is_file()
                and load_json(manifest_path) == manifest
            )
        except (OSError, ValueError):
            manifest_visible = False
        if manifest_visible:
            raise
        for directory, item in reversed(removed_directories):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            fsync_dir(directory.parent)
        for source, destination in reversed(moved):
            if destination.exists() and not source.exists():
                source.parent.mkdir(parents=True, exist_ok=True)
                os.replace(destination, source)
                fsync_dir(source.parent)
                fsync_dir(destination.parent)
        for directory, item in removed_directories:
            directory.chmod(item["mode"])
            os.utime(directory, ns=(item["mtime_ns"], item["mtime_ns"]))
            fsync_dir(directory)
        if not moved:
            shutil.rmtree(quarantine, ignore_errors=True)
        raise
    _cleanup_published_quarantine(quarantine)

    return {
        "manifest": str(manifest_path),
        "raw_bytes": raw_bytes,
        "_cas_objects": cas_objects,
        "_dictionary_objects": sorted(dictionary_objects),
    }


def _cas_inventory(paths: AppPaths) -> dict[str, tuple[int, int]]:
    root, _ = safe_cas_root(paths.archive)
    inventory = {}
    for shard_entry in sorted(root.iterdir()):
        shard, _ = safe_cas_shard(paths.archive, shard_entry.name)
        for candidate in sorted(shard.iterdir()):
            details = cas_object_name_details(candidate.name)
            if details is None:
                raise ValueError(f"archive CAS object name is invalid: {candidate}")
            if details[0] == "temporary":
                continue
            if details[1] != shard_entry.name:
                raise ValueError(
                    f"archive object is in the wrong CAS shard: {candidate}"
                )
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise ValueError(f"archive object is not a regular file: {candidate}")
            relative = str(candidate.relative_to(paths.archive))
            inventory[relative] = (info.st_size, info.st_blocks * 512)
    return inventory


def _archive_metrics(
    paths: AppPaths,
    results: list[dict[str, Any]],
    cas_before: dict[str, tuple[int, int]],
    free_bytes_before: int,
) -> dict[str, int]:
    objects: set[str] = set()
    reused_objects: set[str] = set()
    dictionaries: set[str] = set()
    logical_raw_bytes = sum(result["raw_bytes"] for result in results)
    for result in results:
        dictionaries.update(result["_dictionary_objects"])
        for item in result["_cas_objects"]:
            relative = item["path"]
            objects.add(relative)
            if not item["created"]:
                reused_objects.add(relative)

    object_stats = {
        relative: _cas_frame_path(paths, relative).stat() for relative in objects
    }
    dictionary_stats = {
        relative: safe_cas_object_path(
            paths.archive, relative, kind="dictionary"
        ).stat()
        for relative in dictionaries
    }
    compressed_bytes = sum(info.st_size for info in object_stats.values())
    dictionary_bytes = sum(info.st_size for info in dictionary_stats.values())
    logical_savings = logical_raw_bytes - compressed_bytes
    cas_after = _cas_inventory(paths)
    new_paths = cas_after.keys() - cas_before.keys()
    return {
        "logical_raw_bytes": logical_raw_bytes,
        "raw_bytes": logical_raw_bytes,
        "unique_cas_bytes": compressed_bytes + dictionary_bytes,
        "compressed_bytes": compressed_bytes,
        "unique_new_cas_bytes": sum(cas_after[relative][0] for relative in new_paths),
        "cas_allocated_bytes_change": (
            sum(value[1] for value in cas_after.values())
            - sum(value[1] for value in cas_before.values())
        ),
        "filesystem_free_bytes_change": (
            shutil.disk_usage(paths.archive).free - free_bytes_before
        ),
        "new_objects": len(new_paths),
        "reused_objects": len(reused_objects),
        "dictionary_objects": len(dictionaries),
        "dictionary_bytes": dictionary_bytes,
        "logical_savings_bytes": logical_savings,
        "reclaimed_bytes": logical_savings,
    }


def _archive_history_details(
    paths: AppPaths, sessions: list[dict[str, Any]], results: list[dict[str, Any]]
) -> tuple[dict[str, int], dict[str, int]]:
    sources = {
        f"{session['provider']}\0{_manifest_key(session)}": result["raw_bytes"]
        for session, result in zip(sessions, results, strict=True)
    }
    objects: dict[str, int] = {}
    for result in results:
        for item in result["_cas_objects"]:
            relative = item["path"]
            objects[relative] = _cas_frame_path(paths, relative).stat(
                follow_symlinks=False
            ).st_size
        for relative in result["_dictionary_objects"]:
            objects[relative] = safe_cas_object_path(
                paths.archive, relative, kind="dictionary"
            ).stat(follow_symlinks=False).st_size
    return sources, objects


def archive_planned_session(
    paths: AppPaths,
    session: dict[str, Any],
    *,
    zstd: str,
    quarantine_run: Path,
    before_move: Callable[[], None] | None = None,
    dictionary: Path | None = None,
) -> dict[str, Any]:
    with app_lock(paths):
        paths.ensure_private()
        cas_before = _cas_inventory(paths)
        free_bytes_before = shutil.disk_usage(paths.archive).free
        result = _archive_planned_session_locked(
            paths,
            session,
            zstd=zstd,
            quarantine_run=quarantine_run,
            before_move=before_move,
            dictionary=dictionary,
        )
        metrics = {
            "manifest": result["manifest"],
            **_archive_metrics(paths, [result], cas_before, free_bytes_before),
        }
        sources, objects = _archive_history_details(paths, [session], [result])
        return record_history_after_success(
            paths,
            metrics,
            operation="archive-direct",
            provider=session["provider"],
            logical_archived_bytes=metrics["logical_raw_bytes"],
            physical_allocated_bytes_delta=metrics["cas_allocated_bytes_change"],
            observed_free_bytes_delta=metrics["filesystem_free_bytes_change"],
            cas_objects=objects,
            sources=sources,
        )


def _apply_archive_plan_locked(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    paths.ensure_private()
    plan = load_json(plan_path)
    if (
        plan.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS
        or plan.get("kind") != "archive-plan"
    ):
        raise ValueError("unsupported archive plan")
    if utc_now() > parse_timestamp(plan["expires_at"]):
        raise RuntimeError("archive plan expired")
    sessions = plan.get("sessions")
    if not isinstance(sessions, list):
        raise ValueError("archive plan sessions must be a list")
    for session in sessions:
        if not isinstance(session, dict):
            raise ValueError("archive plan session must be an object")
        validate_planned_session(session)

    zstd = _zstd_binary()
    quarantine_run = paths.state / "quarantine" / plan["run_id"]
    dictionaries: dict[str, Path | None] = {}
    results: list[dict[str, Any]] = []
    cas_before = _cas_inventory(paths)
    free_bytes_before = shutil.disk_usage(paths.archive).free

    for session_number, session in enumerate(sessions, start=1):
        sources = [Path(member["path"]) for member in session["files"]]
        # A fresh targeted enumeration immediately before each transaction
        # cannot go stale across a long apply, and it fails closed when lsof
        # is unavailable instead of silently disabling the check.
        if any_open(sources, open_file_paths_for(sources)):
            raise RuntimeError(f"session became active: {session['session_id']}")
        provider = session["provider"]
        if provider not in dictionaries:
            dictionaries[provider] = load_provider_dictionary(paths, provider)
        result = _archive_planned_session_locked(
            paths,
            session,
            zstd=zstd,
            quarantine_run=quarantine_run,
            dictionary=dictionaries[provider],
        )
        results.append(result)
        if session_number % 500 == 0:
            print(
                f"archive progress: {session_number}/{len(sessions)} sessions committed",
                file=sys.stderr,
                flush=True,
            )

    if quarantine_run.exists() and not any(quarantine_run.iterdir()):
        quarantine_run.rmdir()
    metrics = {
        "sessions": len(results),
        "manifest_count": len(results),
        **_archive_metrics(paths, results, cas_before, free_bytes_before),
    }
    sources, objects = _archive_history_details(paths, sessions, results)
    return {
        **metrics,
        "_history_sources": sources,
        "_history_cas_objects": objects,
        "_history_providers": sorted({session["provider"] for session in sessions}),
    }


def apply_archive_plan(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    with app_lock(paths):
        result = _apply_archive_plan_locked(paths, plan_path)
        sources = result.pop("_history_sources")
        cas_objects = result.pop("_history_cas_objects")
        providers = result.pop("_history_providers")
        if result["sessions"] == 0:
            return result
        return record_history_after_success(
            paths,
            result,
            operation="archive-apply",
            provider=providers[0] if len(providers) == 1 else None,
            logical_archived_bytes=result["logical_raw_bytes"],
            physical_allocated_bytes_delta=result["cas_allocated_bytes_change"],
            observed_free_bytes_delta=result["filesystem_free_bytes_change"],
            cas_objects=cas_objects,
            sources=sources,
        )


def _scan_manifest_paths(paths: AppPaths) -> list[Path]:
    paths.ensure_private()
    root = paths.archive / "manifests"
    result = []
    with os.scandir(root) as entries:
        providers = sorted(entries, key=lambda entry: entry.name)
    for entry in providers:
        info = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"archive provider anchor is unsafe: {entry.path}")
    for entry in providers:
        provider = ensure_private_subdirectory(root, entry.name)
        with os.scandir(provider) as entries:
            manifests = sorted(entries, key=lambda item: item.name)
        for manifest in manifests:
            info = manifest.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise ValueError(f"archive manifest is unsafe: {manifest.path}")
            if manifest.name.endswith(".json"):
                result.append(Path(manifest.path))
    return result


def iter_manifests(paths: AppPaths) -> Iterator[Path]:
    # Import locally because portable archive validation reuses this module.
    from .portable import portable_manifest_visibility

    for _ in range(32):
        before = portable_manifest_visibility(paths)
        manifests = _scan_manifest_paths(paths)
        after = portable_manifest_visibility(paths)
        if before != after:
            continue
        _, hidden = before
        yield from (
            path
            for path in manifests
            if path.relative_to(paths.archive).as_posix() not in hidden
        )
        return
    raise RuntimeError("archive manifest visibility changed during enumeration")


_SIZE_BUCKETS = (
    ("lt_16_kib", 16 * 1024),
    ("16_to_64_kib", 64 * 1024),
    ("64_kib_to_1_mib", 1024**2),
    ("1_to_8_mib", 8 * 1024**2),
    ("gte_8_mib", None),
)

_MANIFEST_KEYS = {
    "schema_version",
    "kind",
    "archive_id",
    "provider",
    "session_id",
    "source_root",
    "last_activity",
    "archived_at",
    "zstd_version",
    "files",
    "directories",
}
_LEGACY_MANIFEST_KEYS = _MANIFEST_KEYS - {"zstd_version", "directories"}
_MEMBER_BASE_KEYS = {
    "path",
    "relative",
    "device",
    "inode",
    "size",
    "mtime_ns",
    "mode",
    "raw_sha256",
}
_DIRECTORY_KEYS = {"path", "relative", "device", "inode", "mtime_ns", "mode"}


def _manifest_int(record: dict[str, Any], key: str, manifest_path: Path) -> int:
    value = record.get(key)
    if type(value) is not int or value < 0:
        raise ValueError(f"archive manifest {key} is invalid: {manifest_path}")
    return value


def _manifest_sha256(value: Any, manifest_path: Path) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in CHUNK_HASH_ALPHABET for character in value)
    ):
        raise ValueError(f"archive manifest SHA-256 is invalid: {manifest_path}")
    return value


def _manifest_cas_object(
    value: Any, kind: str, manifest_path: Path
) -> tuple[str, str | None]:
    if not isinstance(value, str) or not value:
        raise ValueError(
            f"archive manifest has invalid CAS name for {kind}: {manifest_path}"
        )
    relative = Path(value)
    details = cas_object_name_details(relative.name)
    if (
        relative.is_absolute()
        or str(relative) != value
        or len(relative.parts) != 4
        or relative.parts[:2] != ("objects", "sha256")
        or details is None
        or details[0] != kind
        or relative.parts[2] != details[1]
    ):
        raise ValueError(
            f"archive manifest has invalid CAS name for {kind}: {manifest_path}"
        )
    return relative.name.split(".", 1)[0], details[2]


def _manifest_path_key(value: str) -> tuple[str, ...]:
    return tuple(
        unicodedata.normalize("NFC", part).casefold() for part in Path(value).parts
    )


def _validate_manifest_payload(
    manifest: dict[str, Any], manifest_path: Path
) -> dict[str, Any]:
    """Strictly validate one already-loaded supported session manifest."""

    schema = manifest.get("schema_version")
    if type(schema) is not int or schema not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(f"archive manifest schema is unsupported: {manifest_path}")
    if schema == 1 and set(manifest) == _LEGACY_MANIFEST_KEYS:
        manifest = {**manifest, "zstd_version": "unknown", "directories": []}
    elif set(manifest) != _MANIFEST_KEYS:
        raise ValueError(f"archive manifest shape is invalid: {manifest_path}")
    if manifest.get("kind") != "session-archive":
        raise ValueError(f"unsupported archive manifest: {manifest_path}")
    for key in ("archive_id", "provider", "session_id", "source_root", "zstd_version"):
        if (
            not isinstance(manifest.get(key), str)
            or not manifest[key]
            or "\0" in manifest[key]
        ):
            raise ValueError(f"archive manifest {key} is invalid: {manifest_path}")
    provider = manifest["provider"]
    if provider in {".", ".."} or "/" in provider or "\\" in provider:
        raise ValueError(f"archive manifest provider is invalid: {manifest_path}")
    root = Path(manifest["source_root"])
    if not root.is_absolute():
        raise ValueError(
            f"archive manifest source root must be absolute: {manifest_path}"
        )
    for key in ("last_activity", "archived_at"):
        if not isinstance(manifest.get(key), str):
            raise ValueError(f"archive manifest {key} is invalid: {manifest_path}")
        parse_timestamp(manifest[key])

    files = manifest.get("files")
    directories = manifest.get("directories")
    if not isinstance(files, list) or not files or not isinstance(directories, list):
        raise ValueError(f"archive manifest members are invalid: {manifest_path}")
    prior: set[str] = set()
    namespace: set[tuple[str, ...]] = set()
    file_keys: set[tuple[str, ...]] = set()
    for member in files:
        if not isinstance(member, dict):
            raise ValueError(f"archive manifest member is invalid: {manifest_path}")
        chunks = member.get("chunks")
        optional = {key for key in ("reference", "dictionary") if key in member}
        expected = (
            _MEMBER_BASE_KEYS
            | ({"chunks"} if chunks is not None else {"object", "compressed_sha256"})
            | optional
        )
        if set(member) != expected:
            raise ValueError(
                f"archive manifest member shape is invalid: {manifest_path}"
            )
        relative = member.get("relative")
        _validate_member_relative(relative)
        path_key = _manifest_path_key(relative)
        if path_key in namespace:
            raise ValueError(f"archive manifest member is duplicated: {manifest_path}")
        if member.get("path") != str(root / relative):
            raise ValueError(
                f"archive manifest member path is invalid: {manifest_path}"
            )
        for key in ("device", "inode", "size", "mtime_ns", "mode"):
            _manifest_int(member, key, manifest_path)
        if member["mode"] > 0o777:
            raise ValueError(f"archive manifest mode is invalid: {manifest_path}")
        _manifest_sha256(member.get("raw_sha256"), manifest_path)
        reference = member.get("reference")
        dictionary = member.get("dictionary")
        if len(optional) > 1:
            raise ValueError(f"archive manifest recipe is invalid: {manifest_path}")
        if "reference" in member:
            _validate_member_relative(reference)
            if reference not in prior:
                raise ValueError(
                    f"archive manifest reference is unresolved: {manifest_path}"
                )
        if "dictionary" in member:
            _manifest_cas_object(dictionary, "dictionary", manifest_path)
        if chunks is not None:
            if schema != 2 or optional or not isinstance(chunks, list) or not chunks:
                raise ValueError(
                    f"archive manifest chunks are invalid: {manifest_path}"
                )
            total = 0
            for chunk in chunks:
                if not isinstance(chunk, dict) or set(chunk) != {"sha256", "size"}:
                    raise ValueError(
                        f"archive manifest chunks are invalid: {manifest_path}"
                    )
                _chunk_object_relative(
                    _manifest_sha256(chunk.get("sha256"), manifest_path)
                )
                total += _manifest_int(chunk, "size", manifest_path)
            if total != member["size"]:
                raise ValueError(
                    f"archive manifest chunk size is invalid: {manifest_path}"
                )
        else:
            if optional and schema != 2:
                raise ValueError(
                    f"archive manifest recipe schema is invalid: {manifest_path}"
                )
            compressed = _manifest_sha256(
                member.get("compressed_sha256"), manifest_path
            )
            raw_name, compressed_name = _manifest_cas_object(
                member.get("object"), "zstd", manifest_path
            )
            if raw_name != member["raw_sha256"] or (
                compressed_name is not None and compressed_name != compressed
            ):
                raise ValueError(
                    f"archive manifest object hash is invalid: {manifest_path}"
                )
        prior.add(relative)
        namespace.add(path_key)
        file_keys.add(path_key)

    for directory in directories:
        if not isinstance(directory, dict) or set(directory) != _DIRECTORY_KEYS:
            raise ValueError(f"archive manifest directory is invalid: {manifest_path}")
        relative = directory.get("relative")
        _validate_member_relative(relative)
        path_key = _manifest_path_key(relative)
        if path_key in namespace:
            raise ValueError(
                f"archive manifest directory is duplicated: {manifest_path}"
            )
        if directory.get("path") != str(root / relative):
            raise ValueError(
                f"archive manifest directory path is invalid: {manifest_path}"
            )
        for key in ("device", "inode", "mtime_ns", "mode"):
            _manifest_int(directory, key, manifest_path)
        if directory["mode"] > 0o777:
            raise ValueError(f"archive manifest mode is invalid: {manifest_path}")
        namespace.add(path_key)
    if any(
        len(other) > len(file_key) and other[: len(file_key)] == file_key
        for file_key in file_keys
        for other in namespace
    ):
        raise ValueError(f"archive manifest file is a restore parent: {manifest_path}")
    return manifest


def validate_manifest(manifest_path: Path) -> dict[str, Any]:
    """Load and strictly validate one supported session manifest."""

    return _validate_manifest_payload(load_json(manifest_path), manifest_path)


_ARCHIVE_LIST_SORTS = {"activity", "archive", "raw", "ratio", "version"}


def _manifest_zstd_objects(manifest: dict[str, Any]) -> set[str]:
    objects = set()
    for member in manifest["files"]:
        chunks = member.get("chunks")
        if isinstance(chunks, list):
            objects.update(_chunk_object_relative(chunk["sha256"]) for chunk in chunks)
        else:
            objects.add(member["object"])
    return objects


def _parse_archive_list_date(value: Any) -> date:
    if type(value) is not str:
        raise ValueError("archive list date must use YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("archive list date must use YYYY-MM-DD") from exc
    if parsed.isoformat() != value:
        raise ValueError("archive list date must use YYYY-MM-DD")
    return parsed


def list_archives(
    paths: AppPaths,
    *,
    provider: str | None = None,
    session_id: str | None = None,
    archived_on: str | None = None,
    version: int | None = None,
    sort: str = "archive",
    reverse: bool = False,
) -> list[dict[str, Any]]:
    """Return validated archive versions with deterministic filtering and sorting."""

    for label, value in (("provider", provider), ("session ID", session_id)):
        if value is not None and type(value) is not str:
            raise ValueError(f"archive list {label} must be a string")
    if archived_on is not None and type(archived_on) is not str:
        raise ValueError("archive list date must use YYYY-MM-DD")
    if version is not None and (type(version) is not int or version < 0):
        raise ValueError("archive list version must be a non-negative integer")
    if type(sort) is not str or sort not in _ARCHIVE_LIST_SORTS:
        raise ValueError(f"archive list sort is invalid: {sort}")
    if type(reverse) is not bool:
        raise ValueError("archive list reverse must be a Boolean")
    selected_date = (
        _parse_archive_list_date(archived_on) if archived_on is not None else None
    )
    with app_lock(paths):
        return _list_archives_locked(
            paths,
            provider=provider,
            session_id=session_id,
            selected_date=selected_date,
            version=version,
            sort=sort,
            reverse=reverse,
        )


def _list_archives_locked(
    paths: AppPaths,
    *,
    provider: str | None,
    session_id: str | None,
    selected_date: date | None,
    version: int | None,
    sort: str,
    reverse: bool,
) -> list[dict[str, Any]]:
    entries = []
    object_sizes: dict[str, int] = {}
    for manifest_path in iter_manifests(paths):
        manifest = validate_manifest(manifest_path)
        _validate_restore_manifest_location(paths, manifest_path, manifest)
        manifest_version = _manifest_version(manifest)
        archived_at = parse_timestamp(manifest["archived_at"])
        if (
            (provider is not None and manifest["provider"] != provider)
            or (session_id is not None and manifest["session_id"] != session_id)
            or (selected_date is not None and archived_at.date() != selected_date)
            or (version is not None and manifest_version != version)
        ):
            continue
        raw_bytes = sum(member["size"] for member in manifest["files"])
        objects = _manifest_zstd_objects(manifest)
        for relative in objects - object_sizes.keys():
            object_sizes[relative] = _cas_frame_path(paths, relative).stat().st_size
        compressed_bytes = sum(object_sizes[relative] for relative in objects)
        entries.append(
            {
                "manifest": str(manifest_path),
                "provider": manifest["provider"],
                "session_id": manifest["session_id"],
                "session_key": _manifest_session_key(manifest),
                "version": manifest_version,
                "archive_id": manifest["archive_id"],
                "last_activity": manifest["last_activity"],
                "archived_at": manifest["archived_at"],
                "raw_bytes": raw_bytes,
                "compressed_bytes": compressed_bytes,
                "compression_ratio": (
                    round(raw_bytes / compressed_bytes, 3) if compressed_bytes else None
                ),
            }
        )

    def order(entry: dict[str, Any]) -> tuple[Any, ...]:
        primary = {
            "activity": parse_timestamp(entry["last_activity"]),
            "archive": parse_timestamp(entry["archived_at"]),
            "raw": entry["raw_bytes"],
            "ratio": (
                entry["compression_ratio"]
                if entry["compression_ratio"] is not None
                else -1.0
            ),
            "version": entry["version"],
        }[sort]
        return (
            primary,
            entry["provider"],
            entry["session_id"],
            entry["version"],
            entry["archive_id"],
        )

    entries.sort(key=order, reverse=not reverse)
    return entries


def archive_stats(paths: AppPaths) -> dict[str, Any]:
    """Summarize the archive graph from manifests without recompressing."""

    providers: dict[str, dict[str, Any]] = {}
    objects: dict[str, os.stat_result] = {}
    dictionaries: dict[str, os.stat_result] = {}
    for manifest_path in iter_manifests(paths):
        manifest = validate_manifest(manifest_path)
        provider = manifest["provider"]
        bucket = providers.setdefault(
            provider,
            {
                "manifests": 0,
                "files": 0,
                "raw_bytes": 0,
                "companion_raw_bytes": 0,
                "size_histogram": {name: 0 for name, _ in _SIZE_BUCKETS},
            },
        )
        bucket["manifests"] += 1
        members = manifest["files"]
        for index, member in enumerate(members):
            size = member["size"]
            bucket["files"] += 1
            bucket["raw_bytes"] += size
            if index:
                bucket["companion_raw_bytes"] += size
            for name, limit in _SIZE_BUCKETS:
                if limit is None or size < limit:
                    bucket["size_histogram"][name] += 1
                    break
            dictionary = member.get("dictionary")
            if isinstance(dictionary, str) and dictionary not in dictionaries:
                dictionaries[dictionary] = safe_cas_object_path(
                    paths.archive, dictionary, kind="dictionary"
                ).stat()
        for relative in _manifest_zstd_objects(manifest):
            if relative not in objects:
                objects[relative] = _cas_frame_path(paths, relative).stat()
    compressed = sum(info.st_size for info in objects.values())
    dictionary_bytes = sum(info.st_size for info in dictionaries.values())
    raw = sum(bucket["raw_bytes"] for bucket in providers.values())
    return {
        "providers": providers,
        "manifests": sum(bucket["manifests"] for bucket in providers.values()),
        "objects": len(objects),
        "raw_bytes": raw,
        "compressed_bytes": compressed,
        "unique_cas_bytes": compressed + dictionary_bytes,
        "cas_allocated_bytes": sum(
            info.st_blocks * 512 for info in (*objects.values(), *dictionaries.values())
        ),
        "dictionary_objects": len(dictionaries),
        "dictionary_bytes": dictionary_bytes,
        "ratio": round(raw / compressed, 3) if compressed else None,
    }


TRAINABLE_PROVIDERS = ("claude", "codex", "codex-archived")
DEFAULT_DICTIONARY_MINIMUM_BENEFIT_BYTES = 0


def train_dictionary(
    paths: AppPaths,
    provider: str,
    *,
    sample_limit: int = 256,
    max_dict_bytes: int = 112 * 1024,
    minimum_benefit_bytes: int = DEFAULT_DICTIONARY_MINIMUM_BENEFIT_BYTES,
) -> dict[str, Any]:
    """Publish a provider dictionary only after a beneficial holdout benchmark."""

    with app_lock(paths):
        paths.ensure_private()
        cas_before = _cas_inventory(paths)
        result = _train_dictionary_locked(
            paths,
            provider,
            sample_limit=sample_limit,
            max_dict_bytes=max_dict_bytes,
            minimum_benefit_bytes=minimum_benefit_bytes,
        )
        if not result.get("promoted"):
            return result
        dictionary = result["object"]
        dictionary_size = safe_cas_object_path(
            paths.archive, dictionary, kind="dictionary"
        ).stat(follow_symlinks=False).st_size
        cas_after = _cas_inventory(paths)
        return record_history_after_success(
            paths,
            result,
            operation="dictionary-train",
            provider=provider,
            physical_allocated_bytes_delta=(
                sum(value[1] for value in cas_after.values())
                - sum(value[1] for value in cas_before.values())
            ),
            cas_objects={dictionary: dictionary_size},
        )


def benchmark_dictionary(
    paths: AppPaths,
    provider: str,
    *,
    sample_limit: int = 256,
    max_dict_bytes: int = 112 * 1024,
    minimum_benefit_bytes: int = DEFAULT_DICTIONARY_MINIMUM_BENEFIT_BYTES,
) -> dict[str, Any]:
    """Measure a temporary dictionary without changing the CAS or pointer."""

    with app_lock(paths):
        return _run_dictionary_benchmark_locked(
            paths,
            provider,
            sample_limit=sample_limit,
            max_dict_bytes=max_dict_bytes,
            minimum_benefit_bytes=minimum_benefit_bytes,
            promote=False,
        )


def _dictionary_candidates(paths: AppPaths, provider: str) -> list[Path]:
    candidates = []
    for unit in discover_sessions(paths):
        if unit.provider != provider:
            continue
        info = regular_file_stat(unit.primary)
        if 0 < info["size"] < SIZE_TIER_MID:
            candidates.append(unit.primary)
    return candidates


def _validate_dictionary_options(
    provider: Any,
    sample_limit: Any,
    max_dict_bytes: Any,
    minimum_benefit_bytes: Any,
) -> None:
    if type(provider) is not str or provider not in TRAINABLE_PROVIDERS:
        raise ValueError(f"provider is not trainable: {provider}")
    if type(sample_limit) is not int or sample_limit < 10:
        raise ValueError("dictionary benchmark needs at least 10 samples")
    if type(max_dict_bytes) is not int or max_dict_bytes < 1024:
        raise ValueError("dictionary size must be at least 1024 bytes")
    if type(minimum_benefit_bytes) is not int or minimum_benefit_bytes < 0:
        raise ValueError("minimum dictionary benefit must be a non-negative integer")


def _publish_dictionary_candidate_locked(
    paths: AppPaths, candidate: Path
) -> tuple[str, str]:
    digest = sha256_file(candidate)
    shard = ensure_safe_cas_shard(paths.archive, digest[:2])
    relative = f"objects/sha256/{digest[:2]}/{digest}.dict"
    target = shard / f"{digest}.dict"
    if target.exists() or target.is_symlink():
        target = safe_cas_object_path(paths.archive, relative, kind="dictionary")
        if sha256_file(target) != digest:
            raise RuntimeError(f"dictionary object mismatch: {target}")
        return relative, digest

    fd, raw = tempfile.mkstemp(prefix=f".{digest}.", suffix=".part", dir=shard)
    tmp = Path(raw)
    try:
        os.fchmod(fd, 0o600)
        with candidate.open("rb") as source, os.fdopen(fd, "wb") as target_handle:
            shutil.copyfileobj(source, target_handle)
            target_handle.flush()
            os.fsync(target_handle.fileno())
        if sha256_file(tmp) != digest:
            raise RuntimeError("dictionary changed while preparing publication")
        _publish_frame_payload(paths, tmp, target)
        target = safe_cas_object_path(paths.archive, relative, kind="dictionary")
        if sha256_file(target) != digest:
            raise RuntimeError(f"dictionary object mismatch: {target}")
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        tmp.unlink(missing_ok=True)
    return relative, digest


def _run_dictionary_benchmark_locked(
    paths: AppPaths,
    provider: str,
    *,
    sample_limit: int,
    max_dict_bytes: int,
    minimum_benefit_bytes: int,
    promote: bool,
) -> dict[str, Any]:
    if encryption_config(paths) is not None:
        raise RuntimeError(
            "archive dictionaries are disabled while encryption is enabled"
        )
    _validate_dictionary_options(
        provider, sample_limit, max_dict_bytes, minimum_benefit_bytes
    )
    zstd = _zstd_binary()
    with tempfile.TemporaryDirectory(prefix="sesh-dictionary-") as raw_scratch:
        scratch_path = Path(raw_scratch)
        training, holdout, duplicate_samples = split_dictionary_corpus(
            _dictionary_candidates(paths, provider),
            scratch_path / "corpus",
            sample_limit=sample_limit,
        )
        for sample in (*training, *holdout):
            _validate_jsonl_append(sample, 0)
        candidate = scratch_path / "candidate.dict"
        incumbent = load_provider_dictionary(paths, provider, warn=False)
        report = benchmark_dictionary_candidate(
            zstd,
            training,
            holdout,
            candidate,
            incumbent=incumbent,
            max_dict_bytes=max_dict_bytes,
            minimum_benefit_bytes=minimum_benefit_bytes,
        )
        result = {
            "provider": provider,
            "eligible_primaries": len(training) + len(holdout),
            "duplicate_samples": duplicate_samples,
            "would_promote": report["beneficial"],
            **report,
        }
        if not promote or not report["beneficial"]:
            return {**result, "promoted": False} if promote else result

        relative, digest = _publish_dictionary_candidate_locked(paths, candidate)
        pointer = {
            "schema_version": SCHEMA_VERSION,
            "kind": "compression-dictionary",
            "provider": provider,
            "object": relative,
            "raw_sha256": digest,
            "trained_at": iso_utc(utc_now()),
            "zstd_version": _zstd_version(zstd),
            "samples": report["training_samples"],
            "max_dict_bytes": max_dict_bytes,
        }
        atomic_json(paths.archive / "dictionaries" / f"{provider}.json", pointer)
        return {**pointer, "promoted": True, "benchmark": result}


def _train_dictionary_locked(
    paths: AppPaths,
    provider: str,
    *,
    sample_limit: int,
    max_dict_bytes: int,
    minimum_benefit_bytes: int = DEFAULT_DICTIONARY_MINIMUM_BENEFIT_BYTES,
) -> dict[str, Any]:
    """Train and publish one dictionary while the caller holds the app lock."""

    if encryption_config(paths) is not None:
        raise RuntimeError(
            "archive dictionaries are disabled while encryption is enabled"
        )
    paths.ensure_private()
    return _run_dictionary_benchmark_locked(
        paths,
        provider,
        sample_limit=sample_limit,
        max_dict_bytes=max_dict_bytes,
        minimum_benefit_bytes=minimum_benefit_bytes,
        promote=True,
    )


def _validate_member_relative(value: Any) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError("archive manifest member relative path is invalid")
    relative = Path(value)
    if (
        not relative.parts
        or str(relative) != value
        or relative.is_absolute()
        or "\0" in value
        or "\\" in value
        or ".." in relative.parts
    ):
        raise ValueError(f"archive manifest member escaped its root: {value}")


def _decode_chunks_to(
    paths: AppPaths, zstd: str, chunks: list[dict[str, Any]], out: Any
) -> str:
    """Decode chunk objects into out, returning the whole-member raw hash."""

    whole = hashlib.sha256()
    for chunk in chunks:
        relative = _chunk_object_relative(chunk["sha256"])
        with materialize_archive_frame(paths, relative) as chunk_path:
            process = subprocess.Popen(
                [zstd, "-q", "-d", "--stdout", str(chunk_path)],
                stdout=subprocess.PIPE,
            )
            assert process.stdout is not None
            digest = hashlib.sha256()
            decoded_size = 0
            with process.stdout:
                while block := process.stdout.read(4 * 1024 * 1024):
                    digest.update(block)
                    whole.update(block)
                    decoded_size += len(block)
                    out.write(block)
            if process.wait() != 0:
                raise RuntimeError(f"zstd chunk decode failed: {relative}")
        if digest.hexdigest() != chunk["sha256"]:
            raise RuntimeError(f"chunk SHA-256 mismatch: {relative}")
        if decoded_size != chunk["size"]:
            raise RuntimeError(f"chunk size mismatch: {relative}")
    return whole.hexdigest()


def _verify_validated_manifest(
    paths: AppPaths, manifest_path: Path, manifest: dict[str, Any]
) -> dict[str, Any]:
    """Verify the CAS graph for the exact validated manifest snapshot supplied."""

    zstd = _zstd_binary()
    members = manifest["files"]
    referenced: set[str] = set()
    for member in members:
        reference = member.get("reference")
        if reference is not None:
            referenced.add(reference)
    with tempfile.TemporaryDirectory() as scratch:
        decoded: dict[str, Path] = {}
        for index, member in enumerate(members):
            chunks = member.get("chunks")
            if chunks:
                whole: str
                if member["relative"] in referenced:
                    # A chunked member can still be a reference target for
                    # later members, so its decoded bytes must materialize.
                    capture = Path(scratch) / f"member-{index}"
                    with capture.open("wb") as out:
                        whole = _decode_chunks_to(paths, zstd, chunks, out)
                    decoded[member["relative"]] = capture
                else:
                    with open(os.devnull, "wb") as out:
                        whole = _decode_chunks_to(paths, zstd, chunks, out)
                if whole != member["raw_sha256"]:
                    raise RuntimeError(f"archive raw SHA-256 mismatch: {manifest_path}")
                continue
            reference = member.get("reference")
            reference_path = None
            if reference is not None:
                reference_path = decoded.get(reference)
                if reference_path is None:
                    raise ValueError(
                        f"archive manifest reference is unresolved: {manifest_path}"
                    )
            dictionary_path = None
            dictionary = member.get("dictionary")
            if dictionary is not None:
                if not isinstance(dictionary, str):
                    raise ValueError(
                        f"archive manifest dictionary is invalid: {manifest_path}"
                    )
                dictionary_path = safe_cas_object_path(
                    paths.archive, dictionary, kind="dictionary"
                )
            capture = None
            if member["relative"] in referenced:
                capture = Path(scratch) / f"member-{index}"
            with materialize_archive_frame(
                paths,
                member["object"],
                expected_compressed_sha256=member["compressed_sha256"],
            ) as object_path:
                _verify_zstd(
                    zstd,
                    object_path,
                    member["raw_sha256"],
                    reference=reference_path,
                    dictionary=dictionary_path,
                    capture=capture,
                )
            if capture is not None:
                decoded[member["relative"]] = capture
    return manifest


def verify_manifest(paths: AppPaths, manifest_path: Path) -> dict[str, Any]:
    return _verify_validated_manifest(
        paths, manifest_path, validate_manifest(manifest_path)
    )


def verify_all(paths: AppPaths, *, continue_on_error: bool = False) -> dict[str, Any]:
    manifest_paths = list(iter_manifests(paths))
    if not continue_on_error:
        manifests = 0
        files = 0
        for manifest_path in manifest_paths:
            manifest = verify_manifest(paths, manifest_path)
            manifests += 1
            files += len(manifest["files"])
        return {"manifests": manifests, "files": files}

    verified = 0
    files = 0
    failures = []
    for manifest_path in manifest_paths:
        try:
            manifest = verify_manifest(paths, manifest_path)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            failures.append(
                {
                    "manifest": str(manifest_path),
                    "error_type": exc.__class__.__name__,
                    "error": str(exc),
                }
            )
            continue
        verified += 1
        files += len(manifest["files"])
    return {
        "selected": len(manifest_paths),
        "verified": verified,
        "failed_manifests": len(failures),
        "files": files,
        "failures": failures,
    }


@dataclass(frozen=True)
class _RestoreManifestSnapshot:
    path: Path
    device: int
    inode: int
    size: int
    mtime_ns: int
    mode: int
    sha256: str


def _read_restore_manifest_bytes(
    manifest_path: Path,
) -> tuple[bytes, os.stat_result]:
    try:
        fd = os.open(
            manifest_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise ValueError(
            f"archive manifest is not a regular non-symlink file: {manifest_path}"
        ) from exc
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"archive manifest is not a regular file: {manifest_path}")
        raw = handle.read()
        after = os.fstat(handle.fileno())
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise RuntimeError(
            f"archive manifest changed while it was read: {manifest_path}"
        )
    return raw, after


def _load_restore_manifest(
    manifest_path: Path,
) -> tuple[dict[str, Any], _RestoreManifestSnapshot]:
    raw, info = _read_restore_manifest_bytes(manifest_path)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {manifest_path}")
    manifest = _validate_manifest_payload(value, manifest_path)
    snapshot = _RestoreManifestSnapshot(
        path=manifest_path,
        device=info.st_dev,
        inode=info.st_ino,
        size=info.st_size,
        mtime_ns=info.st_mtime_ns,
        mode=info.st_mode,
        sha256=hashlib.sha256(raw).hexdigest(),
    )
    return manifest, snapshot


def _require_restore_manifest_snapshot(snapshot: _RestoreManifestSnapshot) -> None:
    raw, info = _read_restore_manifest_bytes(snapshot.path)
    if (
        info.st_dev != snapshot.device
        or info.st_ino != snapshot.inode
        or info.st_size != snapshot.size
        or info.st_mtime_ns != snapshot.mtime_ns
        or stat.S_IFMT(info.st_mode) != stat.S_IFMT(snapshot.mode)
        or hashlib.sha256(raw).hexdigest() != snapshot.sha256
    ):
        raise RuntimeError(f"archive manifest changed after selection: {snapshot.path}")


def _validate_restore_manifest_location(
    paths: AppPaths, manifest_path: Path, manifest: dict[str, Any]
) -> None:
    """Bind store-owned manifests to their provider and archive-ID path."""

    manifests_root = (paths.archive / "manifests").resolve(strict=True)
    try:
        relative = manifest_path.relative_to(manifests_root)
    except ValueError:
        # Explicit external manifest paths remain supported.
        return
    provider = _validate_restore_component(manifest["provider"], "provider")
    archive_id = _validate_restore_component(manifest["archive_id"], "identifier")
    if relative.parts != (provider, f"{archive_id}.json"):
        raise ValueError(
            f"archive manifest payload does not match its owned location: {manifest_path}"
        )


def resolve_manifest(paths: AppPaths, reference: str) -> Path:
    direct = Path(reference).expanduser()
    if direct.is_file():
        try:
            relative = direct.resolve(strict=True).relative_to(paths.archive)
        except ValueError:
            return direct
        if relative.parts[:1] == ("manifests",):
            # Import locally because portable validation reuses this module.
            from .portable import portable_manifest_visibility

            for _ in range(32):
                before = portable_manifest_visibility(paths)
                visible = relative.as_posix() not in before[1]
                after = portable_manifest_visibility(paths)
                if before == after:
                    if not visible:
                        raise ValueError(f"manifest is not committed: {direct}")
                    return direct
            raise RuntimeError("archive manifest visibility changed during resolution")
        return direct
    matches = [path for path in iter_manifests(paths) if reference == path.stem]
    if len(matches) != 1:
        raise ValueError(
            f"manifest reference matched {len(matches)} entries: {reference}"
        )
    return matches[0]


def _selected_restore_manifest(
    manifest: dict[str, Any], member_relative: str | None
) -> dict[str, Any]:
    if member_relative is None:
        return manifest
    _validate_member_relative(member_relative)
    files = [
        member for member in manifest["files"] if member["relative"] == member_relative
    ]
    if len(files) != 1:
        raise ValueError(
            f"archive member matched {len(files)} entries: {member_relative}"
        )
    member_path = Path(member_relative)
    directories = [
        directory
        for directory in manifest.get("directories", [])
        if Path(directory["relative"]) in member_path.parents
    ]
    return {**manifest, "files": files, "directories": directories}


def _validate_restore_component(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "\0" in value
        or "/" in value
        or "\\" in value
        or Path(value).name != value
    ):
        raise ValueError(f"archive {label} is not a safe restore component")
    return value


def _parse_restore_date(value: str, label: str) -> date:
    if not isinstance(value, str):
        raise ValueError(f"archive restore {label} must use YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"archive restore {label} must use YYYY-MM-DD") from exc
    if parsed.isoformat() != value:
        raise ValueError(f"archive restore {label} must use YYYY-MM-DD")
    return parsed


def _preflight_restore_namespace(
    root: Path, manifest: dict[str, Any]
) -> tuple[list[tuple[dict[str, Any], Path]], list[tuple[dict[str, Any], Path]]]:
    files = [(member, Path(member["relative"])) for member in manifest["files"]]
    directories = [
        (member, Path(member["relative"])) for member in manifest.get("directories", [])
    ]
    relatives = [relative for _, relative in files + directories]

    seen: dict[tuple[str, ...], Path] = {}
    file_paths = {
        tuple(
            unicodedata.normalize("NFC", part).casefold() for part in relative.parts
        ): relative
        for _, relative in files
    }
    for relative in relatives:
        _validate_member_relative(str(relative))
        if not relative.parts:
            raise ValueError("archive manifest member relative path is invalid")
        key = tuple(
            unicodedata.normalize("NFC", part).casefold() for part in relative.parts
        )
        if key in seen:
            raise ValueError(
                f"archive manifest contains duplicate restore target: {relative}"
            )
        seen[key] = relative
    for key, relative in file_paths.items():
        if any(len(other) > len(key) and other[: len(key)] == key for other in seen):
            raise ValueError(f"archive manifest file is a restore parent: {relative}")

    try:
        root_info = root.lstat()
    except FileNotFoundError:
        root_info = None
    if root_info is not None and (
        stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode)
    ):
        raise FileExistsError(f"restore root is not a real directory: {root}")

    prepared_files = [(member, root / relative) for member, relative in files]
    prepared_directories = [
        (member, root / relative) for member, relative in directories
    ]
    for _, target in prepared_files + prepared_directories:
        try:
            target.resolve(strict=False).relative_to(root)
        except ValueError as exc:
            raise ValueError(
                f"archive manifest member escaped its root: {target}"
            ) from exc
        for parent in reversed(target.parents):
            if parent == root:
                continue
            if root not in parent.parents:
                continue
            try:
                parent_info = parent.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(
                parent_info.st_mode
            ):
                raise FileExistsError(
                    f"restore parent is not a real directory: {parent}"
                )
        try:
            target.lstat()
        except FileNotFoundError:
            continue
        raise FileExistsError(f"restore destination exists: {target}")
    return prepared_files, prepared_directories


def _ensure_archive_canary(paths: AppPaths, zstd: str) -> None:
    """Persist one real codec/manifest/restore proof before source removal."""

    marker_path = paths.state / "archive-canary.json"
    codec_path = Path(zstd).resolve(strict=True)
    regular_file_stat(codec_path)
    expected = {
        "schema_version": SCHEMA_VERSION,
        "kind": "archive-restore-canary",
        "protocol": _CANARY_PROTOCOL,
        "raw_sha256": hashlib.sha256(_CANARY_BYTES).hexdigest(),
        "zstd_version": _zstd_version(zstd),
        "codec_path": str(codec_path),
        "codec_sha256": sha256_file(codec_path),
        "archive_sha256": sha256_file(Path(__file__).resolve(strict=True)),
    }
    try:
        marker_info = marker_path.lstat()
        private_marker = (
            stat.S_ISREG(marker_info.st_mode)
            and marker_info.st_nlink == 1
            and (os.name == "nt" or marker_info.st_mode & 0o777 == 0o600)
            and (
                os.name == "nt"
                or not hasattr(os, "getuid")
                or marker_info.st_uid == os.getuid()
            )
        )
        marker = load_json(marker_path) if private_marker else None
        if (
            marker is not None
            and marker.keys() == expected.keys()
            and all(
                type(marker[key]) is type(value) and marker[key] == value
                for key, value in expected.items()
            )
        ):
            return
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        pass

    try:
        with tempfile.TemporaryDirectory(
            prefix=".archive-canary.", dir=paths.state
        ) as raw:
            scratch = Path(raw)
            source_root = scratch / "source"
            source_root.mkdir(mode=0o700)
            source = source_root / "canary.jsonl"
            source.write_bytes(_CANARY_BYTES)
            source.chmod(_CANARY_MODE)
            os.utime(source, ns=(_CANARY_MTIME_NS, _CANARY_MTIME_NS))
            member = {
                "path": str(source),
                "relative": source.name,
                **regular_file_stat(source),
            }
            object_path, compressed_hash, _, _, _ = _ensure_object(
                paths, source, expected["raw_sha256"], zstd
            )
            manifest_path = scratch / "manifest.json"
            atomic_json(
                manifest_path,
                {
                    "schema_version": 1,
                    "kind": "session-archive",
                    "archive_id": "archive-restore-canary",
                    "provider": "canary",
                    "session_id": "canary",
                    "source_root": str(source_root),
                    "last_activity": "2000-01-01T00:00:00Z",
                    "archived_at": iso_utc(utc_now()),
                    "zstd_version": expected["zstd_version"],
                    "files": [
                        {
                            **member,
                            "raw_sha256": expected["raw_sha256"],
                            "compressed_sha256": compressed_hash,
                            "object": str(object_path.relative_to(paths.archive)),
                        }
                    ],
                    "directories": [],
                },
            )
            destination = scratch / "restored"
            restore_manifest(paths, str(manifest_path), destination)
            restored = destination / source.name
            restored_info = regular_file_stat(restored)
            if (
                restored.read_bytes() != _CANARY_BYTES
                or restored_info["mode"] != member["mode"]
                or restored_info["mtime_ns"] != member["mtime_ns"]
            ):
                raise RuntimeError("canary restore did not preserve bytes and metadata")
            atomic_json(marker_path, expected)
    except Exception as exc:
        raise RuntimeError(
            "archive/restore canary failed; source removal was blocked"
        ) from exc


def _decode_restore_member_to(
    paths: AppPaths,
    zstd: str,
    manifest: dict[str, Any],
    member: dict[str, Any],
    out: Any,
    dependency_root: Path,
    decoded_dependencies: dict[str, Path],
) -> None:
    chunks = member.get("chunks")
    if chunks is not None:
        restored_hash = _decode_chunks_to(paths, zstd, chunks, out)
    else:
        decode_args = [zstd, "-q", "-d", "--stdout"]
        reference = member.get("reference")
        if reference is not None:
            reference_path = decoded_dependencies.get(reference)
            if reference_path is None:
                reference_index, referenced = next(
                    (index, item)
                    for index, item in enumerate(manifest["files"])
                    if item["relative"] == reference
                )
                reference_path = dependency_root / f"member-{reference_index}"
                _decode_restore_member(
                    paths,
                    zstd,
                    manifest,
                    referenced,
                    reference_path,
                    dependency_root,
                    decoded_dependencies,
                )
                decoded_dependencies[reference] = reference_path
            decode_args.append(f"--patch-from={reference_path}")
        dictionary = member.get("dictionary")
        if dictionary is not None:
            decode_args += [
                "-D",
                str(safe_cas_object_path(paths.archive, dictionary, kind="dictionary")),
            ]
        with materialize_archive_frame(
            paths,
            member["object"],
            expected_compressed_sha256=member["compressed_sha256"],
        ) as frame:
            process = subprocess.Popen(
                [*decode_args, str(frame)], stdout=subprocess.PIPE
            )
            assert process.stdout is not None
            digest = hashlib.sha256()
            with process.stdout:
                while block := process.stdout.read(4 * 1024 * 1024):
                    digest.update(block)
                    out.write(block)
            if process.wait() != 0:
                raise RuntimeError(f"zstd restore decode failed: {member['relative']}")
        restored_hash = digest.hexdigest()
    if restored_hash != member["raw_sha256"]:
        raise RuntimeError(f"restored SHA-256 mismatch: {member['relative']}")


def _decode_restore_member(
    paths: AppPaths,
    zstd: str,
    manifest: dict[str, Any],
    member: dict[str, Any],
    target: Path,
    dependency_root: Path,
    decoded_dependencies: dict[str, Path],
) -> None:
    with target.open("wb") as out:
        _decode_restore_member_to(
            paths,
            zstd,
            manifest,
            member,
            out,
            dependency_root,
            decoded_dependencies,
        )


@dataclass
class _RestoreRootAnchor:
    root: Path
    fds: list[int]
    links: list[tuple[int, str, int]]

    @property
    def fd(self) -> int:
        return self.fds[-1]

    def close(self) -> None:
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


def _require_restore_primitives() -> None:
    if os.name != "posix" or not all(
        hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW")
    ):
        raise RuntimeError("safe archive restore requires POSIX dir_fd support")
    if any(
        function not in os.supports_dir_fd
        for function in (os.open, os.link, os.mkdir, os.stat, os.unlink)
    ) or (os.link not in os.supports_follow_symlinks or os.utime not in os.supports_fd):
        raise RuntimeError("safe archive restore requires POSIX dir_fd support")


def _fsync_restore_directory(fd: int) -> None:
    try:
        os.fsync(fd)
    except OSError as exc:
        unsupported = {
            errno.EINVAL,
            getattr(errno, "ENOTSUP", None),
            getattr(errno, "EOPNOTSUPP", None),
        }
        if exc.errno not in unsupported:
            raise


def _open_restore_directory_at(parent_fd: int, name: str, path: Path) -> int:
    try:
        return os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise FileExistsError(
            f"restore parent is not a real directory: {path}"
        ) from exc


def _open_restore_root(root: Path) -> _RestoreRootAnchor:
    _require_restore_primitives()
    base_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    fds = [base_fd]
    links: list[tuple[int, str, int]] = []
    current_fd = base_fd
    current_path = Path("/")
    try:
        for name in root.parts[1:]:
            current_path /= name
            try:
                os.mkdir(name, 0o700, dir_fd=current_fd)
            except FileExistsError:
                pass
            else:
                _fsync_restore_directory(current_fd)
            child_fd = _open_restore_directory_at(current_fd, name, current_path)
            fds.append(child_fd)
            links.append((current_fd, name, child_fd))
            current_fd = child_fd
        return _RestoreRootAnchor(root=root, fds=fds, links=links)
    except Exception:
        for fd in reversed(fds):
            os.close(fd)
        raise


def _validate_restore_links(
    root: _RestoreRootAnchor, links: list[tuple[int, str, int]]
) -> None:
    for parent_fd, name, child_fd in [*root.links, *links]:
        try:
            reachable = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            opened = os.fstat(child_fd)
        except OSError as exc:
            raise RuntimeError(
                f"restore destination directory binding changed: {root.root}"
            ) from exc
        if (
            not stat.S_ISDIR(reachable.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or (reachable.st_dev, reachable.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise RuntimeError(
                f"restore destination directory binding changed: {root.root}"
            )


def _open_restore_parent_at(
    root: _RestoreRootAnchor, relative: Path, *, create: bool
) -> tuple[list[tuple[int, str, int]], int, str]:
    current_fd = root.fd
    current_path = root.root
    links: list[tuple[int, str, int]] = []
    try:
        for name in relative.parts[:-1]:
            current_path /= name
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
                else:
                    _fsync_restore_directory(current_fd)
            child_fd = _open_restore_directory_at(current_fd, name, current_path)
            links.append((current_fd, name, child_fd))
            current_fd = child_fd
        return links, current_fd, relative.name
    except Exception:
        for _, _, fd in reversed(links):
            os.close(fd)
        raise


def _close_restore_links(links: list[tuple[int, str, int]]) -> None:
    for _, _, fd in reversed(links):
        os.close(fd)


def _create_restore_directory(
    root: _RestoreRootAnchor, relative: Path, target: Path
) -> None:
    links, parent_fd, name = _open_restore_parent_at(root, relative, create=True)
    try:
        _validate_restore_links(root, links)
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise FileExistsError(f"restore destination exists: {target}") from exc
        _fsync_restore_directory(parent_fd)
    finally:
        _close_restore_links(links)


def _link_restore_temp(parent_fd: int, temp_name: str, target_name: str) -> None:
    os.link(
        temp_name,
        target_name,
        src_dir_fd=parent_fd,
        dst_dir_fd=parent_fd,
        follow_symlinks=False,
    )


def _fsync_restore_temp(fd: int) -> None:
    os.fsync(fd)


def _restore_file_at(
    paths: AppPaths,
    root: _RestoreRootAnchor,
    manifest: dict[str, Any],
    member: dict[str, Any],
    relative: Path,
    target: Path,
    zstd: str,
    dependency_root: Path,
    decoded_dependencies: dict[str, Path],
) -> None:
    links, parent_fd, target_name = _open_restore_parent_at(root, relative, create=True)
    temp_name = f".{target_name}.{os.urandom(16).hex()}.restore"
    temp_exists = False
    temp_fd = -1
    verified_temp: os.stat_result | None = None
    preserve_paths = False

    def matches_verified_temp(info: os.stat_result) -> bool:
        return (
            verified_temp is not None
            and stat.S_ISREG(info.st_mode)
            and (info.st_dev, info.st_ino)
            == (verified_temp.st_dev, verified_temp.st_ino)
        )

    try:
        _validate_restore_links(root, links)
        temp_fd = os.open(
            temp_name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        temp_exists = True
        verified_temp = os.fstat(temp_fd)
        with os.fdopen(os.dup(temp_fd), "wb") as out:
            _decode_restore_member_to(
                paths,
                zstd,
                manifest,
                member,
                out,
                dependency_root,
                decoded_dependencies,
            )
            out.flush()
        verified_temp = os.fstat(temp_fd)
        if not stat.S_ISREG(verified_temp.st_mode):
            raise RuntimeError(f"restore temporary file is not regular: {target}")
        _validate_restore_links(root, links)
        try:
            current_temp = os.stat(temp_name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            preserve_paths = True
            raise RuntimeError(f"restore temporary identity changed: {target}") from exc
        if not matches_verified_temp(current_temp):
            preserve_paths = True
            raise RuntimeError(f"restore temporary identity changed: {target}")
        try:
            _link_restore_temp(parent_fd, temp_name, target_name)
        except FileExistsError as exc:
            raise FileExistsError(f"restore destination exists: {target}") from exc
        try:
            published = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            preserve_paths = True
            raise RuntimeError(f"restore published identity changed: {target}") from exc
        if not matches_verified_temp(published):
            preserve_paths = True
            raise RuntimeError(f"restore published identity changed: {target}")
        try:
            _validate_restore_links(root, links)
        except Exception:
            preserve_paths = True
            raise
        current_temp = os.stat(temp_name, dir_fd=parent_fd, follow_symlinks=False)
        if not matches_verified_temp(current_temp):
            preserve_paths = True
            raise RuntimeError(f"restore temporary identity changed: {target}")
        before_content = os.fstat(temp_fd)
        os.lseek(temp_fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        restored_size = 0
        while block := os.read(temp_fd, 4 * 1024 * 1024):
            digest.update(block)
            restored_size += len(block)
        after_content = os.fstat(temp_fd)
        content_identity = (
            before_content.st_size,
            before_content.st_mtime_ns,
            before_content.st_ctime_ns,
        )
        if (
            content_identity
            != (
                after_content.st_size,
                after_content.st_mtime_ns,
                after_content.st_ctime_ns,
            )
            or restored_size != member["size"]
            or after_content.st_size != member["size"]
            or digest.hexdigest() != member["raw_sha256"]
        ):
            preserve_paths = True
            raise RuntimeError(f"restore retained content changed: {target}")
        os.fchmod(temp_fd, member["mode"])
        os.utime(
            temp_fd,
            ns=(member["mtime_ns"], member["mtime_ns"]),
        )
        _fsync_restore_temp(temp_fd)
        try:
            current_temp = os.stat(temp_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            temp_exists = False
        else:
            if matches_verified_temp(current_temp):
                os.unlink(temp_name, dir_fd=parent_fd)
                temp_exists = False
            else:
                preserve_paths = True
        _fsync_restore_directory(parent_fd)
    finally:
        if temp_fd >= 0:
            os.close(temp_fd)
        if temp_exists and not preserve_paths:
            try:
                current_temp = os.stat(
                    temp_name, dir_fd=parent_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                pass
            else:
                if matches_verified_temp(current_temp):
                    os.unlink(temp_name, dir_fd=parent_fd)
                else:
                    preserve_paths = True
            if not preserve_paths:
                _fsync_restore_directory(parent_fd)
        _close_restore_links(links)


def _restore_directory_metadata_at(
    root: _RestoreRootAnchor,
    relative: Path,
    item: dict[str, Any],
) -> None:
    links, parent_fd, name = _open_restore_parent_at(root, relative, create=False)
    directory_fd = -1
    try:
        directory_fd = _open_restore_directory_at(parent_fd, name, root.root / relative)
        child_link = (parent_fd, name, directory_fd)
        _validate_restore_links(root, [*links, child_link])
        os.fchmod(directory_fd, item["mode"])
        os.utime(
            directory_fd,
            ns=(item["mtime_ns"], item["mtime_ns"]),
        )
        _fsync_restore_directory(directory_fd)
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)
        _close_restore_links(links)


def _restore_prepared_manifest(
    paths: AppPaths,
    manifest: dict[str, Any],
    root: Path,
    files: list[tuple[dict[str, Any], Path]],
    directories: list[tuple[dict[str, Any], Path]],
    zstd: str,
) -> tuple[int, int]:
    anchor = _open_restore_root(root)
    try:
        with tempfile.TemporaryDirectory(
            prefix=".restore-dependencies.", dir=paths.state
        ) as raw_dependencies:
            dependency_root = Path(raw_dependencies)
            decoded_dependencies: dict[str, Path] = {}
            for _, target in sorted(directories, key=lambda item: len(item[1].parts)):
                _create_restore_directory(anchor, target.relative_to(root), target)
            restored = 0
            for member, target in files:
                _restore_file_at(
                    paths,
                    anchor,
                    manifest,
                    member,
                    target.relative_to(root),
                    target,
                    zstd,
                    dependency_root,
                    decoded_dependencies,
                )
                restored += 1
        ordered_directories = sorted(
            directories,
            key=lambda item: len(item[1].parts),
            reverse=True,
        )
        # Apply directory metadata after every member exists. Creating a child
        # must not replace the recorded modification time of its parent.
        for item, target in ordered_directories:
            _restore_directory_metadata_at(anchor, target.relative_to(root), item)
        return restored, len(ordered_directories)
    finally:
        anchor.close()


def restore_manifest(
    paths: AppPaths,
    reference: str,
    destination: Path | None = None,
    *,
    member: str | None = None,
) -> dict[str, Any]:
    paths.ensure_private()
    manifest_path = resolve_manifest(paths, reference).absolute()
    manifest, snapshot = _load_restore_manifest(manifest_path)
    _validate_restore_manifest_location(paths, manifest_path, manifest)
    selected = _selected_restore_manifest(manifest, member)
    _verify_validated_manifest(paths, manifest_path, manifest)
    if destination is None:
        source_root = manifest.get("source_root")
        if not isinstance(source_root, str) or not Path(source_root).is_absolute():
            raise ValueError("archive manifest source root must be absolute")
        requested_root = Path(source_root)
    else:
        requested_root = destination.expanduser()
    if requested_root.is_symlink():
        raise FileExistsError(f"restore root is not a real directory: {requested_root}")
    root = requested_root.resolve()
    files, directories = _preflight_restore_namespace(root, selected)
    _require_restore_manifest_snapshot(snapshot)
    restored, restored_directories = _restore_prepared_manifest(
        paths, manifest, root, files, directories, _zstd_binary()
    )
    return {
        "archive_id": manifest["archive_id"],
        "files": restored,
        "directories": restored_directories,
        "destination": str(root),
        **({"member": member} if member is not None else {}),
    }


def restore_manifest_set(
    paths: AppPaths,
    provider: str,
    date_from: str,
    date_to: str,
    destination: Path,
) -> dict[str, Any]:
    """Restore one provider's manifests in an inclusive UTC archive-date range."""

    paths.ensure_private()
    provider = _validate_restore_component(provider, "provider")
    first_date = _parse_restore_date(date_from, "start date")
    last_date = _parse_restore_date(date_to, "end date")
    if first_date > last_date:
        raise ValueError("archive restore start date is after end date")

    provider_root = paths.archive / "manifests" / provider
    selected: list[tuple[Path, dict[str, Any], _RestoreManifestSnapshot]] = []
    for manifest_path in iter_manifests(paths):
        if manifest_path.parent != provider_root:
            continue
        manifest_path = manifest_path.absolute()
        manifest, snapshot = _load_restore_manifest(manifest_path)
        _validate_restore_manifest_location(paths, manifest_path, manifest)
        if manifest["provider"] != provider:
            raise ValueError(
                f"archive manifest provider path mismatch: {manifest_path}"
            )
        archive_id = _validate_restore_component(manifest["archive_id"], "identifier")
        if manifest_path.name != f"{archive_id}.json":
            raise ValueError(f"archive manifest path mismatch: {manifest_path}")
        archived_date = parse_timestamp(manifest["archived_at"]).astimezone(UTC).date()
        if first_date <= archived_date <= last_date:
            selected.append((manifest_path, manifest, snapshot))
    if not selected:
        raise ValueError(
            f"archive restore matched no {provider} manifests from {date_from} to {date_to}"
        )
    selected.sort(
        key=lambda item: (
            parse_timestamp(item[1]["archived_at"]),
            item[1]["archive_id"],
        )
    )
    for manifest_path, manifest, _ in selected:
        _verify_validated_manifest(paths, manifest_path, manifest)

    requested_root = destination.expanduser()
    if requested_root.is_symlink():
        raise FileExistsError(f"restore root is not a real directory: {requested_root}")
    root = requested_root.resolve()
    planned: list[
        tuple[
            dict[str, Any],
            list[tuple[dict[str, Any], Path]],
            list[tuple[dict[str, Any], Path]],
        ]
    ] = []
    namespace: set[tuple[str, ...]] = set()
    for _, manifest, _ in selected:
        archive_id = manifest["archive_id"]
        key = tuple(
            unicodedata.normalize("NFC", value).casefold()
            for value in (provider, archive_id)
        )
        if key in namespace:
            raise ValueError("archive restore batch namespace is duplicated")
        namespace.add(key)
        scoped_root = root / provider / archive_id
        for component in (root, root / provider, scoped_root):
            try:
                info = component.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise FileExistsError(
                    f"restore root is not a real directory: {component}"
                )
        files, directories = _preflight_restore_namespace(scoped_root, manifest)
        planned.append((manifest, files, directories))

    zstd = _zstd_binary()
    for _, _, snapshot in selected:
        _require_restore_manifest_snapshot(snapshot)
    restored_files = 0
    restored_directories = 0
    for manifest, files, directories in planned:
        files_count, directories_count = _restore_prepared_manifest(
            paths,
            manifest,
            (root / provider / manifest["archive_id"]),
            files,
            directories,
            zstd,
        )
        restored_files += files_count
        restored_directories += directories_count
    return {
        "provider": provider,
        "date_from": date_from,
        "date_to": date_to,
        "manifests": len(planned),
        "files": restored_files,
        "directories": restored_directories,
        "destination": str(root),
    }


def _require_recovery_primitives() -> None:
    if os.name != "posix" or not all(
        hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW")
    ):
        raise RuntimeError("safe quarantine recovery requires POSIX dir_fd support")
    if any(
        function not in os.supports_dir_fd
        for function in (os.open, os.link, os.mkdir, os.unlink, os.rmdir, os.stat)
    ):
        raise RuntimeError("safe quarantine recovery requires POSIX dir_fd support")
    if os.link not in os.supports_follow_symlinks:
        raise RuntimeError("safe quarantine recovery requires no-follow hard links")
    if os.utime not in os.supports_fd:
        raise RuntimeError("safe quarantine recovery requires fd utime")


def _open_recovery_dir(
    path: Path | str, label: str, parent_fd: int | None = None
) -> int:
    try:
        return os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd
        )
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ValueError(
            f"recovery {label} is not a real directory: {path}: {exc}"
        ) from exc


def _open_recovery_parent(
    root_fd: int,
    relative: Path,
    *,
    create: bool = False,
    created: set[Path] | None = None,
) -> tuple[int, str]:
    fd = os.dup(root_fd)
    try:
        for index, part in enumerate(relative.parts[:-1], start=1):
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                else:
                    os.fsync(fd)
                    if created is not None:
                        created.add(Path(*relative.parts[:index]))
            next_fd = _open_recovery_dir(part, f"parent {relative}", fd)
            os.close(fd)
            fd = next_fd
        return fd, relative.name
    except Exception:
        os.close(fd)
        raise


def _load_recovery_json_at(item_fd: int, name: str, label: str) -> dict[str, Any]:
    fd = -1
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=item_fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"recovery {label} is not a regular file: {name}")
        with os.fdopen(fd, encoding="utf-8") as handle:
            fd = -1
            value = json.load(handle)
    except OSError as exc:
        raise ValueError(
            f"recovery {label} is not a regular file: {name}: {exc}"
        ) from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(value, dict):
        raise ValueError(f"recovery {label} must be a JSON object")
    return value


def _stat_recovery_at(root_fd: int, relative: Path) -> os.stat_result | None:
    try:
        parent_fd, name = _open_recovery_parent(root_fd, relative)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(
            f"recovery parent is not a real directory: {relative}: {exc}"
        ) from exc
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    finally:
        os.close(parent_fd)


def _hash_recovery_file_at(root_fd: int, relative: Path) -> tuple[os.stat_result, str]:
    fd = -1
    parent_fd, name = _open_recovery_parent(root_fd, relative)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"recovery file is not regular: {relative}")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        return info, digest
    except OSError as exc:
        raise ValueError(f"recovery file is not regular: {relative}: {exc}") from exc
    finally:
        os.close(parent_fd)
        if fd >= 0:
            os.close(fd)


def _matching_recovery_file(
    root_fd: int, relative: Path, member: dict[str, Any]
) -> os.stat_result | None:
    try:
        info, digest = _hash_recovery_file_at(root_fd, relative)
    except (FileNotFoundError, ValueError):
        return None
    if (
        digest == member["raw_sha256"]
        and info.st_dev == member["device"]
        and info.st_ino == member["inode"]
        and info.st_size == member["size"]
        and info.st_mtime_ns == member["mtime_ns"]
        and info.st_mode & 0o777 == member["mode"]
    ):
        return info
    return None


def _scan_recovery_files_at(root_fd: int, base: Path = Path()) -> set[Path]:
    found: set[Path] = set()
    for name in sorted(os.listdir(root_fd)):
        info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        relative = base / name
        if stat.S_ISDIR(info.st_mode):
            child = _open_recovery_dir(name, "files", root_fd)
            try:
                found.update(_scan_recovery_files_at(child, relative))
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            found.add(relative)
        else:
            raise ValueError(f"recovery quarantine member is not regular: {relative}")
    return found


def _published_recovery_manifest_matches(
    manifest_path: Path, staged: dict[str, Any]
) -> bool:
    if not manifest_path.exists() and not manifest_path.is_symlink():
        return False
    manifest_fd = _open_recovery_dir(manifest_path.parent, "manifest parent")
    try:
        matches = (
            _load_recovery_json_at(
                manifest_fd, manifest_path.name, "published manifest"
            )
            == staged
        )
    finally:
        os.close(manifest_fd)
    if matches:
        fsync_dir(manifest_path.parent)
    return matches


def _recovery_relatives(
    staged: dict[str, Any], journal: dict[str, Any]
) -> tuple[list[Path], list[Path]]:
    files = [Path(member["relative"]) for member in staged["files"]]
    directories = [Path(member["relative"]) for member in staged.get("directories", [])]
    if journal.get("files") != [
        member["relative"] for member in staged["files"]
    ] or journal.get("directories", []) != [
        member["relative"] for member in staged.get("directories", [])
    ]:
        raise ValueError("recovery journal entries do not match its staged manifest")
    all_relatives = files + directories
    parents = {
        Path(*relative.parts[:index])
        for relative in all_relatives
        for index in range(1, len(relative.parts))
    }
    if len(set(all_relatives)) != len(all_relatives) or set(files) & parents:
        raise ValueError("recovery contains a duplicate or file-parent collision")
    return files, directories


def _validate_recovery_schema(payload: dict[str, Any], label: str) -> None:
    if (
        type(payload.get("schema_version")) is not int
        or payload["schema_version"] not in SUPPORTED_SCHEMA_VERSIONS
    ):
        raise ValueError(f"unsupported recovery {label} schema")


def _recovery_source_root_identity(journal: dict[str, Any]) -> dict[str, Any] | None:
    identity = journal.get("source_root_identity")
    if identity is None:
        return None
    if (
        not isinstance(identity, dict)
        or not isinstance(identity.get("resolved_path"), str)
        or not Path(identity["resolved_path"]).is_absolute()
        or type(identity.get("device")) is not int
        or type(identity.get("inode")) is not int
    ):
        raise ValueError("recovery source root identity is invalid")
    return identity


def _validate_recovery_item(
    paths: AppPaths, item: dict[str, Any], claimed: set[Path]
) -> None:
    if item["cleanup_only"]:
        name = item.get("metadata_name")
        if name is None:
            return
        label = "staged manifest" if name == "_manifest.json" else "journal"
        payload = _load_recovery_json_at(item["item_fd"], name, label)
        _validate_recovery_schema(payload, label)
        if name == "_manifest.json":
            if payload.get("kind") != "session-archive":
                raise ValueError("recovery staged manifest has an invalid kind")
            validate_planned_session(payload)
            if item["item_name"] != _manifest_session_key(payload):
                raise ValueError(
                    "recovery archive id does not match its quarantine key"
                )
        elif (
            not isinstance(payload.get("source_root"), str)
            or not Path(payload["source_root"]).is_absolute()
            or not isinstance(payload.get("manifest"), str)
            or not Path(payload["manifest"]).is_absolute()
            or not isinstance(payload.get("files"), list)
            or not isinstance(payload.get("directories", []), list)
        ):
            raise ValueError("recovery journal metadata is invalid")
        _recovery_source_root_identity(payload)
        return
    staged = _load_recovery_json_at(
        item["item_fd"], "_manifest.json", "staged manifest"
    )
    journal = _load_recovery_json_at(item["item_fd"], "_restore.json", "journal")
    for payload, label in ((staged, "staged manifest"), (journal, "journal")):
        _validate_recovery_schema(payload, label)
    if staged.get("kind") != "session-archive":
        raise ValueError("recovery staged manifest has an invalid kind")
    validate_planned_session(staged)
    key = _manifest_session_key(staged)
    provider = staged["provider"]
    manifest_path = (
        paths.archive / "manifests" / provider / f"{staged['archive_id']}.json"
    )
    if item["item_name"] != key:
        raise ValueError("recovery archive id does not match its quarantine key")
    if journal.get("source_root") != staged["source_root"] or journal.get(
        "manifest"
    ) != str(manifest_path):
        raise ValueError("recovery journal is not bound to its staged manifest")
    files, directories = _recovery_relatives(staged, journal)
    source_root = Path(staged["source_root"])
    source_root_identity = _recovery_source_root_identity(journal)
    if source_root_identity is None and source_root.is_symlink():
        raise ValueError("legacy recovery source root must not be a symlink")
    resolved_source_root = source_root.resolve(strict=True)
    item["source_fd"] = _open_recovery_dir(resolved_source_root, "source root")
    if source_root_identity is not None:
        source_root_info = os.fstat(item["source_fd"])
        if (
            source_root_identity["resolved_path"] != str(resolved_source_root)
            or source_root_identity["device"] != source_root_info.st_dev
            or source_root_identity["inode"] != source_root_info.st_ino
        ):
            raise ValueError("recovery source root identity changed")
    item["published"] = _published_recovery_manifest_matches(manifest_path, staged)
    item["manifest_path"] = manifest_path
    item["staged"] = staged
    item["files"] = []
    item["directories"] = []
    files_fd = item.get("files_fd")
    quarantined = _scan_recovery_files_at(files_fd) if files_fd is not None else set()
    expected_quarantined: set[Path] = set()
    for member, relative in zip(staged["files"], files, strict=True):
        target = resolved_source_root / relative
        if target in claimed:
            raise ValueError(f"recovery contains a duplicate destination: {target}")
        claimed.add(target)
        raw_hash = member.get("raw_sha256")
        if (
            not isinstance(raw_hash, str)
            or len(raw_hash) != 64
            or any(char not in "0123456789abcdef" for char in raw_hash)
        ):
            raise ValueError("recovery staged file hash is invalid")
        q_present = relative in quarantined
        q_info = None
        if q_present:
            q_info = _matching_recovery_file(files_fd, relative, member)
            if q_info is None:
                raise ValueError(
                    f"recovery quarantined file identity mismatch: {relative}"
                )
            expected_quarantined.add(relative)
        info = _stat_recovery_at(item["source_fd"], relative)
        if info is not None and stat.S_ISLNK(info.st_mode):
            raise ValueError(f"recovery destination is a symlink: {target}")
        same_link = (
            q_info is not None
            and info is not None
            and (q_info.st_dev, q_info.st_ino) == (info.st_dev, info.st_ino)
        )
        target_matches = same_link or (
            not q_present
            and _matching_recovery_file(item["source_fd"], relative, member) is not None
        )
        if item["published"]:
            state = (
                "published"
                if info is None or (not q_present and target_matches)
                else "conflict"
            )
        elif info is None:
            if not q_present:
                raise ValueError(
                    f"recovery file is missing from source and quarantine: {target}"
                )
            state = "quarantined"
        elif same_link:
            state = "linked"
        elif q_present or not stat.S_ISREG(info.st_mode):
            state = "conflict"
        else:
            state = "restored" if target_matches else "conflict"
        item["files"].append({"relative": relative, "state": state})
    if unexpected := quarantined - expected_quarantined:
        raise ValueError(
            f"recovery quarantine contains an unexpected file: {min(unexpected)}"
        )
    for member, relative in zip(
        staged.get("directories", []), directories, strict=True
    ):
        target = resolved_source_root / relative
        if target in claimed:
            raise ValueError(f"recovery contains a duplicate destination: {target}")
        claimed.add(target)
        info = _stat_recovery_at(item["source_fd"], relative)
        if info is not None and stat.S_ISLNK(info.st_mode):
            raise ValueError(f"recovery destination is a symlink: {target}")
        if info is not None and not stat.S_ISDIR(info.st_mode):
            item["directory_conflicts"] = item.get("directory_conflicts", 0) + 1
        item["directories"].append(
            {"relative": relative, "member": member, "absent": info is None}
        )


def _recovery_temp_metadata_name(name: str) -> bool:
    for canonical in ("_manifest.json", "_restore.json"):
        prefix = f".{canonical}."
        if name.startswith(prefix) and name.endswith(".tmp"):
            token = name[len(prefix) : -4]
            return len(token) == 8 and all(
                char in "abcdefghijklmnopqrstuvwxyz0123456789_" for char in token
            )
    return False


def _inventory_recovery_items(root: Path) -> tuple[int, list[dict[str, Any]]]:
    root_fd = _open_recovery_dir(root, "quarantine root")
    items: list[dict[str, Any]] = []
    try:
        for run_name in sorted(os.listdir(root_fd)):
            run_fd = _open_recovery_dir(run_name, "run", root_fd)
            try:
                for item_name in sorted(os.listdir(run_fd)):
                    item_fd: int | None = _open_recovery_dir(item_name, "item", run_fd)
                    files_fd: int | None = None
                    try:
                        entries = set(os.listdir(item_fd))
                        allowed = {"_restore.json", "_manifest.json", "files"}
                        temp_names = {
                            name
                            for name in entries
                            if _recovery_temp_metadata_name(name)
                        }
                        if (temp_names and "files" in entries) or any(
                            not stat.S_ISREG(
                                os.stat(
                                    name,
                                    dir_fd=item_fd,
                                    follow_symlinks=False,
                                ).st_mode
                            )
                            for name in temp_names
                        ):
                            raise ValueError("recovery item has an unknown layout")
                        entries -= temp_names
                        metadata = entries & {"_restore.json", "_manifest.json"}
                        cleanup_only = not entries or (
                            len(entries) == 1 and len(metadata) == 1
                        )
                        if entries - allowed or (
                            not cleanup_only
                            and not {"_restore.json", "_manifest.json"} <= entries
                        ):
                            raise ValueError("recovery item has an unknown layout")
                        files_fd = (
                            _open_recovery_dir("files", "files", item_fd)
                            if "files" in entries
                            else None
                        )
                        items.append(
                            {
                                "run_name": run_name,
                                "run_fd": os.dup(run_fd),
                                "item_name": item_name,
                                "item_fd": item_fd,
                                "files_fd": files_fd,
                                "cleanup_only": cleanup_only,
                                "metadata_name": next(iter(metadata), None),
                                "temp_names": temp_names,
                            }
                        )
                        item_fd = files_fd = None
                    finally:
                        if files_fd is not None:
                            os.close(files_fd)
                        if item_fd is not None:
                            os.close(item_fd)
            finally:
                os.close(run_fd)
        return root_fd, items
    except Exception:
        for item in items:
            _close_recovery_item(item)
        os.close(root_fd)
        raise


def _cleanup_recovery_item(root_fd: int, item: dict[str, Any]) -> None:
    if item.get("files_fd") is not None:
        os.close(item["files_fd"])
        item["files_fd"] = None
        shutil.rmtree("files", dir_fd=item["item_fd"])
    for name in ("_manifest.json", "_restore.json", *sorted(item["temp_names"])):
        try:
            os.unlink(name, dir_fd=item["item_fd"])
        except FileNotFoundError:
            pass
    os.fsync(item["item_fd"])
    os.rmdir(item["item_name"], dir_fd=item["run_fd"])
    os.fsync(item["run_fd"])


def _remove_empty_recovery_run(root_fd: int, run_name: str) -> None:
    try:
        os.rmdir(run_name, dir_fd=root_fd)
    except OSError as exc:
        if exc.errno not in {errno.ENOTEMPTY, errno.EEXIST}:
            raise
    os.fsync(root_fd)


def _close_recovery_item(item: dict[str, Any]) -> None:
    for key in ("files_fd", "item_fd", "run_fd", "source_fd"):
        if item.get(key) is not None:
            os.close(item[key])
            item[key] = None


def _recover_quarantine_locked(paths: AppPaths) -> dict[str, int]:
    _require_recovery_primitives()
    root = paths.state / "quarantine"
    if not root.exists() and not root.is_symlink():
        return {"restored": 0, "conflicts": 0}
    root_fd, items = _inventory_recovery_items(root)
    restored = conflicts = 0
    try:
        claimed: set[Path] = set()
        for item in items:
            _validate_recovery_item(paths, item, claimed)
        for item in items:
            if item["cleanup_only"]:
                _cleanup_recovery_item(root_fd, item)
                continue
            record_conflicts = item.get("directory_conflicts", 0) + sum(
                file["state"] == "conflict" for file in item["files"]
            )
            if record_conflicts:
                conflicts += record_conflicts
                continue
            if item["published"]:
                _publish_latest_index(
                    paths,
                    item["manifest_path"],
                    item["staged"],
                )
                _cleanup_recovery_item(root_fd, item)
                continue
            raced = False
            created_directories: set[Path] = set()
            for file in item["files"]:
                if file["state"] not in {"quarantined", "linked"}:
                    continue
                parent_fd, name = _open_recovery_parent(
                    item["source_fd"],
                    file["relative"],
                    create=True,
                    created=created_directories,
                )
                try:
                    q_parent_fd, q_name = _open_recovery_parent(
                        item["files_fd"], file["relative"]
                    )
                    try:
                        if file["state"] == "quarantined":
                            try:
                                os.link(
                                    q_name,
                                    name,
                                    src_dir_fd=q_parent_fd,
                                    dst_dir_fd=parent_fd,
                                    follow_symlinks=False,
                                )
                            except FileExistsError:
                                conflicts += 1
                                raced = True
                                continue
                            restored += 1
                        else:
                            q_info = os.stat(
                                q_name, dir_fd=q_parent_fd, follow_symlinks=False
                            )
                            target_info = os.stat(
                                name, dir_fd=parent_fd, follow_symlinks=False
                            )
                            if (q_info.st_dev, q_info.st_ino) != (
                                target_info.st_dev,
                                target_info.st_ino,
                            ):
                                conflicts += 1
                                raced = True
                                continue
                        os.fsync(parent_fd)
                        os.unlink(q_name, dir_fd=q_parent_fd)
                        os.fsync(q_parent_fd)
                    finally:
                        os.close(q_parent_fd)
                finally:
                    os.close(parent_fd)
            if raced:
                continue
            for entry in sorted(
                item["directories"], key=lambda value: len(value["relative"].parts)
            ):
                if not entry["absent"]:
                    continue
                parent_fd, name = _open_recovery_parent(
                    item["source_fd"],
                    entry["relative"],
                    create=True,
                    created=created_directories,
                )
                try:
                    if entry["relative"] not in created_directories:
                        try:
                            os.mkdir(name, 0o700, dir_fd=parent_fd)
                        except FileExistsError:
                            entry["raced"] = True
                            conflicts += 1
                            raced = True
                        else:
                            os.fsync(parent_fd)
                            created_directories.add(entry["relative"])
                finally:
                    os.close(parent_fd)
            for entry in sorted(
                item["directories"],
                key=lambda value: len(value["relative"].parts),
                reverse=True,
            ):
                if not entry["absent"] or entry.get("raced"):
                    continue
                parent_fd, name = _open_recovery_parent(
                    item["source_fd"], entry["relative"]
                )
                try:
                    dir_fd = _open_recovery_dir(name, "source directory", parent_fd)
                    try:
                        member = entry["member"]
                        os.fchmod(dir_fd, member["mode"])
                        os.utime(dir_fd, ns=(member["mtime_ns"], member["mtime_ns"]))
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                finally:
                    os.close(parent_fd)
            if raced:
                continue
            _cleanup_recovery_item(root_fd, item)
            _remove_empty_recovery_run(root_fd, item["run_name"])
        for run_name in sorted(os.listdir(root_fd)):
            _remove_empty_recovery_run(root_fd, run_name)
        return {"restored": restored, "conflicts": conflicts}
    finally:
        for item in items:
            _close_recovery_item(item)
        os.close(root_fd)


def recover_quarantine(paths: AppPaths) -> dict[str, int]:
    """Recover tool-owned quarantine state; it makes no stronger same-user claim."""

    with app_lock(paths):
        return _recover_quarantine_locked(paths)
