from __future__ import annotations

import functools
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterator

from .common import (
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    AppPaths,
    any_open,
    app_lock,
    atomic_json,
    ensure_safe_cas_shard,
    fsync_dir,
    identity_matches,
    iso_utc,
    load_json,
    open_file_paths,
    open_file_paths_for,
    parse_timestamp,
    prune_expired_plans,
    regular_file_stat,
    safe_cas_object_path,
    sha256_file,
    utc_now,
)


@dataclass(frozen=True)
class SessionUnit:
    provider: str
    session_id: str
    source_root: Path
    files: tuple[Path, ...]
    retention_days: int


class SourceChangedError(RuntimeError):
    """An identity-pinned archive source changed before its commit."""


def _assert_quarantine_device(paths: AppPaths, session: dict[str, Any]) -> None:
    state_device = paths.state.stat().st_dev
    source_device = Path(session["source_root"]).stat().st_dev
    if state_device != source_device:
        raise RuntimeError(
            f"quarantine device differs from source root: {session['source_root']}"
        )


def validate_planned_session(session: dict[str, Any]) -> None:
    required_strings = ("provider", "session_id", "source_root", "last_activity")
    if any(not isinstance(session.get(key), str) or not session[key] for key in required_strings):
        raise ValueError("archive session has invalid required metadata")
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
        if relative.is_absolute() or ".." in relative.parts or path != root / relative:
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


def _bundle_files(primary: Path) -> tuple[Path, ...]:
    files = [primary]
    companion = primary.with_suffix("")
    if companion.is_dir() and not companion.is_symlink():
        files.extend(
            path
            for path in sorted(companion.rglob("*"))
            if path.is_file() and not path.is_symlink()
        )
    return tuple(files)


def discover_sessions(paths: AppPaths) -> Iterator[SessionUnit]:
    # Import lazily because observer maintenance reuses the archive
    # transaction primitives from this module.
    from .observer import ClaudeMemPaths

    observer = ClaudeMemPaths.discover(paths).observer_project
    claude_projects = paths.home / ".claude/projects"
    if claude_projects.is_dir():
        for project in sorted(claude_projects.iterdir()):
            if not project.is_dir() or project == observer or project.is_symlink():
                continue
            for primary in sorted(project.glob("*.jsonl")):
                if primary.is_file() and not primary.is_symlink():
                    yield SessionUnit(
                        "claude",
                        f"{project.name}:{primary.stem}",
                        project,
                        _bundle_files(primary),
                        30,
                    )

    for label, root in (
        ("codex", paths.home / ".codex/sessions"),
        ("codex-archived", paths.home / ".codex/archived_sessions"),
    ):
        if not root.is_dir():
            continue
        for source in sorted(root.rglob("*.jsonl")):
            if source.is_file() and not source.is_symlink():
                yield SessionUnit(label, source.stem, root, (source,), 30)


def _unit_activity(unit: SessionUnit) -> datetime:
    timestamps = [_max_jsonl_timestamp(path) for path in unit.files if path.suffix == ".jsonl"]
    if not timestamps:
        raise ValueError("session bundle has no JSONL member")
    return max(timestamps)


def create_archive_plan(paths: AppPaths, now: datetime | None = None) -> tuple[Path, dict[str, Any]]:
    paths.ensure_private()
    current = (now or utc_now()).astimezone(UTC)
    opened = open_file_paths()
    selected: list[dict[str, Any]] = []
    skipped: dict[str, int] = {}
    logical_bytes = 0

    for unit in discover_sessions(paths):
        try:
            if any_open(unit.files, opened):
                raise RuntimeError("open")
            activity = _unit_activity(unit)
            if activity > current - timedelta(days=unit.retention_days):
                raise RuntimeError("recent")
            members = []
            for source in unit.files:
                stat = regular_file_stat(source)
                logical_bytes += stat["size"]
                members.append({"path": str(source), "relative": str(source.relative_to(unit.source_root)), **stat})
            selected.append(
                {
                    "provider": unit.provider,
                    "session_id": unit.session_id,
                    "source_root": str(unit.source_root),
                    "retention_days": unit.retention_days,
                    "last_activity": iso_utc(activity),
                    "files": members,
                }
            )
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            reason = str(exc) or exc.__class__.__name__
            skipped[reason] = skipped.get(reason, 0) + 1

    run_id = current.strftime("%Y%m%dT%H%M%SZ")
    plan = {
        "schema_version": SCHEMA_VERSION,
        "kind": "archive-plan",
        "run_id": run_id,
        "created_at": iso_utc(current),
        "expires_at": iso_utc(current + timedelta(hours=2)),
        "logical_bytes": logical_bytes,
        "sessions": selected,
        "skipped": skipped,
    }
    plan_path = paths.state / "plans" / f"archive-{run_id}.json"
    atomic_json(plan_path, plan)
    prune_expired_plans(paths)
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
        [binary, "-q", "-d", "--stdout", *extra, str(object_path)], stdout=subprocess.PIPE
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


SIZE_TIER_MID = 1024**2
SIZE_TIER_LARGE = 8 * 1024**2
CHUNK_TARGET_BYTES = 1024**2
CHUNK_HASH_ALPHABET = frozenset("0123456789abcdef")


def _chunk_object_relative(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in CHUNK_HASH_ALPHABET for character in value)
    ):
        raise ValueError(f"archive chunk hash is invalid: {value}")
    return f"objects/sha256/{value[:2]}/{value}.zst"


def _chunk_records(source: Path, target: int = CHUNK_TARGET_BYTES) -> Iterator[bytes]:
    """Yield newline-aligned record groups of at least target bytes.

    A single record larger than the target becomes its own legal chunk, so a
    line is never split.
    """

    with source.open("rb") as handle:
        buffer = bytearray()
        for line in handle:
            buffer.extend(line)
            if len(buffer) >= target:
                yield bytes(buffer)
                buffer.clear()
        if buffer:
            yield bytes(buffer)


def _ensure_chunk_object(paths: AppPaths, data: bytes, zstd: str) -> tuple[str, int]:
    """Compress one chunk into the CAS, returning (object relative, size)."""

    raw_hash = hashlib.sha256(data).hexdigest()
    shard = ensure_safe_cas_shard(paths.archive, raw_hash[:2])
    relative = f"objects/sha256/{raw_hash[:2]}/{raw_hash}.zst"
    target = shard / f"{raw_hash}.zst"
    if target.exists() or target.is_symlink():
        target = safe_cas_object_path(paths.archive, relative)
        try:
            _verify_zstd(zstd, target, raw_hash)
        except (RuntimeError, subprocess.SubprocessError):
            stamp = utc_now().strftime("%Y%m%dT%H%M%S.%fZ")
            os.replace(target, target.with_name(f"{target.name}.corrupt-{stamp}"))
        else:
            return relative, target.stat().st_size

    fd, raw_tmp = tempfile.mkstemp(prefix=f".{raw_hash}.", suffix=".part", dir=target.parent)
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
        os.replace(tmp, target)
        target.chmod(0o600)
        fsync_dir(target.parent)
        return relative, target.stat().st_size
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

    pointer = paths.archive / "dictionaries" / f"{provider}.json"
    try:
        if pointer.is_symlink() or not pointer.is_file():
            return None
        payload = load_json(pointer)
        if (
            payload.get("kind") != "compression-dictionary"
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
        object_path = safe_cas_object_path(paths.archive, relative)
        if sha256_file(object_path) != raw_sha256:
            raise ValueError("dictionary object digest mismatch")
        return object_path
    except (OSError, ValueError, RuntimeError) as exc:
        if warn:
            print(f"sesh-compresh: ignoring dictionary for {provider}: {exc}", file=sys.stderr)
        return None


def _known_dictionaries(paths: AppPaths) -> list[Path]:
    root = paths.archive / "dictionaries"
    if not root.is_dir() or root.is_symlink():
        return []
    known = []
    for pointer in sorted(root.glob("*.json")):
        dictionary = load_provider_dictionary(paths, pointer.stem, warn=False)
        if dictionary is not None:
            known.append(dictionary)
    return known


def _ensure_object(
    paths: AppPaths,
    source: Path,
    raw_hash: str,
    zstd: str,
    *,
    reference: Path | None = None,
    dictionary: Path | None = None,
) -> tuple[Path, str, bool, str | None]:
    """Compress source into the CAS.

    Returns the object path, its compressed hash, whether the stored frame
    decodes through reference content, and the dictionary object it decodes
    through (if any).  An existing object is reused only after proving which
    recipe reproduces the raw bytes, and it keeps its original recipe; an
    object no known recipe can decode is moved aside for forensics and
    rebuilt, because anything referencing it was already failing verification.
    """

    shard = ensure_safe_cas_shard(paths.archive, raw_hash[:2])
    relative = f"objects/sha256/{raw_hash[:2]}/{raw_hash}.zst"
    target = shard / f"{raw_hash}.zst"
    if target.exists() or target.is_symlink():
        target = safe_cas_object_path(paths.archive, relative)
        candidates: list[tuple[Path | None, Path | None]] = [(None, None)]
        if reference is not None:
            candidates.append((reference, None))
        if dictionary is not None:
            candidates.append((None, dictionary))
        for known in _known_dictionaries(paths):
            if known != dictionary:
                candidates.append((None, known))
        for candidate_reference, candidate_dictionary in candidates:
            try:
                _verify_zstd(
                    zstd,
                    target,
                    raw_hash,
                    reference=candidate_reference,
                    dictionary=candidate_dictionary,
                )
            except (RuntimeError, subprocess.SubprocessError):
                continue
            used_dictionary = None
            if candidate_dictionary is not None:
                used_dictionary = str(candidate_dictionary.relative_to(paths.archive))
            return target, sha256_file(target), candidate_reference is not None, used_dictionary
        stamp = utc_now().strftime("%Y%m%dT%H%M%S.%fZ")
        os.replace(target, target.with_name(f"{target.name}.corrupt-{stamp}"))

    fd, raw_tmp = tempfile.mkstemp(prefix=f".{raw_hash}.", suffix=".part", dir=target.parent)
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
        ensure_safe_cas_shard(paths.archive, raw_hash[:2])
        os.replace(tmp, target)
        target.chmod(0o600)
        fsync_dir(target.parent)
        used_dictionary = None
        if dictionary is not None:
            used_dictionary = str(dictionary.relative_to(paths.archive))
        return target, compressed_hash, referenced, used_dictionary
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


def archive_planned_session(
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
    _assert_quarantine_device(paths, session)
    sources = [Path(member["path"]) for member in session["files"]]
    for source, member in zip(sources, session["files"], strict=True):
        if not identity_matches(source, member):
            raise SourceChangedError(f"source changed since plan: {source}")

    key = _manifest_key(session)
    manifest_path = paths.archive / "manifests" / session["provider"] / f"{key}.json"
    archived_members: list[dict[str, Any]] = []
    raw_bytes = 0
    compressed_bytes = 0
    for position, (source, member) in enumerate(zip(sources, session["files"], strict=True)):
        raw_hash = sha256_file(source)
        if not identity_matches(source, member):
            raise SourceChangedError(f"source changed while hashing: {source}")
        reference = sources[0] if position else None
        if reference is None and member["size"] > CHUNK_TARGET_BYTES:
            chunks = []
            chunk_compressed_bytes = 0
            for data in _chunk_records(source):
                chunk_relative, chunk_size = _ensure_chunk_object(paths, data, zstd)
                chunks.append({"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
                chunk_compressed_bytes += chunk_size
            archived_members.append(
                {**member, "raw_sha256": raw_hash, "chunks": chunks}
            )
            raw_bytes += member["size"]
            compressed_bytes += chunk_compressed_bytes
            continue
        active_dictionary = (
            dictionary if reference is None and member["size"] < SIZE_TIER_MID else None
        )
        object_path, compressed_hash, used_reference, used_dictionary = _ensure_object(
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
        archived_members.append(entry)
        raw_bytes += member["size"]
        compressed_bytes += object_path.stat().st_size

    extended = any(
        "reference" in member or "dictionary" in member or "chunks" in member
        for member in archived_members
    )
    manifest = {
        "schema_version": SCHEMA_VERSION if extended else 1,
        "kind": "session-archive",
        "archive_id": key,
        "provider": session["provider"],
        "session_id": session["session_id"],
        "source_root": session["source_root"],
        "last_activity": session["last_activity"],
        "archived_at": iso_utc(utc_now()),
        "zstd_version": _zstd_version(zstd),
        "files": archived_members,
        "directories": session.get("directories", []),
    }
    quarantine = quarantine_run / key
    restore_record = quarantine / "_restore.json"
    staged_manifest = quarantine / "_manifest.json"
    atomic_json(staged_manifest, manifest)
    atomic_json(
        restore_record,
        {
            "schema_version": SCHEMA_VERSION,
            "source_root": session["source_root"],
            "manifest": str(manifest_path),
            "files": [member["relative"] for member in archived_members],
            "directories": [item["relative"] for item in session.get("directories", [])],
        },
    )
    moved: list[tuple[Path, Path]] = []
    removed_directories: list[tuple[Path, dict[str, Any]]] = []
    try:
        for source, member in zip(sources, archived_members, strict=True):
            if not identity_matches(source, member):
                raise SourceChangedError(f"source changed before quarantine: {source}")
        if before_move is not None:
            before_move()
        for source, member in zip(sources, archived_members, strict=True):
            destination = quarantine / "files" / member["relative"]
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.replace(source, destination)
            moved.append((source, destination))
        for _, destination in moved:
            relative = str(destination.relative_to(quarantine / "files"))
            expected_hash = next(
                member["raw_sha256"] for member in archived_members if member["relative"] == relative
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
            if directory.is_symlink() or not directory.is_dir():
                raise SourceChangedError(f"bundle directory changed before removal: {directory}")
            try:
                directory.rmdir()
            except OSError as exc:
                raise SourceChangedError(f"bundle directory is no longer empty: {directory}") from exc
            removed_directories.append((directory, item))
        atomic_json(manifest_path, manifest)
        shutil.rmtree(quarantine)
    except Exception:
        for directory, item in reversed(removed_directories):
            directory.mkdir(parents=True, exist_ok=True, mode=item["mode"])
            directory.chmod(item["mode"])
        for source, destination in reversed(moved):
            if destination.exists() and not source.exists():
                source.parent.mkdir(parents=True, exist_ok=True)
                os.replace(destination, source)
        if not moved:
            shutil.rmtree(quarantine, ignore_errors=True)
        raise

    return {
        "manifest": str(manifest_path),
        "raw_bytes": raw_bytes,
        "compressed_bytes": compressed_bytes,
    }


def _apply_archive_plan_locked(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    paths.ensure_private()
    plan = load_json(plan_path)
    if plan.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS or plan.get("kind") != "archive-plan":
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
    manifests: list[str] = []
    raw_bytes = 0
    compressed_bytes = 0

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
        result = archive_planned_session(
            paths,
            session,
            zstd=zstd,
            quarantine_run=quarantine_run,
            dictionary=dictionaries[provider],
        )
        raw_bytes += result["raw_bytes"]
        compressed_bytes += result["compressed_bytes"]
        manifests.append(result["manifest"])
        if session_number % 500 == 0:
            print(
                f"archive progress: {session_number}/{len(sessions)} sessions committed",
                file=sys.stderr,
                flush=True,
            )

    if quarantine_run.exists() and not any(quarantine_run.iterdir()):
        quarantine_run.rmdir()
    return {
        "sessions": len(manifests),
        "raw_bytes": raw_bytes,
        "compressed_bytes": compressed_bytes,
        "reclaimed_bytes": raw_bytes - compressed_bytes,
        "manifest_count": len(manifests),
    }


def apply_archive_plan(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    with app_lock(paths):
        return _apply_archive_plan_locked(paths, plan_path)


def iter_manifests(paths: AppPaths) -> Iterator[Path]:
    root = paths.archive / "manifests"
    if root.is_dir():
        yield from sorted(root.rglob("*.json"))


_SIZE_BUCKETS = (
    ("lt_16_kib", 16 * 1024),
    ("16_to_64_kib", 64 * 1024),
    ("64_kib_to_1_mib", 1024**2),
    ("1_to_8_mib", 8 * 1024**2),
    ("gte_8_mib", None),
)


def archive_stats(paths: AppPaths) -> dict[str, Any]:
    """Summarize the archive graph from manifests without recompressing."""

    providers: dict[str, dict[str, Any]] = {}
    objects: dict[str, int] = {}
    for manifest_path in iter_manifests(paths):
        manifest = load_json(manifest_path)
        if manifest.get("kind") != "session-archive":
            continue
        provider = manifest.get("provider")
        if not isinstance(provider, str) or not provider:
            raise ValueError(f"archive manifest has no provider: {manifest_path}")
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
        members = manifest.get("files")
        if not isinstance(members, list):
            raise ValueError(f"archive manifest has invalid files: {manifest_path}")
        for index, member in enumerate(members):
            size = member.get("size")
            if not isinstance(size, int):
                raise ValueError(f"archive manifest member size is invalid: {manifest_path}")
            bucket["files"] += 1
            bucket["raw_bytes"] += size
            if index:
                bucket["companion_raw_bytes"] += size
            for name, limit in _SIZE_BUCKETS:
                if limit is None or size < limit:
                    bucket["size_histogram"][name] += 1
                    break
            chunks = member.get("chunks")
            if isinstance(chunks, list) and chunks:
                relatives = [_chunk_object_relative(chunk.get("sha256")) for chunk in chunks]
            else:
                relatives = [member["object"]]
            for relative in relatives:
                if relative not in objects:
                    objects[relative] = safe_cas_object_path(paths.archive, relative).stat().st_size
    compressed = sum(objects.values())
    raw = sum(bucket["raw_bytes"] for bucket in providers.values())
    return {
        "providers": providers,
        "manifests": sum(bucket["manifests"] for bucket in providers.values()),
        "objects": len(objects),
        "raw_bytes": raw,
        "compressed_bytes": compressed,
        "ratio": round(raw / compressed, 3) if compressed else None,
    }


TRAINABLE_PROVIDERS = ("claude", "codex", "codex-archived")


def train_dictionary(
    paths: AppPaths,
    provider: str,
    *,
    sample_limit: int = 256,
    max_dict_bytes: int = 112 * 1024,
) -> dict[str, Any]:
    """Train a provider dictionary from live sources and store it in the CAS."""

    if provider not in TRAINABLE_PROVIDERS:
        raise ValueError(f"provider is not trainable: {provider}")
    if sample_limit < 8:
        raise ValueError("dictionary training needs at least 8 samples")
    if max_dict_bytes < 1024:
        raise ValueError("dictionary size must be at least 1024 bytes")
    paths.ensure_private()
    zstd = _zstd_binary()

    candidates = []
    for unit in discover_sessions(paths):
        if unit.provider != provider:
            continue
        for source in unit.files:
            try:
                stat = regular_file_stat(source)
            except (OSError, ValueError):
                continue
            if 0 < stat["size"] < SIZE_TIER_MID:
                candidates.append(source)
    candidates.sort()
    if len(candidates) < 8:
        raise ValueError(
            f"insufficient training samples for {provider}: {len(candidates)}"
        )
    step = max(1, len(candidates) // sample_limit)
    samples = candidates[::step][:sample_limit]

    fd, raw_tmp = tempfile.mkstemp(prefix=".dictionary.", suffix=".part", dir=paths.archive)
    os.close(fd)
    tmp = Path(raw_tmp)
    try:
        tmp.unlink()
        subprocess.run(
            [
                zstd,
                "-q",
                "--train",
                *(str(path) for path in samples),
                "-o",
                str(tmp),
                f"--maxdict={max_dict_bytes}",
            ],
            check=True,
        )
        digest = sha256_file(tmp)
        shard = ensure_safe_cas_shard(paths.archive, digest[:2])
        relative = f"objects/sha256/{digest[:2]}/{digest}.dict"
        target = shard / f"{digest}.dict"
        if target.exists() or target.is_symlink():
            target = safe_cas_object_path(paths.archive, relative)
            if sha256_file(target) != digest:
                raise RuntimeError(f"dictionary object mismatch: {target}")
        else:
            os.replace(tmp, target)
            target.chmod(0o600)
            fsync_dir(target.parent)
    finally:
        tmp.unlink(missing_ok=True)

    pointer = {
        "schema_version": SCHEMA_VERSION,
        "kind": "compression-dictionary",
        "provider": provider,
        "object": relative,
        "raw_sha256": digest,
        "trained_at": iso_utc(utc_now()),
        "zstd_version": _zstd_version(zstd),
        "samples": len(samples),
        "max_dict_bytes": max_dict_bytes,
    }
    atomic_json(paths.archive / "dictionaries" / f"{provider}.json", pointer)
    return pointer


def _validate_member_relative(value: Any) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError("archive manifest member relative path is invalid")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"archive manifest member escaped its root: {value}")


def _decode_chunks_to(
    paths: AppPaths, zstd: str, chunks: list[dict[str, Any]], out: Any
) -> str:
    """Decode chunk objects into out, returning the whole-member raw hash."""

    whole = hashlib.sha256()
    for chunk in chunks:
        chunk_path = safe_cas_object_path(paths.archive, _chunk_object_relative(chunk["sha256"]))
        process = subprocess.Popen(
            [zstd, "-q", "-d", "--stdout", str(chunk_path)], stdout=subprocess.PIPE
        )
        assert process.stdout is not None
        digest = hashlib.sha256()
        with process.stdout:
            while block := process.stdout.read(4 * 1024 * 1024):
                digest.update(block)
                whole.update(block)
                out.write(block)
        if process.wait() != 0:
            raise RuntimeError(f"zstd chunk decode failed: {chunk_path}")
        if digest.hexdigest() != chunk["sha256"]:
            raise RuntimeError(f"chunk SHA-256 mismatch: {chunk_path}")
    return whole.hexdigest()


def _validate_chunk_entries(member: dict[str, Any], manifest_path: Path) -> list[dict[str, Any]]:
    chunks = member.get("chunks")
    if chunks is None:
        return []
    if (
        not isinstance(chunks, list)
        or not chunks
        or member.get("reference") is not None
        or member.get("dictionary") is not None
    ):
        raise ValueError(f"archive manifest chunks are invalid: {manifest_path}")
    for chunk in chunks:
        if not isinstance(chunk, dict) or not isinstance(chunk.get("size"), int):
            raise ValueError(f"archive manifest chunks are invalid: {manifest_path}")
        _chunk_object_relative(chunk.get("sha256"))
    return chunks


def verify_manifest(paths: AppPaths, manifest_path: Path) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    if manifest.get("kind") != "session-archive":
        raise ValueError(f"unsupported manifest: {manifest_path}")
    zstd = _zstd_binary()
    members = manifest["files"]
    for member in members:
        _validate_member_relative(member.get("relative"))
    referenced: set[str] = set()
    for member in members:
        reference = member.get("reference")
        if reference is not None:
            _validate_member_relative(reference)
            referenced.add(reference)
    with tempfile.TemporaryDirectory() as scratch:
        decoded: dict[str, Path] = {}
        for index, member in enumerate(members):
            chunks = _validate_chunk_entries(member, manifest_path)
            if chunks:
                if member["relative"] in referenced:
                    # A chunked member can still be a reference target for
                    # later members, so its decoded bytes must materialize.
                    capture = Path(scratch) / f"member-{index}"
                    with capture.open("wb") as out:
                        whole = _decode_chunks_to(paths, zstd, chunks, out)
                    if whole != member["raw_sha256"]:
                        raise RuntimeError(f"archive raw SHA-256 mismatch: {manifest_path}")
                    decoded[member["relative"]] = capture
                else:
                    for chunk in chunks:
                        chunk_path = safe_cas_object_path(
                            paths.archive, _chunk_object_relative(chunk["sha256"])
                        )
                        _verify_zstd(zstd, chunk_path, chunk["sha256"])
                continue
            object_path = safe_cas_object_path(paths.archive, member["object"])
            if sha256_file(object_path) != member["compressed_sha256"]:
                raise RuntimeError(f"compressed SHA-256 mismatch: {object_path}")
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
                dictionary_path = safe_cas_object_path(paths.archive, dictionary)
            capture = None
            if member["relative"] in referenced:
                capture = Path(scratch) / f"member-{index}"
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
    for item in manifest.get("directories", []):
        _validate_member_relative(item.get("relative"))
    return manifest


def verify_all(paths: AppPaths) -> dict[str, int]:
    manifests = 0
    files = 0
    for manifest_path in iter_manifests(paths):
        manifest = verify_manifest(paths, manifest_path)
        manifests += 1
        files += len(manifest["files"])
    return {"manifests": manifests, "files": files}


def resolve_manifest(paths: AppPaths, reference: str) -> Path:
    direct = Path(reference).expanduser()
    if direct.is_file():
        return direct
    matches = [path for path in iter_manifests(paths) if reference in path.stem]
    if len(matches) != 1:
        raise ValueError(f"manifest reference matched {len(matches)} entries: {reference}")
    return matches[0]


def restore_manifest(paths: AppPaths, reference: str, destination: Path | None = None) -> dict[str, Any]:
    manifest_path = resolve_manifest(paths, reference)
    manifest = verify_manifest(paths, manifest_path)
    root = destination.expanduser().resolve() if destination else Path(manifest["source_root"])
    zstd = _zstd_binary()
    # Preflight every target so a single collision cannot leave a partial
    # restore behind.
    for member in manifest["files"]:
        target = root / member["relative"]
        if target.exists() or target.is_symlink():
            raise FileExistsError(f"restore destination exists: {target}")
    restored = 0
    for member in manifest["files"]:
        target = root / member["relative"]
        if target.exists() or target.is_symlink():
            raise FileExistsError(f"restore destination exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, raw_tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".restore", dir=target.parent)
        os.close(fd)
        tmp = Path(raw_tmp)
        try:
            chunks = member.get("chunks")
            if chunks is not None:
                with tmp.open("wb") as out:
                    _decode_chunks_to(paths, zstd, chunks, out)
            else:
                decode_args = [zstd, "-q", "-d", "-f"]
                reference = member.get("reference")
                if reference is not None:
                    # The reference target restores earlier in this same loop;
                    # ordering is enforced by verify_manifest above.
                    decode_args.append(f"--patch-from={root / reference}")
                dictionary = member.get("dictionary")
                if dictionary is not None:
                    decode_args += ["-D", str(safe_cas_object_path(paths.archive, dictionary))]
                decode_args += [
                    str(safe_cas_object_path(paths.archive, member["object"])),
                    "-o",
                    str(tmp),
                ]
                subprocess.run(decode_args, check=True)
            if sha256_file(tmp) != member["raw_sha256"]:
                raise RuntimeError(f"restored SHA-256 mismatch: {target}")
            tmp.chmod(member["mode"])
            os.utime(tmp, ns=(member["mtime_ns"], member["mtime_ns"]))
            with tmp.open("rb") as handle:
                os.fsync(handle.fileno())
            os.replace(tmp, target)
            fsync_dir(target.parent)
            restored += 1
        finally:
            tmp.unlink(missing_ok=True)
    directories = sorted(
        manifest.get("directories", []),
        key=lambda item: len(Path(item["relative"]).parts),
        reverse=True,
    )
    for item in directories:
        target = root / item["relative"]
        if target.is_symlink():
            raise FileExistsError(f"restore destination is a symlink: {target}")
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Metadata is applied only after every member exists so that recreating
    # children cannot clobber a recorded parent mtime.
    for item in directories:
        target = root / item["relative"]
        target.chmod(item["mode"])
        os.utime(target, ns=(item["mtime_ns"], item["mtime_ns"]))
    if directories:
        fsync_dir(root)
    return {
        "archive_id": manifest["archive_id"],
        "files": restored,
        "directories": len(directories),
        "destination": str(root),
    }


def recover_quarantine(paths: AppPaths) -> dict[str, int]:
    root = paths.state / "quarantine"
    restored = 0
    conflicts = 0
    if not root.is_dir():
        return {"restored": 0, "conflicts": 0}
    for record in sorted(root.rglob("_restore.json")):
        payload = load_json(record)
        source_root = Path(payload["source_root"])
        files_root = record.parent / "files"
        record_conflicts = 0
        for relative in payload["files"]:
            source = source_root / relative
            quarantined = files_root / relative
            if not quarantined.exists():
                continue
            if source.exists() or source.is_symlink():
                conflicts += 1
                record_conflicts += 1
                continue
            source.parent.mkdir(parents=True, exist_ok=True)
            os.replace(quarantined, source)
            restored += 1
        for relative in payload.get("directories", []):
            target = source_root / relative
            if not target.exists() and not target.is_symlink():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
        remaining = [path for path in files_root.rglob("*") if path.is_file()] if files_root.exists() else []
        if not remaining and record_conflicts == 0:
            record.unlink(missing_ok=True)
            (record.parent / "_manifest.json").unlink(missing_ok=True)
            for directory in (files_root, record.parent, record.parent.parent):
                try:
                    directory.rmdir()
                except OSError:
                    pass
    return {"restored": restored, "conflicts": conflicts}
