from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import unicodedata
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Iterator, Literal, Protocol

if os.name == "nt":
    import msvcrt as _msvcrt

    _fcntl = None
else:
    import fcntl as _fcntl

    _msvcrt = None


SCHEMA_VERSION = 2
SUPPORTED_SCHEMA_VERSIONS = (1, 2)

_CAS_ZSTD_NAME = re.compile(
    r"^(?P<raw>[0-9a-f]{64})(?:\.(?P<compressed>[0-9a-f]{64}))?\.zst$"
)
_CAS_DICTIONARY_NAME = re.compile(r"^(?P<raw>[0-9a-f]{64})\.dict$")
_CAS_TEMP_NAME = re.compile(r"^\.(?P<raw>[0-9a-f]{64})\.[a-z0-9_]{8}\.part$")
_RUN_ID = re.compile(r"^\d{8}T\d{6}\.\d{6}Z-[0-9a-f]{32}$")

CasObjectKind = Literal["zstd", "dictionary", "temporary"]

_UNSUPPORTED_DIRECTORY_FSYNC_ERRNOS = frozenset(
    value
    for value in (
        errno.EINVAL,
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
    )
    if value is not None
)

_ARCHIVE_PRIVATE_LAYOUT = (
    ("manifests",),
    ("dictionaries",),
    ("objects",),
    ("objects", "sha256"),
)
_STATE_PRIVATE_LAYOUT = (
    ("clean-quarantine",),
    ("latest",),
    ("plans",),
    ("quarantine",),
)


def _configured_root(value: str | Path, *, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute: {path}")
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} cannot be canonicalized: {path}: {exc}") from exc


@dataclass(frozen=True)
class AppPaths:
    home: Path
    archive: Path
    state: Path

    @classmethod
    def discover(cls, home: Path | None = None) -> "AppPaths":
        resolved = _configured_root(home or Path.home(), label="home directory")
        if home is not None:
            data = resolved / ".local/share"
            state = resolved / ".local/state"
        else:
            data = _configured_root(
                os.environ.get("XDG_DATA_HOME", resolved / ".local/share"),
                label="XDG data directory",
            )
            state = _configured_root(
                os.environ.get("XDG_STATE_HOME", resolved / ".local/state"),
                label="XDG state directory",
            )
        return cls(
            home=resolved,
            archive=data / "sesh-compresh/archives",
            state=state / "sesh-compresh",
        )

    def ensure_private(self) -> None:
        anchors = [
            (self.archive, "archive root"),
            (self.state, "state root"),
            *(
                (self.archive.joinpath(*parts), "archive private directory")
                for parts in _ARCHIVE_PRIVATE_LAYOUT
            ),
            *(
                (self.state.joinpath(*parts), "state private directory")
                for parts in _STATE_PRIVATE_LAYOUT
            ),
        ]
        for path, label in anchors:
            _inspect_directory_anchor(path, label=label, allow_missing=True)
        dynamic = [
            *(
                (path, "archive provider anchor")
                for path in _directory_anchor_children(
                    self.archive / "manifests", label="archive manifests root"
                )
            ),
            *(
                (path, "archive CAS shard")
                for path in _directory_anchor_children(
                    self.archive / "objects/sha256", label="archive CAS root"
                )
            ),
            *(
                (path, "quarantine run anchor")
                for path in _directory_anchor_children(
                    self.state / "quarantine", label="quarantine root"
                )
            ),
        ]
        _secure_directory_anchor(self.archive, label="archive root", parents=True)
        _secure_directory_anchor(self.state, label="state root", parents=True)
        for parts in _ARCHIVE_PRIVATE_LAYOUT:
            ensure_private_subdirectory(self.archive, *parts)
        for parts in _STATE_PRIVATE_LAYOUT:
            ensure_private_subdirectory(self.state, *parts)
        for path, label in dynamic:
            _secure_directory_anchor(path, label=label, parents=False)


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_run_id(current: datetime) -> str:
    return f"{current.astimezone(UTC):%Y%m%dT%H%M%S.%fZ}-{uuid.uuid4().hex}"


def validate_run_id(value: Any) -> str:
    if type(value) is not str or _RUN_ID.fullmatch(value) is None:
        raise ValueError("plan run identifier is invalid")
    return value


def iso_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def sha256_file(path: Path, chunk_size: int = 4 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_stream(stream: Any, chunk_size: int = 4 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(chunk_size):
        digest.update(chunk)
    return digest.hexdigest()


def atomic_json(
    path: Path, payload: dict[str, Any], *, replace: bool = True
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(raw)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(tmp, path)
        else:
            os.link(tmp, path)
        fsync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    except OSError as exc:
        if exc.errno not in _UNSUPPORTED_DIRECTORY_FSYNC_ERRNOS:
            raise
    finally:
        os.close(fd)


def allocated_bytes(path: Path) -> int:
    if path.is_file():
        return path.stat(follow_symlinks=False).st_blocks * 512
    total = path.stat(follow_symlinks=False).st_blocks * 512
    for root, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            candidate = Path(root, name)
            try:
                total += candidate.stat(follow_symlinks=False).st_blocks * 512
            except FileNotFoundError:
                continue
    return total


def regular_file_stat(path: Path) -> dict[str, int]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"source is not a regular non-symlink file: {path}")
    stat = path.stat(follow_symlinks=False)
    return {
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "mode": stat.st_mode & 0o777,
    }


def regular_directory_stat(path: Path) -> dict[str, int]:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"source is not a regular non-symlink directory: {path}")
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mtime_ns": info.st_mtime_ns,
        "mode": info.st_mode & 0o777,
    }


def identity_matches(path: Path, expected: dict[str, Any]) -> bool:
    try:
        current = regular_file_stat(path)
    except (FileNotFoundError, ValueError):
        return False
    return all(current[key] == expected[key] for key in ("device", "inode", "size", "mtime_ns"))


def directory_identity_matches(path: Path, expected: dict[str, Any]) -> bool:
    try:
        current = regular_directory_stat(path)
    except (FileNotFoundError, ValueError):
        return False
    return all(current[key] == expected[key] for key in ("device", "inode", "mtime_ns"))


class LockBackend(Protocol):
    def acquire(self, fd: int) -> None: ...

    def release(self, fd: int) -> None: ...


class _PosixLockBackend:
    def acquire(self, fd: int) -> None:
        assert _fcntl is not None
        _fcntl.flock(fd, _fcntl.LOCK_EX)

    def release(self, fd: int) -> None:
        assert _fcntl is not None
        _fcntl.flock(fd, _fcntl.LOCK_UN)


class _WindowsLockBackend:
    def acquire(self, fd: int) -> None:
        assert _msvcrt is not None
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
            os.fsync(fd)
        while True:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
                return
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                    raise
                time.sleep(0.1)

    def release(self, fd: int) -> None:
        assert _msvcrt is not None
        os.lseek(fd, 0, os.SEEK_SET)
        _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)


def _platform_lock_backend() -> LockBackend:
    return _WindowsLockBackend() if os.name == "nt" else _PosixLockBackend()


@contextmanager
def app_lock(paths: AppPaths, *, backend: LockBackend | None = None) -> Iterator[None]:
    """Serialize local archive publication, GC mutation, and CAS collection."""

    paths.ensure_private()
    lock_path = paths.state / "archive.lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        selected = backend or _platform_lock_backend()
        selected.acquire(fd)
        try:
            yield
        finally:
            selected.release(fd)
    finally:
        os.close(fd)


def _inspect_directory_anchor(
    path: Path, *, label: str, allow_missing: bool = False
) -> os.stat_result | None:
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute: {path}")
    try:
        canonical = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} cannot be canonicalized: {path}: {exc}") from exc
    if canonical != path:
        raise ValueError(f"{label} is not canonical or has a symlinked ancestor: {path}")
    try:
        info = path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return None
        raise ValueError(f"{label} is unavailable: {path}") from None
    except OSError as exc:
        raise ValueError(f"{label} is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"{label} is not a real directory: {path}")
    return info


def _directory_anchor_children(path: Path, *, label: str) -> list[Path]:
    info = _inspect_directory_anchor(path, label=label, allow_missing=True)
    if info is None:
        return []
    try:
        with os.scandir(path) as entries:
            children = sorted(entries, key=lambda entry: entry.name)
    except OSError as exc:
        raise ValueError(f"{label} cannot be scanned: {path}: {exc}") from exc
    result = []
    for entry in children:
        child = Path(entry.path)
        _inspect_directory_anchor(child, label=f"{label} child")
        result.append(child)
    return result


def _secure_directory_anchor(path: Path, *, label: str, parents: bool) -> Path:
    info = _inspect_directory_anchor(path, label=label, allow_missing=True)
    if info is None:
        try:
            path.mkdir(parents=parents, mode=0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise ValueError(f"{label} cannot be created: {path}: {exc}") from exc
        info = _inspect_directory_anchor(path, label=label)
    if os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o700:
        try:
            path.chmod(0o700)
        except OSError as exc:
            raise ValueError(f"{label} permissions cannot be secured: {path}: {exc}") from exc
        info = _inspect_directory_anchor(path, label=label)
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError(f"{label} permissions are not private: {path}")
    return path


def validate_private_subdirectory(root: Path, *parts: str) -> Path:
    """Validate a private descendant path without creating it."""

    _directory_without_symlinks(root, label="private root")
    current = root
    for part in parts:
        component = Path(part)
        if component.is_absolute() or component.parts != (part,) or part in {"", ".", ".."}:
            raise ValueError(f"private directory has an invalid component: {part}")
        target = current / part
        _inspect_directory_anchor(
            target, label="private subdirectory", allow_missing=True
        )
        if target.parent != current:
            raise ValueError(f"private subdirectory escaped its root: {target}")
        current = target
    return current


def ensure_private_subdirectory(root: Path, *parts: str) -> Path:
    """Create validated private directories below one canonical private root."""

    validate_private_subdirectory(root, *parts)
    current = root
    for part in parts:
        current = _secure_directory_anchor(
            current / part, label="private subdirectory", parents=False
        )
    return current


def _directory_without_symlinks(path: Path, *, label: str) -> Path:
    info = _inspect_directory_anchor(path, label=label)
    assert info is not None
    if os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError(f"{label} permissions are not private: {path}")
    try:
        canonical = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} cannot be canonicalized: {path}: {exc}") from exc
    if canonical != path:
        raise ValueError(f"{label} is not canonical: {path}")
    return canonical


def safe_cas_root(archive: Path) -> tuple[Path, Path]:
    canonical_archive = _directory_without_symlinks(archive, label="archive root")
    objects = archive / "objects"
    canonical_objects = _directory_without_symlinks(objects, label="archive objects root")
    if canonical_objects.parent != canonical_archive:
        raise ValueError(f"archive objects root escaped the archive: {objects}")
    root = archive / "objects" / "sha256"
    canonical_root = _directory_without_symlinks(root, label="archive CAS root")
    if canonical_root.parent != canonical_objects:
        raise ValueError(f"archive CAS root escaped archive objects: {root}")
    try:
        canonical_root.relative_to(canonical_archive)
    except ValueError as exc:
        raise ValueError(f"archive CAS root escaped the canonical archive: {root}") from exc
    return root, canonical_root


def safe_cas_shard(archive: Path, shard_name: str) -> tuple[Path, Path]:
    if len(shard_name) != 2 or any(character not in "0123456789abcdef" for character in shard_name):
        raise ValueError(f"invalid archive CAS shard: {shard_name}")
    root, canonical_root = safe_cas_root(archive)
    shard = root / shard_name
    canonical_shard = _directory_without_symlinks(shard, label="archive CAS shard")
    if canonical_shard.parent != canonical_root:
        raise ValueError(f"archive CAS shard escaped its root: {shard}")
    return shard, canonical_shard


def ensure_safe_cas_shard(archive: Path, shard_name: str) -> Path:
    if len(shard_name) != 2 or any(
        character not in "0123456789abcdef" for character in shard_name
    ):
        raise ValueError(f"invalid archive CAS shard: {shard_name}")
    shard = ensure_private_subdirectory(
        archive, "objects", "sha256", shard_name
    )
    safe_cas_shard(archive, shard_name)
    return shard


def cas_object_name_details(
    name: str,
) -> tuple[CasObjectKind, str, str | None] | None:
    """Classify a CAS name and return its shard and compressed digest."""

    zstd = _CAS_ZSTD_NAME.fullmatch(name)
    if zstd is not None:
        return "zstd", zstd.group("raw")[:2], zstd.group("compressed")
    dictionary = _CAS_DICTIONARY_NAME.fullmatch(name)
    if dictionary is not None:
        return "dictionary", dictionary.group("raw")[:2], None
    temporary = _CAS_TEMP_NAME.fullmatch(name)
    if temporary is not None:
        return "temporary", temporary.group("raw")[:2], None
    return None


def safe_cas_object_path(
    archive: Path,
    value: str,
    *,
    kind: CasObjectKind,
    content_validation: bool = True,
) -> Path:
    relative = Path(value)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or len(relative.parts) != 4
        or relative.parts[:2] != ("objects", "sha256")
    ):
        raise ValueError(f"archive object escaped the CAS: {value}")
    details = cas_object_name_details(relative.name)
    if details is None or details[0] != kind:
        raise ValueError(
            f"archive object has an invalid CAS name for {kind}: {value}"
        )
    _, expected_shard, compressed_digest = details
    if relative.parts[2] != expected_shard:
        raise ValueError(f"archive object is in the wrong CAS shard: {value}")
    shard, canonical_shard = safe_cas_shard(archive, expected_shard)
    target = shard / relative.parts[3]
    try:
        info = target.lstat()
    except OSError as exc:
        raise ValueError(f"archive object is unavailable: {target}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"archive object is not a regular file: {target}")
    try:
        canonical_target = target.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"archive object cannot be canonicalized: {target}: {exc}") from exc
    _, canonical_root = safe_cas_root(archive)
    try:
        canonical_target.relative_to(canonical_root)
    except ValueError as exc:
        raise ValueError(f"archive object escaped the canonical CAS: {target}") from exc
    if canonical_target.parent != canonical_shard:
        raise ValueError(f"archive object escaped its canonical shard: {target}")
    if (
        content_validation
        and compressed_digest is not None
        and sha256_file(target) != compressed_digest
    ):
        raise ValueError(f"archive CAS compressed digest mismatch: {target}")
    return target


def _prune_expired_plans_locked(paths: AppPaths, *, keep: int) -> int:
    if keep < 0:
        raise ValueError("retained expired plan count must be non-negative")
    plans_root = paths.state / "plans"
    if not plans_root.is_dir() or plans_root.is_symlink():
        return 0
    expired: list[tuple[datetime, Path, dict[str, int]]] = []
    current = utc_now()
    for plan_path in sorted(plans_root.glob("*.json")):
        try:
            identity = regular_file_stat(plan_path)
            payload = load_json(plan_path)
            expires_at = payload.get("expires_at")
            if isinstance(expires_at, str) and parse_timestamp(expires_at) < current:
                expired.append((parse_timestamp(expires_at), plan_path, identity))
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            continue
    expired.sort(key=lambda item: (item[0], str(item[1])), reverse=True)
    removed = 0
    for _, plan_path, identity in expired[keep:]:
        if not identity_matches(plan_path, identity):
            continue
        try:
            plan_path.unlink()
            removed += 1
        except OSError:
            continue
    return removed


def prune_expired_plans(paths: AppPaths, *, keep: int = 32) -> int:
    """Bound tool-owned plan history while preserving every live plan."""

    with app_lock(paths):
        return _prune_expired_plans_locked(paths, keep=keep)


def open_file_paths(*, strict: bool = False) -> set[Path]:
    """Return paths currently reported open by ``lsof``.

    Existing archive and cache commands retain their best-effort behavior.  A
    caller making reference-sensitive decisions can opt into ``strict`` mode,
    where a missing or failed enumerator aborts the operation instead of
    making an empty set look authoritative.
    """

    discovered = _lsof_binary()
    if discovered is None:
        if strict:
            raise RuntimeError("open-file enumeration unavailable: lsof was not found")
        return set()
    result = subprocess.run(
        [discovered, "-nP", "-Fn0"],
        capture_output=True,
        text=True,
        errors="surrogateescape",
        check=False,
    )
    if strict and result.returncode != 0:
        detail = result.stderr.strip()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(f"open-file enumeration failed with status {result.returncode}{suffix}")
    if result.returncode not in (0, 1):
        return set()
    return _parse_lsof_paths(result.stdout)


def _lsof_binary() -> str | None:
    discovered = shutil.which("lsof")
    if discovered is None and Path("/usr/sbin/lsof").is_file():
        return "/usr/sbin/lsof"
    return discovered


class _LsofPaths(set[Path]):
    def __init__(self, paths: Iterable[Path], encoded_names: Iterable[str]) -> None:
        super().__init__(paths)
        self.encoded_names = list(encoded_names)

    def update(self, *others: Iterable[Path]) -> None:
        for other in others:
            if isinstance(other, _LsofPaths):
                self.encoded_names.extend(other.encoded_names)
            super().update(other)


def _parse_lsof_paths(output: str) -> set[Path]:
    fields = [field.lstrip("\n") for field in output.split("\0")]
    names = [field[1:] for field in fields if field.startswith("n/")]
    return _LsofPaths(
        (Path(value) for name in names for value in _decode_lsof_names(name)),
        names,
    )


def _decode_lsof_names(value: str) -> set[str]:
    decoded, _ = _decode_lsof_value(value)
    return {os.fsdecode(item) for item in decoded}


def _decode_lsof_value(value: str) -> tuple[set[bytes], bool]:
    raw = os.fsencode(value)
    escapes = {
        ord("b"): 8,
        ord("f"): 12,
        ord("n"): 10,
        ord("r"): 13,
        ord("t"): 9,
        ord("\\"): 92,
    }
    pending = [(0, b"")]
    decoded = set()
    while pending and len(decoded) < 4096:
        index, prefix = pending.pop()
        if index == len(raw):
            decoded.add(prefix)
            continue
        current = raw[index]
        if current == 92 and index + 1 < len(raw):
            escaped = raw[index + 1]
            if escaped in escapes:
                pending.append((index + 2, prefix + bytes((escapes[escaped],))))
                continue
            if escaped == ord("x") and index + 3 < len(raw):
                try:
                    pending.append(
                        (index + 4, prefix + bytes((int(raw[index + 2 : index + 4], 16),)))
                    )
                    continue
                except ValueError:
                    pass
        if current == ord("^") and index + 1 < len(raw):
            control = raw[index + 1]
            if control == ord("?") or 65 <= control <= 95:
                pending.append(
                    (index + 2, prefix + bytes((255 if control == ord("?") else control & 31,)))
                )
                pending.append((index + 1, prefix + b"^"))
                continue
        pending.append((index + 1, prefix + bytes((current,))))
    return decoded, not pending


def _lsof_component_matches(encoded: str, component: str) -> bool:
    decoded, complete = _decode_lsof_value(encoded)
    if not complete:
        return True
    expected = unicodedata.normalize("NFC", component).casefold()
    return any(
        unicodedata.normalize("NFC", os.fsdecode(value)).casefold() == expected
        for value in decoded
    )


def _lsof_name_matches_root(encoded_name: str, root: Path) -> bool:
    encoded_parts = encoded_name.split("/")
    root_parts = root.parts
    if not root.is_absolute() or not encoded_parts or encoded_parts[0]:
        return False
    components = root_parts[1:]
    return len(encoded_parts) - 1 >= len(components) and all(
        _lsof_component_matches(encoded, component)
        for encoded, component in zip(encoded_parts[1:], components, strict=False)
    )


def open_file_paths_for(
    candidates: Iterable[Path],
    *,
    batch_size: int = 128,
    recursive: bool = False,
) -> set[Path]:
    """Enumerate open candidate paths through bounded, path-filtered lsof calls.

    Recursive mode uses one ``+D`` query per directory because naming a
    directory alone does not select its open descendants.
    """

    if batch_size <= 0:
        raise ValueError("lsof batch size must be positive")
    paths = tuple(dict.fromkeys(Path(path) for path in candidates))
    if not paths:
        return set()
    binary = _lsof_binary()
    if binary is None:
        raise RuntimeError("open-file enumeration unavailable: lsof was not found")
    opened: set[Path] = _LsofPaths((), ())
    batches = (
        tuple((path,) for path in paths)
        if recursive
        else tuple(
            paths[offset : offset + batch_size]
            for offset in range(0, len(paths), batch_size)
        )
    )
    for batch in batches:
        filters = [str(path) for path in batch]
        if recursive and batch[0].is_dir():
            filters = ["-x", "f", "+D", str(batch[0])]
        try:
            result = subprocess.run(
                [binary, "-nP", "-Fn0", *filters],
                capture_output=True,
                text=True,
                errors="surrogateescape",
                check=False,
            )
        except OSError as exc:
            raise RuntimeError(
                f"path-filtered open-file enumeration could not execute: {exc}"
            ) from exc
        if result.stderr:
            detail = result.stderr.strip() or repr(result.stderr)
            raise RuntimeError(
                "path-filtered open-file enumeration reported diagnostics "
                f"with status {result.returncode}: {detail}"
            )
        if result.returncode not in (0, 1):
            raise RuntimeError(
                f"path-filtered open-file enumeration failed with status {result.returncode}"
            )
        opened.update(_parse_lsof_paths(result.stdout))
    return opened


def any_open(paths: Iterable[Path], opened: set[Path]) -> bool:
    def components(path: Path) -> tuple[str, ...]:
        return tuple(
            unicodedata.normalize("NFC", part).casefold()
            for part in path.resolve(strict=False).parts
        )

    resolved = [path.resolve(strict=False) for path in paths]
    if isinstance(opened, _LsofPaths) and any(
        _lsof_name_matches_root(name, root)
        for name in opened.encoded_names
        for root in resolved
    ):
        return True
    roots = [components(path) for path in resolved]
    for candidate in opened:
        value = components(candidate)
        for root in roots:
            if value[: len(root)] == root:
                return True
    return False


def run_checked(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(args, check=True, **kwargs)
