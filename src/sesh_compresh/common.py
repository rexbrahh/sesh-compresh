from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Protocol

if os.name == "nt":
    import msvcrt as _msvcrt

    _fcntl = None
else:
    import fcntl as _fcntl

    _msvcrt = None


SCHEMA_VERSION = 1


@dataclass(frozen=True)
class AppPaths:
    home: Path
    archive: Path
    state: Path

    @classmethod
    def discover(cls, home: Path | None = None) -> "AppPaths":
        resolved = (home or Path.home()).expanduser().resolve()
        if home is not None:
            data = resolved / ".local/share"
            state = resolved / ".local/state"
        else:
            data = Path(os.environ.get("XDG_DATA_HOME", resolved / ".local/share"))
            state = Path(os.environ.get("XDG_STATE_HOME", resolved / ".local/state"))
        return cls(
            home=resolved,
            archive=data / "sesh-compresh/archives",
            state=state / "sesh-compresh",
        )

    def ensure_private(self) -> None:
        for path in (self.archive, self.state):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.chmod(0o700)


def utc_now() -> datetime:
    return datetime.now(UTC)


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


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
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
        os.replace(tmp, path)
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
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
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
def app_lock(paths: AppPaths, *, backend: LockBackend | None = None) -> Iterable[None]:
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


def _directory_without_symlinks(path: Path, *, label: str) -> Path:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"{label} is not a real directory: {path}")
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} cannot be canonicalized: {path}: {exc}") from exc


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
    _directory_without_symlinks(archive, label="archive root")
    objects = archive / "objects"
    objects.mkdir(exist_ok=True, mode=0o700)
    _directory_without_symlinks(objects, label="archive objects root")
    root = archive / "objects" / "sha256"
    root.mkdir(exist_ok=True, mode=0o700)
    _directory_without_symlinks(root, label="archive CAS root")
    shard = root / shard_name
    shard.mkdir(exist_ok=True, mode=0o700)
    safe_cas_shard(archive, shard_name)
    return shard


def safe_cas_object_path(archive: Path, value: str) -> Path:
    relative = Path(value)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or len(relative.parts) != 4
        or relative.parts[:2] != ("objects", "sha256")
    ):
        raise ValueError(f"archive object escaped the CAS: {value}")
    shard, canonical_shard = safe_cas_shard(archive, relative.parts[2])
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
    return target


def prune_expired_plans(paths: AppPaths, *, keep: int = 32) -> int:
    """Bound tool-owned plan history while preserving every live plan."""

    if keep < 0:
        raise ValueError("retained expired plan count must be non-negative")
    plans_root = paths.state / "plans"
    if not plans_root.is_dir() or plans_root.is_symlink():
        return 0
    with app_lock(paths):
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
        [discovered, "-nP", "-Fn"],
        capture_output=True,
        text=True,
        check=False,
    )
    if strict and result.returncode != 0:
        detail = result.stderr.strip()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(f"open-file enumeration failed with status {result.returncode}{suffix}")
    if result.returncode not in (0, 1):
        return set()
    paths: set[Path] = set()
    for line in result.stdout.splitlines():
        if line.startswith("n/"):
            paths.add(Path(line[1:]))
    return paths


def _lsof_binary() -> str | None:
    discovered = shutil.which("lsof")
    if discovered is None and Path("/usr/sbin/lsof").is_file():
        return "/usr/sbin/lsof"
    return discovered


def _parse_lsof_paths(output: str) -> set[Path]:
    return {Path(line[1:]) for line in output.splitlines() if line.startswith("n/")}


def open_file_paths_for(
    candidates: Iterable[Path],
    *,
    batch_size: int = 128,
) -> set[Path]:
    """Enumerate open candidate paths through bounded, path-filtered lsof calls."""

    if batch_size <= 0:
        raise ValueError("lsof batch size must be positive")
    paths = tuple(dict.fromkeys(Path(path) for path in candidates))
    if not paths:
        return set()
    binary = _lsof_binary()
    if binary is None:
        raise RuntimeError("open-file enumeration unavailable: lsof was not found")
    opened: set[Path] = set()
    for offset in range(0, len(paths), batch_size):
        batch = paths[offset : offset + batch_size]
        result = subprocess.run(
            [binary, "-nP", "-Fn", *(str(path) for path in batch)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 1 and not result.stdout.strip() and not result.stderr.strip():
            continue
        if result.returncode != 0:
            detail = result.stderr.strip()
            suffix = f": {detail}" if detail else ""
            raise RuntimeError(
                f"path-filtered open-file enumeration failed with status {result.returncode}{suffix}"
            )
        opened.update(_parse_lsof_paths(result.stdout))
    return opened


def any_open(paths: Iterable[Path], opened: set[Path]) -> bool:
    resolved = [str(path) for path in paths]
    for candidate in opened:
        value = str(candidate)
        if any(value == root or value.startswith(root + os.sep) for root in resolved):
            return True
    return False


def run_checked(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(args, check=True, **kwargs)
