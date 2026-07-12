from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


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
            archive=data / "storage-safeguard/archives",
            state=state / "storage-safeguard",
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


def identity_matches(path: Path, expected: dict[str, Any]) -> bool:
    try:
        current = regular_file_stat(path)
    except (FileNotFoundError, ValueError):
        return False
    return all(current[key] == expected[key] for key in ("device", "inode", "size", "mtime_ns"))


def open_file_paths() -> set[Path]:
    lsof = Path("/usr/sbin/lsof")
    if not lsof.exists():
        return set()
    result = subprocess.run(
        [str(lsof), "-nP", "-Fn"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        return set()
    paths: set[Path] = set()
    for line in result.stdout.splitlines():
        if line.startswith("n/"):
            paths.add(Path(line[1:]))
    return paths


def any_open(paths: Iterable[Path], opened: set[Path]) -> bool:
    resolved = [str(path) for path in paths]
    for candidate in opened:
        value = str(candidate)
        if any(value == root or value.startswith(root + os.sep) for root in resolved):
            return True
    return False


def run_checked(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(args, check=True, **kwargs)
