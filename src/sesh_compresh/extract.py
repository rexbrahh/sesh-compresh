"""Bounded extraction from immutable archive members."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import subprocess
from pathlib import Path
from typing import Any, BinaryIO

from .archive import (
    CHUNK_TARGET_BYTES,
    _chunk_object_relative,
    _zstd_binary,
    materialize_archive_frame,
    validate_manifest,
)
from .common import (
    _UNSUPPORTED_DIRECTORY_FSYNC_ERRNOS,
    AppPaths,
    app_lock,
    regular_file_stat,
    safe_cas_object_path,
)

_OS_LINK = os.link
_OUTPUT_PRIMITIVES_SUPPORTED = (
    os.name == "posix"
    and all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW"))
    and all(
        function in os.supports_dir_fd
        for function in (os.open, _OS_LINK, os.stat, os.unlink)
    )
    and _OS_LINK in os.supports_follow_symlinks
)


def _require_output_primitives() -> None:
    if not _OUTPUT_PRIMITIVES_SUPPORTED:
        raise RuntimeError("safe extraction output requires POSIX dir_fd support")


def _output_parent(destination: Path) -> tuple[Path, int]:
    _require_output_primitives()
    target = destination.expanduser()
    if not target.is_absolute():
        target = Path.cwd() / target
    parent = target.parent
    info = parent.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or parent.resolve(strict=True) != parent
    ):
        raise ValueError(f"extraction parent is not a canonical directory: {parent}")
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(parent_fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise RuntimeError(f"extraction parent changed while opening: {parent}")
        try:
            os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(f"extraction destination exists: {target}")
        return target, parent_fd
    except BaseException:
        os.close(parent_fd)
        raise


def _parent_matches(path: Path, parent_fd: int) -> bool:
    try:
        current = path.lstat()
    except OSError:
        return False
    opened = os.fstat(parent_fd)
    return (
        stat.S_ISDIR(current.st_mode)
        and not stat.S_ISLNK(current.st_mode)
        and (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino)
    )


def _sync_parent(parent_fd: int) -> None:
    try:
        os.fsync(parent_fd)
    except OSError as error:
        if error.errno not in _UNSUPPORTED_DIRECTORY_FSYNC_ERRNOS:
            raise


def _temporary_output(parent_fd: int, target_name: str) -> tuple[str, int]:
    while True:
        name = f".{target_name}.{secrets.token_hex(8)}.part"
        try:
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
        except FileExistsError:
            continue
        return name, fd


def _decode_frame_range(
    zstd: str,
    frame: Path,
    *,
    expected_hash: str,
    expected_size: int,
    range_start: int,
    range_end: int,
    output: BinaryIO,
    dictionary: Path | None = None,
) -> int:
    extra = ["-D", str(dictionary)] if dictionary is not None else []
    process = subprocess.Popen(
        [zstd, "-q", "-d", "--stdout", *extra, str(frame)],
        stdout=subprocess.PIPE,
    )
    assert process.stdout is not None
    digest = hashlib.sha256()
    decoded = 0
    written = 0
    try:
        with process.stdout:
            while block := process.stdout.read(4 * 1024 * 1024):
                block_start = decoded
                decoded += len(block)
                if decoded > expected_size:
                    raise RuntimeError(
                        f"archive frame decoded beyond its size: {frame}"
                    )
                digest.update(block)
                start = max(range_start, block_start) - block_start
                end = min(range_end, decoded) - block_start
                if start < end:
                    output.write(block[start:end])
                    written += end - start
        status = process.wait()
    except BaseException:
        process.kill()
        process.wait()
        raise
    if status != 0:
        raise RuntimeError(f"zstd frame decode failed with status {status}: {frame}")
    if decoded != expected_size:
        raise RuntimeError(f"archive frame size mismatch: {frame}")
    if digest.hexdigest() != expected_hash:
        raise RuntimeError(f"archive frame SHA-256 mismatch: {frame}")
    return written


def extract_member_range(
    paths: AppPaths,
    manifest_path: Path,
    member_relative: str,
    start: int,
    length: int,
    destination: Path,
) -> dict[str, Any]:
    """Extract one exact byte range without overwriting an existing path."""

    with app_lock(paths):
        return _extract_member_range_locked(
            paths, manifest_path, member_relative, start, length, destination
        )


def extract_member_tail(
    paths: AppPaths,
    manifest_path: Path,
    member_relative: str,
    tail_bytes: int,
    destination: Path,
) -> dict[str, Any]:
    """Extract an exact member tail without overwriting an existing path."""

    with app_lock(paths):
        return _extract_member_range_locked(
            paths,
            manifest_path,
            member_relative,
            None,
            None,
            destination,
            tail_bytes=tail_bytes,
        )


def _extract_member_range_locked(
    paths: AppPaths,
    manifest_path: Path,
    member_relative: str,
    start: int | None,
    length: int | None,
    destination: Path,
    *,
    tail_bytes: int | None = None,
) -> dict[str, Any]:
    """Extract while the caller holds the application lock."""

    regular_file_stat(manifest_path)
    manifest = validate_manifest(manifest_path)
    if not isinstance(member_relative, str) or not member_relative:
        raise ValueError("archive extraction member must be a non-empty string")
    members = [
        member for member in manifest["files"] if member["relative"] == member_relative
    ]
    if len(members) != 1:
        raise ValueError(f"archive extraction member matched {len(members)} entries")
    member = members[0]
    if tail_bytes is not None:
        if type(tail_bytes) is not int or tail_bytes < 0 or tail_bytes > member["size"]:
            raise ValueError("archive extraction tail is outside the member")
        start = member["size"] - tail_bytes
        length = tail_bytes
    if type(start) is not int or type(length) is not int:
        raise ValueError("archive extraction bounds must be integers")
    if start < 0 or length < 0 or start + length > member["size"]:
        raise ValueError("archive extraction range is outside the member")
    if length and "reference" in member:
        raise ValueError("referenced archive members are not seekable")
    chunks = member.get("chunks")
    if length and chunks is None and member["size"] > CHUNK_TARGET_BYTES:
        raise ValueError("large whole-file archive members are not seekable")
    target, parent_fd = _output_parent(destination)

    temp_name = None
    temp_fd = -1
    decoded_frames = 0
    written = 0
    try:
        temp_name, temp_fd = _temporary_output(parent_fd, target.name)
        output_handle = os.fdopen(temp_fd, "wb")
        temp_fd = -1
        with output_handle as output:
            if length == 0:
                pass
            elif chunks is not None:
                zstd = _zstd_binary()
                range_end = start + length
                chunk_start = 0
                for chunk in chunks:
                    chunk_end = chunk_start + chunk["size"]
                    if chunk_end > start and chunk_start < range_end:
                        with materialize_archive_frame(
                            paths, _chunk_object_relative(chunk["sha256"])
                        ) as frame:
                            written += _decode_frame_range(
                                zstd,
                                frame,
                                expected_hash=chunk["sha256"],
                                expected_size=chunk["size"],
                                range_start=max(start, chunk_start) - chunk_start,
                                range_end=min(range_end, chunk_end) - chunk_start,
                                output=output,
                            )
                        decoded_frames += 1
                    chunk_start = chunk_end
            else:
                zstd = _zstd_binary()
                dictionary = member.get("dictionary")
                dictionary_path = (
                    safe_cas_object_path(paths.archive, dictionary, kind="dictionary")
                    if dictionary is not None
                    else None
                )
                with materialize_archive_frame(
                    paths,
                    member["object"],
                    expected_compressed_sha256=member["compressed_sha256"],
                ) as frame:
                    written = _decode_frame_range(
                        zstd,
                        frame,
                        expected_hash=member["raw_sha256"],
                        expected_size=member["size"],
                        range_start=start,
                        range_end=start + length,
                        output=output,
                        dictionary=dictionary_path,
                    )
                decoded_frames = 1
            if written != length:
                raise RuntimeError("archive extraction produced the wrong byte count")
            output.flush()
            os.fsync(output.fileno())
        if not _parent_matches(target.parent, parent_fd):
            raise RuntimeError(
                f"extraction parent changed before publication: {target.parent}"
            )
        _OS_LINK(
            temp_name,
            target.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if not _parent_matches(target.parent, parent_fd):
            os.unlink(target.name, dir_fd=parent_fd)
            _sync_parent(parent_fd)
            raise RuntimeError(
                f"extraction parent changed during publication: {target.parent}"
            )
        os.unlink(temp_name, dir_fd=parent_fd)
        temp_name = None
        _sync_parent(parent_fd)
    finally:
        try:
            if temp_fd >= 0:
                os.close(temp_fd)
            if temp_name is not None:
                try:
                    os.unlink(temp_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                else:
                    _sync_parent(parent_fd)
        finally:
            os.close(parent_fd)

    return {
        "manifest": str(manifest_path),
        "member": member_relative,
        "start": start,
        "length": length,
        "output": str(target),
        "decoded_frames": decoded_frames,
        "total_frames": len(chunks) if chunks is not None else 1,
    }
