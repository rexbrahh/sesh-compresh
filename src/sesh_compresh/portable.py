from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import unicodedata
import zipfile
from datetime import timedelta
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable

from .archive import (
    _chunk_object_relative,
    _manifest_session_key,
    _refresh_latest_indexes,
    iter_manifests,
    resolve_manifest,
    validate_manifest,
    verify_manifest,
)
from .common import (
    SCHEMA_VERSION,
    AppPaths,
    app_lock,
    atomic_json,
    cas_object_name_details,
    ensure_private_subdirectory,
    ensure_safe_cas_shard,
    fsync_dir,
    identity_matches,
    iso_utc,
    load_json,
    new_run_id,
    parse_timestamp,
    regular_file_stat,
    safe_cas_object_path,
    sha256_file,
    utc_now,
    validate_private_subdirectory,
    _prune_expired_plans_locked,
)
from .encryption import encryption_config


PORTABLE_FORMAT_VERSION = 1
INDEX_NAME = "index.json"
_MAX_INDEX_BYTES = 64 * 1024 * 1024
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_RUN_ID = re.compile(r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9a-f]{32}")
_INDEX_KEYS = {
    "format_version",
    "kind",
    "bundle_id",
    "created_at",
    "manifests",
    "objects",
}
_FILE_ENTRY_KEYS = {"path", "size", "sha256"}
_OBJECT_ENTRY_KEYS = _FILE_ENTRY_KEYS | {"kind"}
_PLAN_KEYS = {
    "schema_version",
    "kind",
    "run_id",
    "created_at",
    "expires_at",
    "artifact",
    "bundle_id",
    "index_sha256",
    "manifests",
    "objects",
}
_ARTIFACT_KEYS = {
    "path",
    "device",
    "inode",
    "size",
    "mtime_ns",
    "mode",
    "sha256",
}
_INTENT_KEYS = {
    "format_version",
    "kind",
    "run_id",
    "phase",
    "plan_sha256",
    "artifact_sha256",
    "bundle_id",
    "index_sha256",
    "manifests",
    "objects",
}
_INTENT_PHASES = {"publishing", "committed", "cleanup"}
_VISIBILITY_KEYS = {"schema_version", "kind", "generation"}


class _PortablePublicationError(RuntimeError):
    def __init__(self, message: str, *, preserve_temporary: bool) -> None:
        super().__init__(message)
        self.preserve_temporary = preserve_temporary


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _payload_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _sha256_stream(source: BinaryIO) -> str:
    digest = hashlib.sha256()
    while block := source.read(4 * 1024 * 1024):
        digest.update(block)
    return digest.hexdigest()


def _retained_fd_digest(
    fd: int, *, expected_size: int, expected_sha256: str, label: str
) -> str:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"{label} retained file is not regular")
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    size = 0
    while block := os.read(fd, 4 * 1024 * 1024):
        digest.update(block)
        size += len(block)
    after = os.fstat(fd)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        or size != expected_size
        or after.st_size != expected_size
        or digest.hexdigest() != expected_sha256
    ):
        raise RuntimeError(f"{label} retained content changed")
    return digest.hexdigest()


def _matches_retained_fd(fd: int, path: Path) -> bool:
    try:
        retained = os.fstat(fd)
        reachable = path.stat(follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISREG(retained.st_mode)
        and stat.S_ISREG(reachable.st_mode)
        and (retained.st_dev, retained.st_ino)
        == (reachable.st_dev, reachable.st_ino)
    )


def _link_portable_temp(source: Path, target: Path) -> None:
    os.link(source, target, follow_symlinks=False)


def _publish_retained_temp(
    fd: int,
    temporary: Path,
    target: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    label: str,
) -> bool:
    """Link one retained file without replacing or unlinking foreign paths."""

    preserve_paths = False
    if not _matches_retained_fd(fd, temporary):
        raise _PortablePublicationError(
            f"{label} temporary identity changed", preserve_temporary=True
        )
    try:
        _link_portable_temp(temporary, target)
    except FileExistsError:
        return False
    if not _matches_retained_fd(fd, target):
        preserve_paths = True
        raise _PortablePublicationError(
            f"{label} published identity changed", preserve_temporary=False
        )
    if not _matches_retained_fd(fd, temporary):
        preserve_paths = True
        raise _PortablePublicationError(
            f"{label} temporary identity changed", preserve_temporary=True
        )
    try:
        _retained_fd_digest(
            fd,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            label=label,
        )
    except Exception as exc:
        preserve_paths = True
        raise _PortablePublicationError(
            str(exc), preserve_temporary=True
        ) from exc
    fsync_dir(target.parent)
    if _matches_retained_fd(fd, temporary):
        temporary.unlink()
    else:
        preserve_paths = True
    if preserve_paths:
        raise _PortablePublicationError(
            f"{label} temporary identity changed", preserve_temporary=True
        )
    fsync_dir(target.parent)
    return True


def _safe_zip_name(value: Any) -> str:
    if not isinstance(value, str) or not value or "\0" in value or "\\" in value:
        raise ValueError("portable artifact path is invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or str(path) != value
    ):
        raise ValueError(f"portable artifact path is invalid: {value}")
    return value


def _zip_path_key(value: str) -> tuple[str, ...]:
    return tuple(
        unicodedata.normalize("NFC", part).casefold()
        for part in PurePosixPath(value).parts
    )


def _manifest_artifact_path(manifest: dict[str, Any]) -> str:
    provider = manifest["provider"]
    archive_id = manifest["archive_id"]
    if any(value in {"", ".", ".."} or "/" in value or "\\" in value for value in (provider, archive_id)):
        raise ValueError("portable manifest identity is invalid")
    return f"manifests/{provider}/{archive_id}.json"


def _object_kind(relative: str) -> str:
    name = PurePosixPath(_safe_zip_name(relative)).name
    details = cas_object_name_details(name)
    if details is None or details[0] not in {"zstd", "dictionary"}:
        raise ValueError(f"portable object path is invalid: {relative}")
    kind, shard, _ = details
    parts = PurePosixPath(relative).parts
    if len(parts) != 4 or parts[:2] != ("objects", "sha256") or parts[2] != shard:
        raise ValueError(f"portable object path is invalid: {relative}")
    return kind


def _manifest_objects(manifest: dict[str, Any]) -> dict[str, str]:
    objects: dict[str, str] = {}
    for member in manifest["files"]:
        chunks = member.get("chunks")
        if chunks is not None:
            for chunk in chunks:
                objects[_chunk_object_relative(chunk["sha256"])] = "zstd"
        else:
            relative = member["object"]
            if _object_kind(relative) != "zstd":
                raise ValueError(f"portable manifest object kind is invalid: {relative}")
            objects[relative] = "zstd"
        dictionary = member.get("dictionary")
        if dictionary is not None:
            if _object_kind(dictionary) != "dictionary":
                raise ValueError(
                    f"portable manifest dictionary kind is invalid: {dictionary}"
                )
            objects[dictionary] = "dictionary"
    return objects


def _validate_file_entry(value: Any, *, object_entry: bool) -> dict[str, Any]:
    expected = _OBJECT_ENTRY_KEYS if object_entry else _FILE_ENTRY_KEYS
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("portable index entry shape is invalid")
    path = _safe_zip_name(value.get("path"))
    if type(value.get("size")) is not int or value["size"] < 0:
        raise ValueError("portable index entry size is invalid")
    if not isinstance(value.get("sha256"), str) or not _HEX_SHA256.fullmatch(
        value["sha256"]
    ):
        raise ValueError("portable index entry digest is invalid")
    if object_entry:
        kind = value.get("kind")
        if kind not in {"zstd", "dictionary"} or _object_kind(path) != kind:
            raise ValueError("portable index object kind is invalid")
    else:
        parts = PurePosixPath(path).parts
        if (
            len(parts) != 3
            or parts[0] != "manifests"
            or not parts[2].endswith(".json")
        ):
            raise ValueError("portable index manifest path is invalid")
    return dict(value)


def _validate_index(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _INDEX_KEYS:
        raise ValueError("portable index shape is invalid")
    if (
        type(value.get("format_version")) is not int
        or value["format_version"] != PORTABLE_FORMAT_VERSION
        or value.get("kind") != "sesh-compresh-portable"
        or not isinstance(value.get("bundle_id"), str)
        or not _HEX_SHA256.fullmatch(value["bundle_id"])
        or not isinstance(value.get("created_at"), str)
        or not isinstance(value.get("manifests"), list)
        or not value["manifests"]
        or not isinstance(value.get("objects"), list)
    ):
        raise ValueError("portable index metadata is invalid")
    if value["created_at"] != iso_utc(parse_timestamp(value["created_at"])):
        raise ValueError("portable index timestamp is not canonical")
    manifests = [
        _validate_file_entry(item, object_entry=False)
        for item in value["manifests"]
    ]
    objects = [
        _validate_file_entry(item, object_entry=True) for item in value["objects"]
    ]
    for entries, label in ((manifests, "manifest"), (objects, "object")):
        paths = [item["path"] for item in entries]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError(f"portable index {label} paths are not sorted and unique")
    all_paths = [item["path"] for item in manifests + objects]
    keys = [_zip_path_key(path) for path in all_paths]
    if len(keys) != len(set(keys)):
        raise ValueError("portable index paths collide after normalization")
    graph = {"manifests": manifests, "objects": objects}
    if value["bundle_id"] != _payload_digest(graph):
        raise ValueError("portable index bundle identity is invalid")
    return {**value, **graph}


def _valid_zip_extra(extra: bytes) -> bool:
    """Accept only well-formed ZIP64 metadata."""

    offset = 0
    seen = False
    while offset < len(extra):
        if offset + 4 > len(extra):
            return False
        identifier = int.from_bytes(extra[offset : offset + 2], "little")
        size = int.from_bytes(extra[offset + 2 : offset + 4], "little")
        offset += 4
        if offset + size > len(extra) or identifier != 0x0001 or seen:
            return False
        seen = True
        offset += size
    return offset == len(extra)


def _zip_members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    if archive.comment:
        raise ValueError("portable ZIP comment is not allowed")
    members: dict[str, zipfile.ZipInfo] = {}
    normalized: set[tuple[str, ...]] = set()
    for info in archive.infolist():
        name = _safe_zip_name(info.filename)
        key = _zip_path_key(name)
        mode = info.external_attr >> 16
        if (
            name in members
            or key in normalized
            or info.is_dir()
            or info.compress_type != zipfile.ZIP_STORED
            or info.flag_bits & 0x1
            or info.comment
            or not _valid_zip_extra(info.extra)
            or info.create_system != 3
            or not stat.S_ISREG(mode)
            or stat.S_IMODE(mode) != 0o600
            or info.compress_size != info.file_size
        ):
            raise ValueError(f"portable ZIP member is invalid: {name}")
        members[name] = info
        normalized.add(key)
    return members


def _read_index(
    archive: zipfile.ZipFile, members: dict[str, zipfile.ZipInfo]
) -> tuple[dict[str, Any], str]:
    info = members.get(INDEX_NAME)
    if info is None or info.file_size > _MAX_INDEX_BYTES:
        raise ValueError("portable index is missing or too large")
    try:
        with archive.open(info) as source:
            raw = source.read(_MAX_INDEX_BYTES + 1)
        if len(raw) != info.file_size:
            raise ValueError("portable index size is invalid")
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        raise ValueError(f"portable index is invalid: {exc}") from exc
    index = _validate_index(value)
    if raw != _canonical_json_bytes(index) + b"\n":
        raise ValueError("portable index encoding is not canonical")
    return index, hashlib.sha256(raw).hexdigest()


def _inspect_open_zip(archive: zipfile.ZipFile) -> tuple[dict[str, Any], str]:
    members = _zip_members(archive)
    index, index_sha256 = _read_index(archive, members)
    expected = [
        INDEX_NAME,
        *(item["path"] for item in index["objects"]),
        *(item["path"] for item in index["manifests"]),
    ]
    if list(members) != expected:
        raise ValueError(
            "portable ZIP entries or their order do not match its index"
        )
    for item in index["manifests"] + index["objects"]:
        info = members[item["path"]]
        if info.file_size != item["size"]:
            raise ValueError(
                f"portable ZIP member size is invalid: {item['path']}"
            )
        try:
            with archive.open(info) as source:
                digest = _sha256_stream(source)
        except zipfile.BadZipFile as exc:
            raise ValueError(
                f"portable ZIP member is corrupt: {item['path']}"
            ) from exc
        if digest != item["sha256"]:
            raise ValueError(
                f"portable ZIP member digest is invalid: {item['path']}"
            )
    return index, index_sha256


def _inspect_zip(artifact: Path) -> tuple[dict[str, Any], str]:
    try:
        with zipfile.ZipFile(artifact, "r") as archive:
            return _inspect_open_zip(archive)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"portable artifact is not a valid ZIP: {artifact}: {exc}") from exc


def _inspect_zip_fd(fd: int) -> tuple[dict[str, Any], str]:
    try:
        with os.fdopen(os.dup(fd), "rb") as handle, zipfile.ZipFile(
            handle, "r"
        ) as archive:
            return _inspect_open_zip(archive)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("portable retained artifact is not a valid ZIP") from exc


def _stage_entry(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    target: Path,
    expected: dict[str, Any],
) -> None:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        digest = hashlib.sha256()
        size = 0
        with archive.open(info) as source, os.fdopen(fd, "wb") as destination:
            fd = -1
            while block := source.read(4 * 1024 * 1024):
                destination.write(block)
                digest.update(block)
                size += len(block)
            destination.flush()
            os.fsync(destination.fileno())
    except zipfile.BadZipFile as exc:
        raise ValueError(f"portable ZIP member is corrupt: {info.filename}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if size != expected["size"] or digest.hexdigest() != expected["sha256"]:
        raise ValueError(f"portable staged member mismatch: {info.filename}")
    fsync_dir(target.parent)


def _validate_staged_archive(
    source_paths: AppPaths, index: dict[str, Any]
) -> dict[str, set[str]]:
    expected_objects = {
        item["path"]: item["kind"] for item in index["objects"]
    }
    reachable: dict[str, str] = {}
    affected: dict[str, set[str]] = {}
    for item in index["manifests"]:
        manifest_path = source_paths.archive / item["path"]
        manifest = validate_manifest(manifest_path)
        if _manifest_artifact_path(manifest) != item["path"]:
            raise ValueError(
                f"portable manifest path does not match its identity: {item['path']}"
            )
        verify_manifest(source_paths, manifest_path)
        for relative, kind in _manifest_objects(manifest).items():
            prior = reachable.setdefault(relative, kind)
            if prior != kind:
                raise ValueError(f"portable object has conflicting kinds: {relative}")
        affected.setdefault(manifest["provider"], set()).add(
            _manifest_session_key(manifest)
        )
    if reachable != expected_objects:
        raise ValueError("portable artifact object graph is not exact")
    for item in index["objects"]:
        if item["kind"] != "dictionary":
            continue
        path = safe_cas_object_path(
            source_paths.archive, item["path"], kind="dictionary"
        )
        expected_digest = PurePosixPath(item["path"]).name.removesuffix(".dict")
        if sha256_file(path) != expected_digest:
            raise ValueError(f"portable dictionary digest is invalid: {item['path']}")
    return affected


def _stage_artifact(
    paths: AppPaths, artifact: Path, stage_root: Path
) -> tuple[dict[str, Any], str, dict[str, set[str]]]:
    index, index_sha256 = _inspect_zip(artifact)
    archive_root = stage_root / "archive"
    state_root = stage_root / "state"
    source_paths = AppPaths(home=paths.home, archive=archive_root, state=state_root)
    source_paths.ensure_private()
    with zipfile.ZipFile(artifact, "r") as archive:
        members = _zip_members(archive)
        for item in index["objects"] + index["manifests"]:
            target = archive_root / PurePosixPath(item["path"])
            _stage_entry(archive, members[item["path"]], target, item)
    affected = _validate_staged_archive(source_paths, index)
    return index, index_sha256, affected


def _zip_info(name: str, size: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    info.file_size = size
    return info


def _write_zip_file(
    archive: zipfile.ZipFile, name: str, source: Path, size: int
) -> None:
    with source.open("rb") as input_file, archive.open(
        _zip_info(name, size), "w", force_zip64=True
    ) as output_file:
        shutil.copyfileobj(input_file, output_file, 4 * 1024 * 1024)


def export_portable_archive(
    paths: AppPaths,
    manifest_references: Iterable[str],
    destination: Path,
) -> dict[str, Any]:
    """Create one verified, no-overwrite portable artifact."""

    references = list(manifest_references)
    if not references or any(not isinstance(value, str) or not value for value in references):
        raise ValueError("portable export needs at least one manifest reference")
    destination = destination.expanduser()
    parent = destination.parent.resolve(strict=True)
    destination = parent / destination.name
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"portable export destination exists: {destination}")
    with app_lock(paths):
        if encryption_config(paths) is not None:
            raise RuntimeError(
                "portable export is unavailable while archive encryption is enabled"
            )
        manifests: dict[str, Path] = {}
        objects: dict[str, tuple[str, Path]] = {}
        for reference in references:
            manifest_path = resolve_manifest(paths, reference)
            if manifest_path.is_symlink():
                raise ValueError(f"portable export manifest is a symlink: {manifest_path}")
            manifest_path = manifest_path.resolve(strict=True)
            manifest = verify_manifest(paths, manifest_path)
            relative = _manifest_artifact_path(manifest)
            expected = paths.archive / PurePosixPath(relative)
            if manifest_path != expected:
                raise ValueError(
                    f"portable export manifest is outside the archive: {manifest_path}"
                )
            manifests[relative] = manifest_path
            for object_relative, kind in _manifest_objects(manifest).items():
                object_path = safe_cas_object_path(
                    paths.archive, object_relative, kind=kind  # type: ignore[arg-type]
                )
                if kind == "dictionary" and sha256_file(object_path) != PurePosixPath(
                    object_relative
                ).name.removesuffix(".dict"):
                    raise RuntimeError(
                        f"portable export dictionary digest is invalid: {object_path}"
                    )
                prior = objects.setdefault(object_relative, (kind, object_path))
                if prior != (kind, object_path):
                    raise ValueError(
                        f"portable export object has conflicting identity: {object_relative}"
                    )
        manifest_entries = [
            {
                "path": relative,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for relative, path in sorted(manifests.items())
        ]
        object_entries = [
            {
                "path": relative,
                "kind": kind,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for relative, (kind, path) in sorted(objects.items())
        ]
        graph = {"manifests": manifest_entries, "objects": object_entries}
        index = {
            "format_version": PORTABLE_FORMAT_VERSION,
            "kind": "sesh-compresh-portable",
            "bundle_id": _payload_digest(graph),
            "created_at": iso_utc(utc_now()),
            **graph,
        }
        index_raw = _canonical_json_bytes(index) + b"\n"

        fd, raw_tmp = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=parent
        )
        tmp = Path(raw_tmp)
        preserve_temporary = False
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(os.dup(fd), "w+b") as handle, zipfile.ZipFile(
                handle, "w", compression=zipfile.ZIP_STORED, allowZip64=True
            ) as archive:
                archive.writestr(_zip_info(INDEX_NAME, len(index_raw)), index_raw)
                for item in object_entries:
                    _write_zip_file(
                        archive,
                        item["path"],
                        objects[item["path"]][1],
                        item["size"],
                    )
                for item in manifest_entries:
                    _write_zip_file(
                        archive,
                        item["path"],
                        manifests[item["path"]],
                        item["size"],
                    )
            os.fsync(fd)
            artifact_size = os.fstat(fd).st_size
            os.lseek(fd, 0, os.SEEK_SET)
            with os.fdopen(os.dup(fd), "rb") as retained_artifact:
                artifact_sha256 = _sha256_stream(retained_artifact)
            checked, _ = _inspect_zip_fd(fd)
            if checked != _validate_index(index):
                raise RuntimeError("portable export validation changed its index")
            try:
                created = _publish_retained_temp(
                    fd,
                    tmp,
                    destination,
                    expected_size=artifact_size,
                    expected_sha256=artifact_sha256,
                    label="portable export",
                )
            except FileExistsError:
                raise FileExistsError(
                    f"portable export destination exists: {destination}"
                ) from None
            if not created:
                raise FileExistsError(
                    f"portable export destination exists: {destination}"
                )
            checked_after, _ = _inspect_zip_fd(fd)
            if checked_after != checked:
                raise RuntimeError("portable export retained ZIP changed")
            _retained_fd_digest(
                fd,
                expected_size=artifact_size,
                expected_sha256=artifact_sha256,
                label="portable export",
            )
            return {
                "artifact": str(destination),
                "bundle_id": index["bundle_id"],
                "manifests": len(manifest_entries),
                "objects": len(object_entries),
                "bytes": artifact_size,
                "sha256": artifact_sha256,
            }
        except _PortablePublicationError as exc:
            preserve_temporary = exc.preserve_temporary
            raise
        finally:
            if not preserve_temporary and _matches_retained_fd(fd, tmp):
                tmp.unlink()
            os.close(fd)


def _artifact_record(artifact: Path) -> dict[str, Any]:
    expanded = artifact.expanduser()
    if expanded.is_symlink():
        raise ValueError(f"portable artifact is a symlink: {expanded}")
    canonical = expanded.resolve(strict=True)
    info = regular_file_stat(canonical)
    return {"path": str(canonical), **info, "sha256": sha256_file(canonical)}


def _validate_artifact_record(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != _ARTIFACT_KEYS
        or not isinstance(value.get("path"), str)
        or not Path(value["path"]).is_absolute()
        or not isinstance(value.get("sha256"), str)
        or not _HEX_SHA256.fullmatch(value["sha256"])
        or any(
            type(value.get(key)) is not int or value[key] < 0
            for key in ("device", "inode", "size", "mtime_ns", "mode")
        )
    ):
        raise ValueError("portable import artifact identity is invalid")
    return dict(value)


def _plan_digest(plan: dict[str, Any]) -> str:
    return _payload_digest(plan)


def create_portable_import_plan(
    paths: AppPaths, artifact: Path
) -> tuple[Path, dict[str, Any]]:
    """Validate an artifact and bind one short-lived import plan to its bytes."""

    with app_lock(paths):
        if encryption_config(paths) is not None:
            raise RuntimeError(
                "portable import is unavailable while archive encryption is enabled"
            )
        artifact_record = _artifact_record(artifact)
        artifact_path = Path(artifact_record["path"])
        imports_root = ensure_private_subdirectory(paths.state, "portable-imports")
        with tempfile.TemporaryDirectory(prefix=".inspect.", dir=imports_root) as raw:
            index, index_sha256, _ = _stage_artifact(paths, artifact_path, Path(raw))
        current = utc_now()
        run_id = new_run_id(current)
        plan = {
            "schema_version": SCHEMA_VERSION,
            "kind": "portable-import-plan",
            "run_id": run_id,
            "created_at": iso_utc(current),
            "expires_at": iso_utc(current + timedelta(hours=2)),
            "artifact": artifact_record,
            "bundle_id": index["bundle_id"],
            "index_sha256": index_sha256,
            "manifests": len(index["manifests"]),
            "objects": len(index["objects"]),
        }
        plan_path = (
            paths.state
            / "plans"
            / f"portable-import-{run_id}-{_plan_digest(plan)}.json"
        )
        _prune_expired_plans_locked(paths, keep=32)
        atomic_json(plan_path, plan, replace=False)
        return plan_path, plan


def _validate_import_plan(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    if plan_path.parent != paths.state / "plans":
        raise ValueError("portable import plan escaped the plans root")
    regular_file_stat(plan_path)
    plan = load_json(plan_path)
    if (
        set(plan) != _PLAN_KEYS
        or type(plan.get("schema_version")) is not int
        or plan["schema_version"] != SCHEMA_VERSION
        or plan.get("kind") != "portable-import-plan"
        or not isinstance(plan.get("run_id"), str)
        or not _RUN_ID.fullmatch(plan["run_id"])
        or not isinstance(plan.get("created_at"), str)
        or not isinstance(plan.get("expires_at"), str)
        or not isinstance(plan.get("bundle_id"), str)
        or not _HEX_SHA256.fullmatch(plan["bundle_id"])
        or not isinstance(plan.get("index_sha256"), str)
        or not _HEX_SHA256.fullmatch(plan["index_sha256"])
        or any(type(plan.get(key)) is not int or plan[key] < 0 for key in ("manifests", "objects"))
    ):
        raise ValueError("portable import plan is invalid")
    _validate_artifact_record(plan.get("artifact"))
    created_at = parse_timestamp(plan["created_at"])
    expires_at = parse_timestamp(plan["expires_at"])
    if created_at > expires_at:
        raise ValueError("portable import plan timestamps are reversed")
    if plan_path.name != (
        f"portable-import-{plan['run_id']}-{_plan_digest(plan)}.json"
    ):
        raise ValueError("portable import plan identity is invalid")
    return plan


def _validate_intent(run_root: Path) -> dict[str, Any]:
    intent_path = run_root / "intent.json"
    regular_file_stat(intent_path)
    intent = load_json(intent_path)
    if (
        set(intent) != _INTENT_KEYS
        or type(intent.get("format_version")) is not int
        or intent["format_version"] != PORTABLE_FORMAT_VERSION
        or intent.get("kind") != "portable-import-intent"
        or not isinstance(intent.get("run_id"), str)
        or not _RUN_ID.fullmatch(intent["run_id"])
        or intent["run_id"] != run_root.name
        or intent.get("phase") not in _INTENT_PHASES
        or not isinstance(intent.get("plan_sha256"), str)
        or not _HEX_SHA256.fullmatch(intent["plan_sha256"])
        or not isinstance(intent.get("artifact_sha256"), str)
        or not _HEX_SHA256.fullmatch(intent["artifact_sha256"])
        or not isinstance(intent.get("bundle_id"), str)
        or not _HEX_SHA256.fullmatch(intent["bundle_id"])
        or not isinstance(intent.get("index_sha256"), str)
        or not _HEX_SHA256.fullmatch(intent["index_sha256"])
        or not isinstance(intent.get("manifests"), list)
        or not isinstance(intent.get("objects"), list)
    ):
        raise ValueError(f"portable import intent is invalid: {intent_path}")
    graph_index = _validate_index(
        {
            "format_version": PORTABLE_FORMAT_VERSION,
            "kind": "sesh-compresh-portable",
            "bundle_id": intent["bundle_id"],
            "created_at": "1970-01-01T00:00:00Z",
            "manifests": intent["manifests"],
            "objects": intent["objects"],
        }
    )
    return {**intent, "manifests": graph_index["manifests"], "objects": graph_index["objects"]}


def _require_intent_matches_plan(
    run_root: Path, plan: dict[str, Any]
) -> dict[str, Any]:
    intent = _validate_intent(run_root)
    expected = {
        "run_id": plan["run_id"],
        "plan_sha256": _plan_digest(plan),
        "artifact_sha256": plan["artifact"]["sha256"],
        "bundle_id": plan["bundle_id"],
        "index_sha256": plan["index_sha256"],
    }
    if any(intent[key] != value for key, value in expected.items()) or (
        len(intent["manifests"]), len(intent["objects"])
    ) != (plan["manifests"], plan["objects"]):
        raise RuntimeError(
            f"portable import staging belongs to a different plan: {run_root}"
        )
    return intent


def _visibility_path(paths: AppPaths) -> Path:
    return paths.state / "portable-visibility.json"


def _visibility_generation(paths: AppPaths) -> int:
    path = _visibility_path(paths)
    if not path.exists() and not path.is_symlink():
        return 0
    regular_file_stat(path)
    payload = load_json(path)
    if (
        set(payload) != _VISIBILITY_KEYS
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != SCHEMA_VERSION
        or payload.get("kind") != "portable-manifest-visibility"
        or type(payload.get("generation")) is not int
        or payload["generation"] < 0
    ):
        raise ValueError(f"portable visibility state is invalid: {path}")
    return payload["generation"]


def _bump_visibility_generation(paths: AppPaths) -> int:
    generation = _visibility_generation(paths) + 1
    atomic_json(
        _visibility_path(paths),
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "portable-manifest-visibility",
            "generation": generation,
        },
    )
    return generation


def portable_manifest_visibility(paths: AppPaths) -> tuple[int, frozenset[str]]:
    """Return the visibility generation and uncommitted manifest paths."""

    generation = _visibility_generation(paths)
    imports_root = paths.state / "portable-imports"
    if not imports_root.exists() and not imports_root.is_symlink():
        return generation, frozenset()
    validate_private_subdirectory(paths.state, "portable-imports")
    hidden: set[str] = set()
    with os.scandir(imports_root) as entries:
        children = sorted(entries, key=lambda item: item.name)
    for entry in children:
        info = entry.stat(follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError(
                f"portable import staging entry is unsafe: {entry.path}"
            )
        run_root = Path(entry.path)
        intent_path = run_root / "intent.json"
        if not intent_path.exists() and not intent_path.is_symlink():
            continue
        intent = _validate_intent(run_root)
        if intent["phase"] == "publishing":
            hidden.update(item["path"] for item in intent["manifests"])
    return generation, frozenset(hidden)


def _replace_intent_phase(
    run_root: Path, intent: dict[str, Any], phase: str
) -> dict[str, Any]:
    if phase not in _INTENT_PHASES:
        raise ValueError(f"portable import phase is invalid: {phase}")
    updated = {**intent, "phase": phase}
    atomic_json(run_root / "intent.json", updated)
    return _validate_intent(run_root)


def _target_for_entry(paths: AppPaths, item: dict[str, Any], *, object_entry: bool) -> Path:
    relative = PurePosixPath(item["path"])
    if object_entry:
        ensure_safe_cas_shard(paths.archive, relative.parts[2])
    else:
        ensure_private_subdirectory(paths.archive, "manifests", relative.parts[1])
    return paths.archive / relative


def _existing_entry_matches(
    paths: AppPaths, target: Path, item: dict[str, Any], *, object_entry: bool
) -> bool:
    if not target.exists() and not target.is_symlink():
        return False
    try:
        if object_entry:
            safe_cas_object_path(paths.archive, item["path"], kind=item["kind"])
        else:
            regular_file_stat(target)
            validate_manifest(target)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"portable import target conflicts: {target}") from exc
    if target.stat(follow_symlinks=False).st_size != item["size"] or sha256_file(
        target
    ) != item["sha256"]:
        raise RuntimeError(f"portable import target conflicts: {target}")
    return True


def _publish_file(
    source: Path,
    target: Path,
    expected_size: int,
    expected_sha256: str,
    *,
    cas_object: bool,
) -> bool:
    """Publish one fsynced regular file without replacing a target."""

    prefix_name = target.name.split(".", 1)[0] if cas_object else target.name
    fd, raw_tmp = tempfile.mkstemp(
        prefix=f".{prefix_name}.", suffix=".part", dir=target.parent
    )
    tmp = Path(raw_tmp)
    preserve_temporary = False
    try:
        os.fchmod(fd, 0o600)
        with source.open("rb") as input_file, os.fdopen(
            os.dup(fd), "wb"
        ) as output_file:
            shutil.copyfileobj(input_file, output_file, 4 * 1024 * 1024)
            output_file.flush()
            os.fsync(output_file.fileno())
        _retained_fd_digest(
            fd,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            label="portable import",
        )
        return _publish_retained_temp(
            fd,
            tmp,
            target,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            label="portable import",
        )
    except _PortablePublicationError as exc:
        preserve_temporary = exc.preserve_temporary
        raise
    finally:
        if not preserve_temporary and _matches_retained_fd(fd, tmp):
            tmp.unlink()
        os.close(fd)


def _publish_staged_import(paths: AppPaths, run_root: Path) -> dict[str, Any]:
    intent = _validate_intent(run_root)
    if intent["phase"] == "cleanup":
        result = {
            "bundle_id": intent["bundle_id"],
            "manifests": len(intent["manifests"]),
            "objects": len(intent["objects"]),
            "published": 0,
            "reused": len(intent["manifests"]) + len(intent["objects"]),
        }
        _cleanup_import_stage(run_root)
        return result
    stage_paths = AppPaths(
        home=paths.home,
        archive=run_root / "archive",
        state=run_root / "state",
    )
    affected = _validate_staged_archive(
        stage_paths,
        {
            "manifests": intent["manifests"],
            "objects": intent["objects"],
        },
    )
    # Validate the existing manifest namespace before any imported root appears.
    for manifest_path in list(iter_manifests(paths)):
        validate_manifest(manifest_path)

    targets: list[tuple[dict[str, Any], Path, bool, bool]] = []
    for object_entry, entries in (
        (True, intent["objects"]),
        (False, intent["manifests"]),
    ):
        for item in entries:
            target = _target_for_entry(paths, item, object_entry=object_entry)
            exists = _existing_entry_matches(
                paths, target, item, object_entry=object_entry
            )
            targets.append((item, target, object_entry, exists))

    if intent["phase"] == "publishing":
        # Readers use this generation to retry a scan that overlaps the first
        # publication from this intent.
        _bump_visibility_generation(paths)

    published = reused = 0
    for item, target, object_entry, exists in targets:
        if exists:
            fsync_dir(target.parent)
            reused += 1
            continue
        source = stage_paths.archive / PurePosixPath(item["path"])
        created = _publish_file(
            source,
            target,
            item["size"],
            item["sha256"],
            cas_object=object_entry,
        )
        if created:
            published += 1
        else:
            _existing_entry_matches(
                paths, target, item, object_entry=object_entry
            )
            fsync_dir(target.parent)
            reused += 1

    if intent["phase"] == "publishing":
        intent = _replace_intent_phase(run_root, intent, "committed")
        _bump_visibility_generation(paths)

    for provider, session_keys in affected.items():
        _refresh_latest_indexes(paths, provider, session_keys)

    intent = _replace_intent_phase(run_root, intent, "cleanup")
    result = {
        "bundle_id": intent["bundle_id"],
        "manifests": len(intent["manifests"]),
        "objects": len(intent["objects"]),
        "published": published,
        "reused": reused,
    }
    _cleanup_import_stage(run_root)
    return result


def _cleanup_import_stage(run_root: Path) -> None:
    """Remove staged trees while keeping the durable intent until last."""

    intent = _validate_intent(run_root)
    if intent["phase"] != "cleanup":
        raise RuntimeError("portable import cleanup started before commit")
    allowed = {"archive", "state", "intent.json"}
    with os.scandir(run_root) as entries:
        names = {entry.name for entry in entries}
    unexpected = names - allowed
    if unexpected:
        raise RuntimeError(
            f"portable import cleanup found unexpected entries: {sorted(unexpected)}"
        )
    for name in ("archive", "state"):
        target = run_root / name
        if not target.exists() and not target.is_symlink():
            continue
        validate_private_subdirectory(run_root, name)
        shutil.rmtree(target)
        fsync_dir(run_root)
    with os.scandir(run_root) as entries:
        remaining = {entry.name for entry in entries}
    if remaining != {"intent.json"}:
        raise RuntimeError(
            f"portable import cleanup remains incomplete: {sorted(remaining)}"
        )
    intent_path = run_root / "intent.json"
    regular_file_stat(intent_path)
    intent_path.unlink()
    fsync_dir(run_root)
    imports_root = run_root.parent
    run_root.rmdir()
    fsync_dir(imports_root)


def _prepare_import_stage(
    paths: AppPaths, plan: dict[str, Any], run_root: Path
) -> None:
    artifact_record = _validate_artifact_record(plan["artifact"])
    artifact = Path(artifact_record["path"])
    if not identity_matches(artifact, artifact_record) or sha256_file(artifact) != artifact_record["sha256"]:
        raise RuntimeError("portable import artifact identity changed after planning")
    index, index_sha256, _ = _stage_artifact(paths, artifact, run_root)
    if (
        index["bundle_id"] != plan["bundle_id"]
        or index_sha256 != plan["index_sha256"]
        or len(index["manifests"]) != plan["manifests"]
        or len(index["objects"]) != plan["objects"]
    ):
        raise RuntimeError("portable import artifact graph changed after planning")
    atomic_json(
        run_root / "intent.json",
        {
            "format_version": PORTABLE_FORMAT_VERSION,
            "kind": "portable-import-intent",
            "run_id": plan["run_id"],
            "phase": "publishing",
            "plan_sha256": _plan_digest(plan),
            "artifact_sha256": artifact_record["sha256"],
            "bundle_id": index["bundle_id"],
            "index_sha256": index_sha256,
            "manifests": index["manifests"],
            "objects": index["objects"],
        },
        replace=False,
    )


def apply_portable_import_plan(
    paths: AppPaths, plan_path: Path
) -> dict[str, Any]:
    """Apply one validated import plan with recoverable staged publication."""

    with app_lock(paths):
        if encryption_config(paths) is not None:
            raise RuntimeError(
                "portable import is unavailable while archive encryption is enabled"
            )
        plan = _validate_import_plan(paths, plan_path)
        if utc_now() > parse_timestamp(plan["expires_at"]):
            raise RuntimeError("portable import plan expired")
        imports_root = ensure_private_subdirectory(paths.state, "portable-imports")
        run_root = imports_root / plan["run_id"]
        if run_root.exists() or run_root.is_symlink():
            validate_private_subdirectory(imports_root, plan["run_id"])
            intent_path = run_root / "intent.json"
            if intent_path.exists() or intent_path.is_symlink():
                _require_intent_matches_plan(run_root, plan)
            else:
                shutil.rmtree(run_root)
                fsync_dir(imports_root)
        if not run_root.exists():
            run_root = ensure_private_subdirectory(imports_root, plan["run_id"])
            try:
                _prepare_import_stage(paths, plan, run_root)
            except BaseException:
                if not (run_root / "intent.json").exists():
                    shutil.rmtree(run_root)
                    fsync_dir(imports_root)
                raise
        _require_intent_matches_plan(run_root, plan)
        return _publish_staged_import(paths, run_root)


def recover_portable_imports(paths: AppPaths) -> dict[str, Any]:
    """Finish every validated portable import intent."""

    with app_lock(paths):
        if encryption_config(paths) is not None:
            raise RuntimeError(
                "portable import is unavailable while archive encryption is enabled"
            )
        imports_root = ensure_private_subdirectory(paths.state, "portable-imports")
        completed = []
        incomplete = []
        cleaned = 0
        with os.scandir(imports_root) as entries:
            children = sorted(entries, key=lambda item: item.name)
        for entry in children:
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise ValueError(f"portable import staging entry is unsafe: {entry.path}")
            run_root = Path(entry.path)
            validate_private_subdirectory(imports_root, entry.name)
            intent_path = run_root / "intent.json"
            if not intent_path.exists() and not intent_path.is_symlink():
                with os.scandir(run_root) as staged_entries:
                    empty = next(staged_entries, None) is None
                if empty:
                    run_root.rmdir()
                    fsync_dir(imports_root)
                    cleaned += 1
                    continue
                incomplete.append(str(run_root))
                continue
            completed.append(_publish_staged_import(paths, run_root))
        return {
            "completed": len(completed),
            "imports": completed,
            "incomplete": incomplete,
            "cleaned": cleaned,
        }
