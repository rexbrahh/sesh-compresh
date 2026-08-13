"""Internal, read-only archive schema inventory."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Iterator

from .common import (
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    AppPaths,
    app_lock,
    atomic_json,
    fsync_dir,
    load_json,
    parse_timestamp,
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


def _real_directory(path: Path, label: str) -> bool:
    if not path.is_absolute() or path.resolve(strict=False) != path:
        raise ValueError(f"{label} is not canonical: {path}")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"{label} is not a real directory: {path}")
    return True


def _regular_json_files(root: Path, label: str) -> Iterator[Path]:
    if not _real_directory(root, label):
        return
    with os.scandir(root) as entries:
        children = sorted(entries, key=lambda entry: entry.name)
    for entry in children:
        info = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{label} contains an unsafe entry: {entry.path}")
        if not entry.name.endswith(".json"):
            raise ValueError(f"{label} contains an unknown entry: {entry.path}")
        yield Path(entry.path)


def _manifest_files(paths: AppPaths) -> Iterator[Path]:
    root = paths.archive / "manifests"
    if not _real_directory(root, "archive manifests root"):
        return
    with os.scandir(root) as entries:
        providers = sorted(entries, key=lambda entry: entry.name)
    for provider in providers:
        info = provider.stat(follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError(
                f"archive manifests root contains an unsafe entry: {provider.path}"
            )
        yield from _regular_json_files(Path(provider.path), "archive manifest provider")


def _schema_error(kind: str, path: Path, error: BaseException) -> dict[str, str]:
    return {
        "kind": kind,
        "path": str(path),
        "error": f"{error.__class__.__name__}: {error}",
    }


def _expected_latest_payloads(
    paths: AppPaths,
    manifests: list[tuple[Path, dict[str, Any]]],
) -> dict[Path, dict[str, Any]]:
    from .archive import _manifest_session_key, _manifest_version

    latest: dict[tuple[str, str], tuple[int, str, Path, dict[str, Any]]] = {}
    for manifest_path, manifest in manifests:
        provider = manifest["provider"]
        archive_id = manifest["archive_id"]
        expected_manifest = (
            paths.archive / "manifests" / provider / f"{archive_id}.json"
        )
        if manifest_path != expected_manifest:
            raise ValueError(
                f"archive manifest path does not match its archive id: {manifest_path}"
            )
        session_key = _manifest_session_key(manifest)
        version = _manifest_version(manifest)
        candidate = (version, archive_id, manifest_path, manifest)
        identity = (provider, session_key)
        current = latest.get(identity)
        if current is None or candidate[:2] > current[:2]:
            latest[identity] = candidate

    expected = {}
    for (provider, session_key), (
        version,
        archive_id,
        manifest_path,
        manifest,
    ) in latest.items():
        index_path = paths.state / "latest" / f"{provider}-{session_key}.json"
        expected[index_path] = {
            "schema_version": SCHEMA_VERSION,
            "kind": "archive-latest",
            "provider": provider,
            "session_key": session_key,
            "version": version,
            "archive_id": archive_id,
            "archived_at": manifest["archived_at"],
            "manifest": str(manifest_path.relative_to(paths.archive)),
        }
    return expected


def _validate_latest_index_shape(
    paths: AppPaths, path: Path, payload: dict[str, Any]
) -> None:
    if set(payload) != _LATEST_INDEX_KEYS or payload.get("kind") != "archive-latest":
        raise ValueError("latest-index shape is invalid")
    if type(payload.get("version")) is not int or payload["version"] < 0:
        raise ValueError("latest-index version is invalid")
    for key in ("provider", "session_key", "archive_id", "archived_at", "manifest"):
        if (
            type(payload.get(key)) is not str
            or not payload[key]
            or "\0" in payload[key]
        ):
            raise ValueError(f"latest-index {key} is invalid")
    provider = payload["provider"]
    session_key = payload["session_key"]
    if (
        provider in {".", ".."}
        or "/" in provider
        or "\\" in provider
        or re.fullmatch(r"[0-9a-f]{20}", session_key) is None
    ):
        raise ValueError("latest-index identity is invalid")
    expected_path = paths.state / "latest" / f"{provider}-{session_key}.json"
    expected_manifest = Path("manifests") / provider / f"{payload['archive_id']}.json"
    if path != expected_path or Path(payload["manifest"]) != expected_manifest:
        raise ValueError("latest-index path is invalid")
    parse_timestamp(payload["archived_at"])


def _inventory_archive_schemas(paths: AppPaths) -> dict[str, Any]:
    """Inspect schema compatibility and exact latest-index currentness."""

    # Lazy import keeps this module available to archive.py's later rebuild
    # integration without creating an import cycle.
    from .archive import validate_manifest

    invalid: list[dict[str, str]] = []
    unsupported: list[dict[str, Any]] = []
    schema_counts = {"manifest": {}, "latest-index": {}}
    totals = {"manifest": 0, "latest-index": 0}
    manifests: list[tuple[Path, dict[str, Any]]] = []

    for path in _manifest_files(paths):
        totals["manifest"] += 1
        try:
            payload = load_json(path)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            invalid.append(_schema_error("manifest", path, error))
            continue
        schema = payload.get("schema_version")
        if type(schema) is not int:
            invalid.append(
                _schema_error(
                    "manifest", path, ValueError("schema version is not an integer")
                )
            )
            continue
        key = str(schema)
        schema_counts["manifest"][key] = schema_counts["manifest"].get(key, 0) + 1
        if schema not in SUPPORTED_SCHEMA_VERSIONS:
            unsupported.append(
                {"kind": "manifest", "path": str(path), "schema_version": schema}
            )
            continue
        try:
            manifests.append((path, validate_manifest(path)))
        except (OSError, UnicodeError, ValueError, RuntimeError) as error:
            invalid.append(_schema_error("manifest", path, error))

    expected: dict[Path, dict[str, Any]] = {}
    if not any(item["kind"] == "manifest" for item in invalid + unsupported):
        try:
            expected = _expected_latest_payloads(paths, manifests)
        except (OSError, UnicodeError, ValueError, RuntimeError) as error:
            path = manifests[0][0] if manifests else paths.archive / "manifests"
            invalid.append(_schema_error("manifest", path, error))

    actual: set[Path] = set()
    stale: list[dict[str, str]] = []
    unexpected: list[str] = []
    for path in _regular_json_files(
        paths.state / "latest", "archive latest-index root"
    ):
        actual.add(path)
        totals["latest-index"] += 1
        try:
            payload = load_json(path)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            invalid.append(_schema_error("latest-index", path, error))
            continue
        schema = payload.get("schema_version")
        if type(schema) is not int:
            invalid.append(
                _schema_error(
                    "latest-index",
                    path,
                    ValueError("schema version is not an integer"),
                )
            )
            continue
        key = str(schema)
        schema_counts["latest-index"][key] = (
            schema_counts["latest-index"].get(key, 0) + 1
        )
        if schema not in SUPPORTED_SCHEMA_VERSIONS:
            unsupported.append(
                {
                    "kind": "latest-index",
                    "path": str(path),
                    "schema_version": schema,
                }
            )
            continue
        try:
            _validate_latest_index_shape(paths, path, payload)
        except (OSError, UnicodeError, ValueError, RuntimeError) as error:
            invalid.append(_schema_error("latest-index", path, error))
            continue
        wanted = expected.get(path)
        if wanted is None:
            unexpected.append(str(path))
        elif payload != wanted:
            stale.append(
                {
                    "path": str(path),
                    "expected_manifest": wanted["manifest"],
                    "actual_manifest": str(payload.get("manifest")),
                }
            )

    missing = sorted(str(path) for path in expected.keys() - actual)
    compatible = not invalid and not unsupported
    current = compatible and not missing and not stale and not unexpected

    return {
        "current_schema": SCHEMA_VERSION,
        "supported_schemas": list(SUPPORTED_SCHEMA_VERSIONS),
        "compatible": compatible,
        "latest_indexes_current": current,
        "manifests": totals["manifest"],
        "latest_indexes": totals["latest-index"],
        "expected_latest_indexes": len(expected),
        "manifest_schemas": schema_counts["manifest"],
        "latest_index_schemas": schema_counts["latest-index"],
        "missing_latest_indexes": missing,
        "stale_latest_indexes": stale,
        "unexpected_latest_indexes": sorted(unexpected),
        "invalid": invalid,
        "unsupported": unsupported,
    }


def check_archive_schema(paths: AppPaths) -> dict[str, Any]:
    """Return a read-only compatibility and latest-index report."""

    return _inventory_archive_schemas(paths)


def rebuild_latest_indexes(paths: AppPaths) -> dict[str, Any]:
    """Rebuild derived latest indexes without changing manifests or CAS objects."""

    with app_lock(paths):
        before = _inventory_archive_schemas(paths)
        if not before["compatible"]:
            raise ValueError("archive schema is incompatible; latest indexes unchanged")

        manifests = [(path, load_json(path)) for path in _manifest_files(paths)]
        expected = _expected_latest_payloads(paths, manifests)
        existing = set(
            _regular_json_files(paths.state / "latest", "archive latest-index root")
        )
        changed = 0
        removed = 0
        for path, payload in sorted(expected.items()):
            current = load_json(path) if path in existing else None
            if current != payload:
                atomic_json(path, payload)
                changed += 1
        for path in sorted(existing - expected.keys()):
            path.unlink()
            fsync_dir(path.parent)
            removed += 1

        after = _inventory_archive_schemas(paths)
        if not after["compatible"] or not after["latest_indexes_current"]:
            raise RuntimeError("archive latest-index rebuild did not validate")
        latest_root = paths.state / "latest"
        if latest_root.is_dir() and not latest_root.is_symlink():
            fsync_dir(latest_root)
        return {
            **after,
            "indexes_written": changed,
            "indexes_removed": removed,
            "manifests_rewritten": 0,
            "cas_objects_rewritten": 0,
        }
