from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .archive import (
    _cas_inventory,
    _manifest_zstd_objects,
    _publish_frame_payload,
    _validate_manifest_payload,
    _verify_validated_manifest,
    _verify_zstd,
    _zstd_binary,
    iter_manifests,
    validate_manifest,
)
from .common import (
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
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
    prune_expired_plans,
    regular_file_stat,
    safe_cas_object_path,
    sha256_file,
    utc_now,
    validate_run_id,
)
from .encryption import encryption_config
from .history import record_history_after_success


DEFAULT_REPACK_MINIMUM_COMPRESSED_BYTES = 8 * 1024**2
_PLAN_KEYS = {
    "schema_version",
    "kind",
    "run_id",
    "created_at",
    "expires_at",
    "archive",
    "minimum_compressed_bytes",
    "candidates",
    "manifests",
    "raw_bytes",
    "compressed_bytes",
    "items",
}
_ITEM_KEYS = {
    "manifest",
    "manifest_identity",
    "manifest_logical_sha256",
    "manifest_sha256",
    "member",
    "raw_sha256",
    "raw_bytes",
    "compressed_sha256",
    "compressed_bytes",
    "object",
    "object_identity",
    "archive_id",
    "provider",
}
_IDENTITY_KEYS = {"device", "inode", "size", "mtime_ns", "mode"}
_HEX = frozenset("0123456789abcdef")


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and not set(value) - _HEX


def _valid_identity(value: Any) -> bool:
    return (
        type(value) is dict
        and set(value) == _IDENTITY_KEYS
        and all(type(item) is int and item >= 0 for item in value.values())
    )


def _valid_plan_item(item: Any) -> bool:
    return (
        type(item) is dict
        and set(item) == _ITEM_KEYS
        and all(
            isinstance(item[key], str)
            for key in ("manifest", "member", "object", "archive_id", "provider")
        )
        and all(
            _valid_sha256(item[key])
            for key in (
                "manifest_logical_sha256",
                "manifest_sha256",
                "raw_sha256",
                "compressed_sha256",
            )
        )
        and all(
            type(item[key]) is int and item[key] >= 0
            for key in ("raw_bytes", "compressed_bytes")
        )
        and _valid_identity(item["manifest_identity"])
        and _valid_identity(item["object_identity"])
    )


def _plan_digest(plan: dict[str, Any]) -> str:
    encoded = json.dumps(
        plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _legacy_candidate(
    paths: AppPaths,
    manifest_path: Path,
    manifest: dict[str, Any],
    member: dict[str, Any],
    minimum_compressed_bytes: int,
) -> dict[str, Any] | None:
    if any(key in member for key in ("chunks", "dictionary", "reference")):
        return None
    relative = member["object"]
    details = cas_object_name_details(Path(relative).name)
    if details is None or details[0] != "zstd" or details[2] is not None:
        return None
    expected = f"{member['raw_sha256']}.zst"
    if Path(relative).name != expected:
        return None
    frame = safe_cas_object_path(paths.archive, relative, kind="zstd")
    identity = regular_file_stat(frame)
    if identity["size"] < minimum_compressed_bytes:
        return None
    if sha256_file(frame) != member["compressed_sha256"]:
        raise ValueError(f"archive compressed SHA-256 mismatch: {manifest_path}")
    return {
        "manifest": str(manifest_path),
        "manifest_identity": regular_file_stat(manifest_path),
        "manifest_logical_sha256": _logical_manifest_sha256(manifest),
        "manifest_sha256": sha256_file(manifest_path),
        "member": member["relative"],
        "raw_sha256": member["raw_sha256"],
        "raw_bytes": member["size"],
        "compressed_sha256": member["compressed_sha256"],
        "compressed_bytes": identity["size"],
        "object": relative,
        "object_identity": identity,
        "archive_id": manifest["archive_id"],
        "provider": manifest["provider"],
    }


def create_repack_plan(
    paths: AppPaths,
    *,
    minimum_compressed_bytes: int = DEFAULT_REPACK_MINIMUM_COMPRESSED_BYTES,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any]]:
    if (
        type(minimum_compressed_bytes) is not int
        or minimum_compressed_bytes < 0
    ):
        raise ValueError("repack minimum compressed bytes must be non-negative")
    paths.ensure_private()
    if encryption_config(paths) is not None:
        raise RuntimeError("archive repack does not support encrypted archives")
    prune_expired_plans(paths)
    current = (now or utc_now()).astimezone(UTC)
    with app_lock(paths):
        items = []
        for manifest_path, manifest in _validate_archive_graph(paths):
            for member in manifest["files"]:
                candidate = _legacy_candidate(
                    paths,
                    manifest_path,
                    manifest,
                    member,
                    minimum_compressed_bytes,
                )
                if candidate is not None:
                    items.append(candidate)
        items.sort(
            key=lambda item: (
                -item["compressed_bytes"],
                item["manifest"],
                item["member"],
            )
        )
        run_id = new_run_id(current)
        plan = {
            "schema_version": SCHEMA_VERSION,
            "kind": "archive-repack-plan",
            "run_id": run_id,
            "created_at": iso_utc(current),
            "expires_at": iso_utc(max(current, utc_now()) + timedelta(hours=2)),
            "archive": str(paths.archive),
            "minimum_compressed_bytes": minimum_compressed_bytes,
            "candidates": len(items),
            "manifests": len({item["manifest"] for item in items}),
            "raw_bytes": sum(item["raw_bytes"] for item in items),
            "compressed_bytes": sum(item["compressed_bytes"] for item in items),
            "items": items,
        }
        digest = _plan_digest(plan)
        plan_path = (
            paths.state / "plans" / f"archive-repack-{run_id}-{digest}.json"
        )
        atomic_json(plan_path, plan, replace=False)
        return plan_path, plan


def apply_repack_plan(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    with app_lock(paths):
        paths.ensure_private()
        if encryption_config(paths) is not None:
            raise RuntimeError("archive repack does not support encrypted archives")
        plan = _validate_plan(paths, plan_path)
        journal = _journal_path(paths)
        if any(journal.parent.iterdir()):
            raise RuntimeError(
                "repack recovery is pending; run archive repack recover"
            )
        _validate_archive_graph(paths)
        statuses = _preflight_items(paths, plan["items"])

        zstd = _zstd_binary()
        cas_before = _cas_inventory(paths)
        free_before = shutil.disk_usage(paths.archive).free
        cache: dict[str, tuple[str, str, int]] = {}
        updated_manifests: set[str] = set()
        new_objects: dict[str, int] = {}
        repacked = non_beneficial = already_repacked = objects_removed = 0
        for index, (item, status) in enumerate(
            zip(plan["items"], statuses, strict=True), start=1
        ):
            if status == "completed":
                already_repacked += 1
                print(
                    "repack progress: "
                    f"{index}/{len(plan['items'])} candidates committed; "
                    "0 bytes saved",
                    file=sys.stderr,
                    flush=True,
                )
                continue
            outcome = _repack_item_locked(paths, item, zstd, journal, cache)
            if outcome["repacked"]:
                repacked += 1
                updated_manifests.add(item["manifest"])
                new_objects[outcome["new_object"]] = outcome["new_bytes"]
                objects_removed += int(outcome["old_removed"])
            else:
                non_beneficial += 1
            print(
                "repack progress: "
                f"{index}/{len(plan['items'])} candidates committed; "
                f"{outcome['saved_bytes']} bytes saved",
                file=sys.stderr,
                flush=True,
            )

        cas_after = _cas_inventory(paths)
        compressed_before = sum(value[0] for value in cas_before.values())
        compressed_after = sum(value[0] for value in cas_after.values())
        result = {
            "selected": len(plan["items"]),
            "repacked": repacked,
            "non_beneficial": non_beneficial,
            "already_repacked": already_repacked,
            "manifests_updated": len(updated_manifests),
            "objects_removed": objects_removed,
            "compressed_bytes_before": compressed_before,
            "compressed_bytes_after": compressed_after,
            "bytes_reclaimed": max(0, compressed_before - compressed_after),
            "physical_allocated_bytes_delta": (
                sum(value[1] for value in cas_after.values())
                - sum(value[1] for value in cas_before.values())
            ),
            "observed_free_bytes_delta": (
                shutil.disk_usage(paths.archive).free - free_before
            ),
        }
        if not repacked:
            result["history_recorded"] = False
            return result
        recorded = record_history_after_success(
            paths,
            result,
            operation="archive-repack",
            physical_allocated_bytes_delta=result[
                "physical_allocated_bytes_delta"
            ],
            observed_free_bytes_delta=result["observed_free_bytes_delta"],
            cas_objects=new_objects,
        )
        recorded.setdefault("history_recorded", True)
        return recorded


def recover_repack(paths: AppPaths) -> dict[str, int]:
    with app_lock(paths):
        paths.ensure_private()
        if encryption_config(paths) is not None:
            raise RuntimeError("archive repack does not support encrypted archives")
        root = ensure_private_subdirectory(paths.state, "repack")
        entries = sorted(root.iterdir())
        if not entries:
            return {"completed": 0, "rolled_back": 0}
        journal_path = root / "active.json"
        if entries != [journal_path] or journal_path.is_symlink():
            raise ValueError("archive repack journal directory is invalid")
        regular_file_stat(journal_path)
        journal = _validate_journal(paths, load_json(journal_path), journal_path)
        manifest_path = Path(journal["manifest"])
        manifest = validate_manifest(manifest_path)
        expected_manifest = (
            paths.archive
            / "manifests"
            / manifest["provider"]
            / f"{manifest['archive_id']}.json"
        )
        if manifest_path != expected_manifest:
            raise ValueError("archive repack journal manifest path is invalid")
        current_sha = sha256_file(manifest_path)
        before = current_sha == journal["manifest_before_sha256"]
        after = (
            "manifest_after_sha256" in journal
            and current_sha == journal["manifest_after_sha256"]
        )
        if not before and not after:
            raise RuntimeError("archive repack journal manifest state is unknown")
        temporary = _journal_temporary(paths, journal)
        old_candidate = paths.archive / journal["old_object"]
        old_frame = None
        if old_candidate.exists() or old_candidate.is_symlink():
            old_frame = safe_cas_object_path(
                paths.archive, journal["old_object"], kind="zstd"
            )
            if not identity_matches(old_frame, journal["old_object_identity"]):
                raise RuntimeError(
                    "archive repack journal old object identity drifted"
                )
        elif before:
            raise RuntimeError("archive repack journal old object is missing")

        if before:
            member = next(
                (
                    value
                    for value in manifest["files"]
                    if value["relative"] == journal["member"]
                ),
                None,
            )
            if member is None or member.get("object") != journal["old_object"]:
                raise RuntimeError("archive repack journal old manifest drifted")
            _verify_validated_manifest(paths, manifest_path, manifest)
            new_relative = journal.get("new_object")
            if new_relative is not None:
                new_frame = _journal_new_object(paths, journal)
                if new_frame is not None and not _object_is_referenced(
                    paths, new_relative
                ):
                    new_frame.unlink()
                    fsync_dir(new_frame.parent)
            if temporary is not None:
                temporary.unlink()
                fsync_dir(temporary.parent)
            _remove_journal(journal_path)
            return {"completed": 0, "rolled_back": 1}

        updated = journal["updated_manifest"]
        if manifest != updated:
            raise RuntimeError("archive repack journal committed manifest drifted")
        _verify_validated_manifest(paths, manifest_path, manifest)
        if temporary is not None:
            temporary.unlink()
            fsync_dir(temporary.parent)
        if old_frame is not None and not _object_is_referenced(
            paths, journal["old_object"]
        ):
            old_frame.unlink()
            fsync_dir(old_frame.parent)
        _remove_journal(journal_path)
        return {"completed": 1, "rolled_back": 0}


def _validate_plan(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    expected_root = paths.state / "plans"
    if plan_path.parent != expected_root:
        raise ValueError("archive repack plan escaped the plans root")
    regular_file_stat(plan_path)
    plan = load_json(plan_path)
    if (
        set(plan) != _PLAN_KEYS
        or type(plan.get("schema_version")) is not int
        or plan["schema_version"] not in SUPPORTED_SCHEMA_VERSIONS
        or plan.get("kind") != "archive-repack-plan"
        or plan.get("archive") != str(paths.archive)
    ):
        raise ValueError("archive repack plan is invalid")
    run_id = validate_run_id(plan.get("run_id"))
    if type(plan.get("created_at")) is not str or type(plan.get("expires_at")) is not str:
        raise ValueError("archive repack plan timestamps are invalid")
    created = parse_timestamp(plan["created_at"])
    expires = parse_timestamp(plan["expires_at"])
    if created > expires or utc_now() > expires:
        raise RuntimeError("archive repack plan expired")
    digest = _plan_digest(plan)
    if plan_path.name != f"archive-repack-{run_id}-{digest}.json":
        raise ValueError("archive repack plan name does not match its identity")
    items = plan.get("items")
    if type(items) is not list or any(not _valid_plan_item(item) for item in items):
        raise ValueError("archive repack plan items are invalid")
    if (
        type(plan.get("minimum_compressed_bytes")) is not int
        or plan["minimum_compressed_bytes"] < 0
        or type(plan.get("candidates")) is not int
        or plan["candidates"] != len(items)
        or type(plan.get("manifests")) is not int
        or plan["manifests"] != len({item["manifest"] for item in items})
        or type(plan.get("raw_bytes")) is not int
        or plan["raw_bytes"] != sum(item.get("raw_bytes", -1) for item in items)
        or type(plan.get("compressed_bytes")) is not int
        or plan["compressed_bytes"]
        != sum(item.get("compressed_bytes", -1) for item in items)
    ):
        raise ValueError("archive repack plan summary is invalid")
    return plan


def _planned_member(manifest: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    matches = [
        member for member in manifest["files"] if member["relative"] == item["member"]
    ]
    if len(matches) != 1:
        raise RuntimeError("archive repack manifest member drifted")
    return matches[0]


def _validate_archive_graph(
    paths: AppPaths,
) -> list[tuple[Path, dict[str, Any]]]:
    manifests = []
    for manifest_path in iter_manifests(paths):
        manifest = validate_manifest(manifest_path)
        manifests.append((manifest_path, manifest))
        for member in manifest["files"]:
            chunks = member.get("chunks")
            if chunks is not None:
                for chunk in chunks:
                    digest = chunk["sha256"]
                    safe_cas_object_path(
                        paths.archive,
                        f"objects/sha256/{digest[:2]}/{digest}.zst",
                        kind="zstd",
                    )
            else:
                frame = safe_cas_object_path(
                    paths.archive, member["object"], kind="zstd"
                )
                if sha256_file(frame) != member["compressed_sha256"]:
                    raise ValueError(
                        f"archive compressed SHA-256 mismatch: {manifest_path}"
                    )
            dictionary = member.get("dictionary")
            if dictionary is not None:
                safe_cas_object_path(paths.archive, dictionary, kind="dictionary")
    _cas_inventory(paths)
    return manifests


def _logical_manifest_sha256(manifest: dict[str, Any]) -> str:
    logical = json.loads(json.dumps(manifest))
    for member in logical["files"]:
        member.pop("object", None)
        member.pop("compressed_sha256", None)
    encoded = json.dumps(
        logical, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _preflight_items(paths: AppPaths, items: list[dict[str, Any]]) -> list[str]:
    statuses: list[str] = []
    by_manifest: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, item in enumerate(items):
        by_manifest.setdefault(item["manifest"], []).append((index, item))
    resolved: dict[int, str] = {}
    for value, grouped in by_manifest.items():
        manifest_path = Path(value)
        first = grouped[0][1]
        expected_manifest = (
            paths.archive
            / "manifests"
            / first["provider"]
            / f"{first['archive_id']}.json"
        )
        if manifest_path != expected_manifest:
            raise ValueError("archive repack manifest path is invalid")
        manifest = validate_manifest(manifest_path)
        if any(
            item["manifest_logical_sha256"] != _logical_manifest_sha256(manifest)
            for _, item in grouped
        ):
            raise RuntimeError("archive repack logical manifest drifted")
        original_snapshot = identity_matches(
            manifest_path, first["manifest_identity"]
        ) and sha256_file(manifest_path) == first["manifest_sha256"]
        completed_present = False
        pending: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
        for index, item in grouped:
            member = _planned_member(manifest, item)
            if (
                member["raw_sha256"] != item["raw_sha256"]
                or member["size"] != item["raw_bytes"]
            ):
                raise RuntimeError("archive repack logical manifest drifted")
            if (
                member.get("object") == item["object"]
                and member.get("compressed_sha256") == item["compressed_sha256"]
            ):
                pending.append((index, item, member))
                continue
            details = cas_object_name_details(Path(member.get("object", "")).name)
            if (
                details is None
                or details[0] != "zstd"
                or details[2] is None
                or Path(member["object"]).name.split(".", 1)[0]
                != item["raw_sha256"]
                or member.get("compressed_sha256") != details[2]
            ):
                raise RuntimeError("archive repack manifest storage drifted")
            frame = safe_cas_object_path(
                paths.archive, member["object"], kind="zstd"
            )
            if sha256_file(frame) != member["compressed_sha256"]:
                raise RuntimeError("archive repack compressed SHA-256 drifted")
            resolved[index] = "completed"
            completed_present = True
        if not original_snapshot and not completed_present:
            raise RuntimeError("archive repack manifest identity drifted")
        for index, item, _ in pending:
            frame = safe_cas_object_path(paths.archive, item["object"], kind="zstd")
            if not identity_matches(frame, item["object_identity"]):
                raise RuntimeError("archive repack object identity drifted")
            if sha256_file(frame) != item["compressed_sha256"]:
                raise RuntimeError("archive repack compressed SHA-256 drifted")
            resolved[index] = "pending"
    for index in range(len(items)):
        statuses.append(resolved[index])
    return statuses


def _journal_path(paths: AppPaths) -> Path:
    return ensure_private_subdirectory(paths.state, "repack") / "active.json"


def _write_journal(path: Path, payload: dict[str, Any]) -> None:
    atomic_json(path, payload)


def _remove_journal(path: Path) -> None:
    path.unlink()
    fsync_dir(path.parent)


_JOURNAL_BASE_KEYS = {
    "schema_version",
    "kind",
    "phase",
    "manifest",
    "manifest_before_sha256",
    "member",
    "old_object",
    "old_object_identity",
    "temporary",
    "temporary_identity",
}
_JOURNAL_PREPARED_KEYS = _JOURNAL_BASE_KEYS | {
    "new_object",
    "new_compressed_sha256",
    "new_bytes",
    "manifest_after_sha256",
    "updated_manifest",
}


def _journal_relative(value: Any, *, temporary: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError("archive repack journal CAS path is invalid")
    relative = Path(value)
    details = cas_object_name_details(relative.name)
    expected_kind = "temporary" if temporary else "zstd"
    if (
        relative.is_absolute()
        or len(relative.parts) != 4
        or relative.parts[:2] != ("objects", "sha256")
        or details is None
        or details[0] != expected_kind
        or relative.parts[2] != details[1]
    ):
        raise ValueError("archive repack journal CAS path is invalid")
    return value


def _validate_journal(
    paths: AppPaths, journal: dict[str, Any], journal_path: Path
) -> dict[str, Any]:
    phase = journal.get("phase")
    expected = (
        _JOURNAL_BASE_KEYS if phase == "compressing" else _JOURNAL_PREPARED_KEYS
    )
    if (
        set(journal) != expected
        or type(journal.get("schema_version")) is not int
        or journal["schema_version"] != SCHEMA_VERSION
        or journal.get("kind") != "archive-repack-journal"
        or phase not in {"compressing", "prepared", "published", "committed"}
        or not isinstance(journal.get("manifest"), str)
        or not Path(journal["manifest"]).is_absolute()
        or not isinstance(journal.get("member"), str)
        or not isinstance(journal.get("manifest_before_sha256"), str)
        or len(journal["manifest_before_sha256"]) != 64
        or type(journal.get("old_object_identity")) is not dict
        or type(journal.get("temporary_identity")) is not dict
    ):
        raise ValueError(f"archive repack journal is invalid: {journal_path}")
    _journal_relative(journal["old_object"])
    if journal["temporary"] is not None:
        _journal_relative(journal["temporary"], temporary=True)
    if phase != "compressing":
        _journal_relative(journal["new_object"])
        details = cas_object_name_details(Path(journal["new_object"]).name)
        if (
            not isinstance(journal.get("new_compressed_sha256"), str)
            or details is None
            or details[2] != journal["new_compressed_sha256"]
            or type(journal.get("new_bytes")) is not int
            or journal["new_bytes"] < 0
            or not isinstance(journal.get("manifest_after_sha256"), str)
            or len(journal["manifest_after_sha256"]) != 64
            or type(journal.get("updated_manifest")) is not dict
        ):
            raise ValueError(f"archive repack journal is invalid: {journal_path}")
        updated = _validate_manifest_payload(
            journal["updated_manifest"], Path(journal["manifest"])
        )
        encoded = (json.dumps(updated, indent=2, sort_keys=True) + "\n").encode()
        if hashlib.sha256(encoded).hexdigest() != journal["manifest_after_sha256"]:
            raise ValueError(f"archive repack journal is invalid: {journal_path}")
    return journal


def _journal_temporary(paths: AppPaths, journal: dict[str, Any]) -> Path | None:
    value = journal["temporary"]
    if value is None:
        return None
    candidate = paths.archive / value
    if not candidate.exists() and not candidate.is_symlink():
        return None
    path = safe_cas_object_path(paths.archive, value, kind="temporary")
    anchor = journal["temporary_identity"]
    current = regular_file_stat(path)
    if any(current.get(key) != anchor.get(key) for key in ("device", "inode", "mode")):
        raise RuntimeError("archive repack journal temporary identity drifted")
    return path


def _journal_new_object(paths: AppPaths, journal: dict[str, Any]) -> Path | None:
    relative = journal["new_object"]
    path = paths.archive / relative
    if not path.exists() and not path.is_symlink():
        return None
    frame = safe_cas_object_path(paths.archive, relative, kind="zstd")
    if (
        frame.stat(follow_symlinks=False).st_size != journal["new_bytes"]
        or sha256_file(frame) != journal["new_compressed_sha256"]
    ):
        raise RuntimeError("archive repack journal new object drifted")
    return frame


def _stream_recompress(zstd: str, source: Path, target: Path) -> None:
    decoder = subprocess.Popen(
        [zstd, "-q", "-d", "--stdout", str(source)], stdout=subprocess.PIPE
    )
    assert decoder.stdout is not None
    encoder: subprocess.Popen[bytes] | None = None
    try:
        with target.open("wb") as output:
            encoder = subprocess.Popen(
                [zstd, "-q", "-19", "--long=27", "--check", "-T0"],
                stdin=decoder.stdout,
                stdout=output,
            )
            decoder.stdout.close()
            encoder_status = encoder.wait()
        decoder_status = decoder.wait()
    except BaseException:
        for process in (encoder, decoder):
            if process is not None and process.poll() is None:
                process.kill()
            if process is not None:
                process.wait()
        raise
    if decoder_status != 0 or encoder_status != 0:
        raise RuntimeError(
            "archive repack codec pipeline failed: "
            f"decoder={decoder_status}, encoder={encoder_status}"
        )
    with target.open("rb") as handle:
        os.fsync(handle.fileno())


def _object_is_referenced(paths: AppPaths, relative: str) -> bool:
    for _, manifest in _validate_archive_graph(paths):
        if relative in _manifest_zstd_objects(manifest):
            return True
    return False


def _updated_manifest(
    manifest: dict[str, Any], item: dict[str, Any], relative: str, digest: str
) -> dict[str, Any]:
    updated = json.loads(json.dumps(manifest))
    member = _planned_member(updated, item)
    member["object"] = relative
    member["compressed_sha256"] = digest
    return updated


def _repack_item_locked(
    paths: AppPaths,
    item: dict[str, Any],
    zstd: str,
    journal_path: Path,
    cache: dict[str, tuple[str, str, int]],
) -> dict[str, Any]:
    manifest_path = Path(item["manifest"])
    manifest = validate_manifest(manifest_path)
    old_frame = safe_cas_object_path(paths.archive, item["object"], kind="zstd")
    _verify_zstd(zstd, old_frame, item["raw_sha256"])
    cached = cache.get(item["object"])
    temporary: Path | None = None
    if cached is None:
        shard = ensure_safe_cas_shard(paths.archive, item["raw_sha256"][:2])
        fd, raw = tempfile.mkstemp(
            prefix=f".{item['raw_sha256']}.", suffix=".part", dir=shard
        )
        os.close(fd)
        temporary = Path(raw)
        temporary.chmod(0o600)
        journal = {
            "schema_version": SCHEMA_VERSION,
            "kind": "archive-repack-journal",
            "phase": "compressing",
            "manifest": str(manifest_path),
            "manifest_before_sha256": sha256_file(manifest_path),
            "member": item["member"],
            "old_object": item["object"],
            "old_object_identity": regular_file_stat(old_frame),
            "temporary": str(temporary.relative_to(paths.archive)),
            "temporary_identity": regular_file_stat(temporary),
        }
        try:
            _write_journal(journal_path, journal)
        except BaseException:
            if not journal_path.exists() and not journal_path.is_symlink():
                temporary.unlink()
                fsync_dir(temporary.parent)
            raise
        _stream_recompress(zstd, old_frame, temporary)
        _verify_zstd(zstd, temporary, item["raw_sha256"])
        new_bytes = temporary.stat().st_size
        if new_bytes >= item["compressed_bytes"]:
            temporary.unlink()
            fsync_dir(temporary.parent)
            _remove_journal(journal_path)
            return {
                "repacked": False,
                "saved_bytes": 0,
                "old_removed": False,
                "new_object": "",
                "new_bytes": 0,
            }
        compressed = sha256_file(temporary)
        relative = (
            f"objects/sha256/{item['raw_sha256'][:2]}/"
            f"{item['raw_sha256']}.{compressed}.zst"
        )
        target = shard / Path(relative).name
    else:
        relative, compressed, new_bytes = cached
        target = safe_cas_object_path(paths.archive, relative, kind="zstd")
        _verify_zstd(zstd, target, item["raw_sha256"])
        journal = {
            "schema_version": SCHEMA_VERSION,
            "kind": "archive-repack-journal",
            "phase": "published",
            "manifest": str(manifest_path),
            "manifest_before_sha256": sha256_file(manifest_path),
            "member": item["member"],
            "old_object": item["object"],
            "old_object_identity": regular_file_stat(old_frame),
            "temporary": None,
            "temporary_identity": {},
        }

    updated = _updated_manifest(manifest, item, relative, compressed)
    journal.update(
        {
            "new_object": relative,
            "new_compressed_sha256": compressed,
            "new_bytes": new_bytes,
            "manifest_after_sha256": hashlib.sha256(
                (json.dumps(updated, indent=2, sort_keys=True) + "\n").encode()
            ).hexdigest(),
            "updated_manifest": updated,
        }
    )
    if cached is None:
        journal["phase"] = "prepared"
        _write_journal(journal_path, journal)
        _publish_frame_payload(paths, temporary, target)
        target = safe_cas_object_path(paths.archive, relative, kind="zstd")
        if sha256_file(target) != compressed:
            raise RuntimeError("archive repack published compressed SHA-256 mismatch")
        journal["phase"] = "published"
    _write_journal(journal_path, journal)
    if temporary is not None:
        temporary.unlink(missing_ok=True)
        fsync_dir(temporary.parent)

    atomic_json(manifest_path, updated)
    journal["phase"] = "committed"
    _write_journal(journal_path, journal)
    _verify_validated_manifest(paths, manifest_path, validate_manifest(manifest_path))
    removed = False
    if not _object_is_referenced(paths, item["object"]):
        if not identity_matches(old_frame, item["object_identity"]):
            raise RuntimeError("archive repack old object identity drifted")
        old_frame.unlink()
        fsync_dir(old_frame.parent)
        removed = True
    _remove_journal(journal_path)
    cache[item["object"]] = (relative, compressed, new_bytes)
    return {
        "repacked": True,
        "saved_bytes": item["compressed_bytes"] - new_bytes,
        "old_removed": removed,
        "new_object": relative,
        "new_bytes": new_bytes,
    }
