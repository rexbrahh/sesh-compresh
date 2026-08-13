from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import sesh_compresh.archive as archive_module
import sesh_compresh.common as common_module
import sesh_compresh.history as history_module
import sesh_compresh.observer as observer_module
from sesh_compresh.archive import (
    CHUNK_TARGET_BYTES,
    SourceChangedError,
    UnsafeSessionTreeError,
    _chunk_records,
    _zstd_binary,
    apply_archive_plan,
    archive_planned_session,
    archive_stats,
    benchmark_dictionary,
    create_archive_plan,
    iter_manifests,
    list_archives,
    load_provider_dictionary,
    recover_quarantine,
    resolve_latest_manifest,
    restore_manifest,
    restore_manifest_set,
    train_dictionary,
    validate_manifest,
    verify_manifest,
    verify_all,
)
from sesh_compresh.common import (
    AppPaths,
    atomic_json,
    ensure_safe_cas_shard,
    regular_directory_stat,
    regular_file_stat,
    safe_cas_object_path,
    sha256_file,
    utc_now,
)
from sesh_compresh.observer import ClaudeMemPaths
from sesh_compresh.history import history_summary


class ArchiveRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.paths = AppPaths.discover(self.home)
        self.project = self.home / ".claude/projects/-fixture-project"
        self.project.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_session(self, name: str, timestamp: str = "2020-01-01T00:00:00Z") -> Path:
        path = self.project / f"{name}.jsonl"
        records = [
            {"type": "user", "timestamp": timestamp, "content": "repeat " * 5000},
            {"type": "assistant", "timestamp": timestamp, "content": "answer " * 5000},
            {"type": "summary", "sessionId": name},
        ]
        path.write_text(
            "".join(json.dumps(item) + "\n" for item in records), encoding="utf-8"
        )
        os.chmod(path, 0o640)
        return path

    def stage_recovery_item(
        self,
        run: str,
        *,
        relative: str = "nested/session.jsonl",
        schema_version: int = 2,
        journal_schema_version: int | None = None,
        directories: tuple[str, ...] = (),
        source_root_symlink: bool = False,
        source_root_intermediate_symlink: bool = False,
    ) -> dict[str, Path]:
        if source_root_symlink and source_root_intermediate_symlink:
            raise ValueError("test source root can use only one symlink layout")
        if source_root_intermediate_symlink:
            real_parent = self.paths.home / f"source-{run}-real-parent"
            real_source_root = real_parent / "root"
            real_source_root.mkdir(parents=True)
            linked_parent = self.paths.home / f"source-{run}-link-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            source_root = linked_parent / "root"
        else:
            real_source_root = self.paths.home / f"source-{run}"
            real_source_root.mkdir()
            source_root = real_source_root
        if source_root_symlink:
            source_root = self.paths.home / f"source-{run}-link"
            source_root.symlink_to(real_source_root, target_is_directory=True)
        source = source_root / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("payload", encoding="utf-8")
        file_member = {
            "path": str(source),
            "relative": relative,
            **regular_file_stat(source),
            "raw_sha256": sha256_file(source),
        }
        directory_members = []
        for value in directories:
            directory = source_root / value
            directory.mkdir(parents=True, exist_ok=True)
            directory_members.append(
                {
                    "path": str(directory),
                    "relative": value,
                    **regular_directory_stat(directory),
                }
            )

        staged_manifest = {
            "schema_version": schema_version,
            "kind": "session-archive",
            "archive_id": "",
            "provider": "claude",
            "session_id": run,
            "source_root": str(source_root),
            "last_activity": "2020-01-01T00:00:00Z",
            "archived_at": "2020-01-01T00:00:00Z",
            "zstd_version": "zstd 1.test",
            "files": [file_member],
            "directories": directory_members,
        }
        archive_id = archive_module._manifest_key(staged_manifest)
        staged_manifest["archive_id"] = archive_id
        item_root = self.paths.state / "quarantine" / run / archive_id
        quarantined = item_root / "files" / relative
        quarantined.parent.mkdir(parents=True)
        os.replace(source, quarantined)
        for member in sorted(
            directory_members,
            key=lambda value: len(Path(value["relative"]).parts),
            reverse=True,
        ):
            Path(member["path"]).rmdir()

        manifest_path = (
            self.paths.archive / "manifests" / "claude" / f"{archive_id}.json"
        )
        staged_path = item_root / "_manifest.json"
        record_path = item_root / "_restore.json"
        atomic_json(staged_path, staged_manifest)
        atomic_json(
            record_path,
            {
                "schema_version": (
                    journal_schema_version
                    if journal_schema_version is not None
                    else schema_version
                ),
                "source_root": str(source_root),
                "manifest": str(manifest_path),
                "files": [relative],
                "directories": list(directories),
            },
        )
        return {
            "source_root": source_root,
            "real_source_root": real_source_root,
            "source": source,
            "quarantined": quarantined,
            "item_root": item_root,
            "staged": staged_path,
            "record": record_path,
            "manifest": manifest_path,
        }

    def post_publish_crash(
        self, session: dict, run: str, *, delete_payload: bool
    ) -> dict[str, Path]:
        key = archive_module._manifest_key(session)
        item_root = self.paths.state / "quarantine" / run / key
        real_rmtree = archive_module.shutil.rmtree

        def crashing_rmtree(path: Path) -> None:
            self.assertEqual(item_root / "files", Path(path))
            if delete_payload:
                real_rmtree(path)
            raise SystemExit("post-publication cleanup crash")

        self.paths.ensure_private()
        archive_module._ensure_archive_canary(self.paths, _zstd_binary())
        with mock.patch.object(
            archive_module.shutil, "rmtree", side_effect=crashing_rmtree
        ):
            with self.assertRaises(SystemExit):
                archive_planned_session(
                    self.paths,
                    session,
                    zstd=_zstd_binary(),
                    quarantine_run=self.paths.state / "quarantine" / run,
                )
        staged = json.loads((item_root / "_manifest.json").read_text(encoding="utf-8"))
        manifest_path = (
            self.paths.archive
            / "manifests"
            / session["provider"]
            / f"{staged['archive_id']}.json"
        )
        return {"item_root": item_root, "manifest": manifest_path}

    def test_verified_round_trip_and_collision_refusal(self) -> None:
        source = self.write_session("session-a")
        original_hash = sha256_file(source)
        original_mode = source.stat().st_mode & 0o777
        original_mtime = source.stat().st_mtime_ns
        plan_path, plan = create_archive_plan(self.paths, utc_now())
        self.assertEqual(1, len(plan["sessions"]))

        result = apply_archive_plan(self.paths, plan_path)
        self.assertEqual(1, result["sessions"])
        self.assertEqual(1, result["manifest_count"])
        self.assertFalse(source.exists())
        history = history_summary(self.paths)
        self.assertEqual(1, history["events"])
        self.assertEqual(result["logical_raw_bytes"], history["logical_archived_bytes"])
        self.assertEqual(result["unique_cas_bytes"], history["unique_cas_bytes"])
        self.assertEqual({"manifests": 1, "files": 1}, verify_all(self.paths))

        manifest = next(iter_manifests(self.paths))
        destination = self.home / "restore-canary"
        restored = restore_manifest(self.paths, str(manifest), destination)
        restored_path = destination / source.relative_to(self.project)
        self.assertEqual(1, restored["files"])
        self.assertEqual(original_hash, sha256_file(restored_path))
        self.assertEqual(original_mode, restored_path.stat().st_mode & 0o777)
        self.assertEqual(original_mtime, restored_path.stat().st_mtime_ns)
        with self.assertRaises(FileExistsError):
            restore_manifest(self.paths, str(manifest), destination)

    def test_archive_history_failure_does_not_hide_completed_apply(self) -> None:
        source = self.write_session("history-failure")
        plan_path, _ = create_archive_plan(self.paths, utc_now())

        with mock.patch.object(
            history_module,
            "append_history_event",
            side_effect=OSError("history unavailable"),
        ):
            result = apply_archive_plan(self.paths, plan_path)

        self.assertFalse(source.exists())
        self.assertEqual(1, result["sessions"])
        self.assertFalse(result["history_recorded"])
        self.assertEqual(
            "maintenance history append failed", result["history_warning"]
        )

    def test_verify_all_continue_materializes_and_aggregates_expected_failures(
        self,
    ) -> None:
        manifest_paths = [self.home / f"manifest-{index}.json" for index in range(4)]
        selection_complete = False

        def select(_paths: AppPaths):
            nonlocal selection_complete
            yield from manifest_paths
            selection_complete = True

        def verify(_paths: AppPaths, manifest_path: Path) -> dict:
            self.assertTrue(selection_complete)
            if manifest_path == manifest_paths[1]:
                raise ValueError("invalid manifest")
            if manifest_path == manifest_paths[2]:
                raise OSError("object unavailable")
            return {"files": [{}] if manifest_path == manifest_paths[0] else [{}, {}]}

        with (
            mock.patch.object(archive_module, "iter_manifests", side_effect=select),
            mock.patch.object(archive_module, "verify_manifest", side_effect=verify),
        ):
            result = verify_all(self.paths, continue_on_error=True)

        self.assertEqual(4, result["selected"])
        self.assertEqual(2, result["verified"])
        self.assertEqual(2, result["failed_manifests"])
        self.assertEqual(
            result["selected"], result["verified"] + result["failed_manifests"]
        )
        self.assertEqual(3, result["files"])
        self.assertEqual(
            [
                {
                    "manifest": str(manifest_paths[1]),
                    "error_type": "ValueError",
                    "error": "invalid manifest",
                },
                {
                    "manifest": str(manifest_paths[2]),
                    "error_type": "OSError",
                    "error": "object unavailable",
                },
            ],
            result["failures"],
        )

    def test_verify_all_default_contract_and_unexpected_errors_remain_fail_fast(
        self,
    ) -> None:
        manifest_paths = [self.home / f"manifest-{index}.json" for index in range(3)]
        with (
            mock.patch.object(
                archive_module, "iter_manifests", return_value=iter(manifest_paths[:2])
            ),
            mock.patch.object(
                archive_module,
                "verify_manifest",
                side_effect=({"files": [{}]}, {"files": [{}, {}]}),
            ),
        ):
            self.assertEqual({"manifests": 2, "files": 3}, verify_all(self.paths))

        with (
            mock.patch.object(
                archive_module, "iter_manifests", return_value=iter(manifest_paths)
            ),
            mock.patch.object(
                archive_module,
                "verify_manifest",
                side_effect=({"files": [{}]}, ValueError("stop"), {"files": [{}]}),
            ) as verify,
        ):
            with self.assertRaisesRegex(ValueError, "stop"):
                verify_all(self.paths)
        self.assertEqual(2, verify.call_count)

        with (
            mock.patch.object(
                archive_module, "iter_manifests", return_value=iter(manifest_paths)
            ),
            mock.patch.object(
                archive_module,
                "verify_manifest",
                side_effect=TypeError("programming error"),
            ) as verify,
        ):
            with self.assertRaisesRegex(TypeError, "programming error"):
                verify_all(self.paths, continue_on_error=True)
        verify.assert_called_once_with(self.paths, manifest_paths[0])

    def test_verify_all_continue_checks_valid_manifest_after_invalid_manifest(
        self,
    ) -> None:
        invalid_source = self.write_session("verify-invalid")
        invalid = self.archive_session(
            self.plain_session("verify-invalid", invalid_source),
            "verify-invalid-run",
        )
        valid_source = self.write_session("verify-valid")
        self.archive_session(
            self.plain_session("verify-valid", valid_source),
            "verify-valid-run",
        )
        invalid_path = Path(invalid["manifest"])
        payload = json.loads(invalid_path.read_text(encoding="utf-8"))
        payload["kind"] = "invalid"
        atomic_json(invalid_path, payload)

        result = verify_all(self.paths, continue_on_error=True)

        self.assertEqual(2, result["selected"])
        self.assertEqual(1, result["verified"])
        self.assertEqual(1, result["failed_manifests"])
        self.assertEqual(
            result["selected"], result["verified"] + result["failed_manifests"]
        )
        self.assertEqual(1, result["files"])
        self.assertEqual(1, len(result["failures"]))
        self.assertEqual(str(invalid_path), result["failures"][0]["manifest"])
        self.assertEqual("ValueError", result["failures"][0]["error_type"])

    def test_archive_plan_names_are_unique_and_publish_without_replacement(
        self,
    ) -> None:
        self.write_session("unique-plan")
        current = datetime(2000, 1, 1, tzinfo=UTC)
        for index in range(33):
            atomic_json(
                self.paths.state / "plans" / f"expired-{index}.json",
                {"expires_at": "2000-01-01T00:00:00Z"},
            )
        events = []

        def publish(*args, **kwargs):
            events.append("publish")
            return common_module.atomic_json(*args, **kwargs)

        def prune(*args, **kwargs):
            events.append("prune")
            return common_module.prune_expired_plans(*args, **kwargs)

        with (
            mock.patch.object(archive_module, "open_file_paths", return_value=set()),
            mock.patch.object(
                archive_module, "atomic_json", side_effect=publish
            ) as write,
            mock.patch.object(archive_module, "prune_expired_plans", side_effect=prune),
        ):
            first_path, first = create_archive_plan(self.paths, current)
            second_path, second = create_archive_plan(self.paths, current)

        self.assertNotEqual(first["run_id"], second["run_id"])
        self.assertNotEqual(first_path, second_path)
        self.assertTrue(first_path.is_file())
        self.assertTrue(second_path.is_file())
        self.assertEqual(
            32,
            sum(
                common_module.parse_timestamp(
                    common_module.load_json(path)["expires_at"]
                )
                < utc_now()
                for path in (self.paths.state / "plans").glob("expired-*.json")
            ),
        )
        self.assertEqual(["prune", "publish", "prune", "publish"], events)
        self.assertEqual(
            [False, False], [call.kwargs["replace"] for call in write.call_args_list]
        )

    def test_archive_plan_filters_exact_source_device(self) -> None:
        self.write_session("source-device")
        source_device = self.project.stat().st_dev

        _, included = create_archive_plan(
            self.paths, utc_now(), source_device=source_device
        )
        _, excluded = create_archive_plan(
            self.paths, utc_now(), source_device=source_device + 1
        )

        self.assertEqual(1, len(included["sessions"]))
        self.assertEqual([], excluded["sessions"])
        self.assertEqual(1, excluded["skipped"]["different filesystem"])
        with self.assertRaisesRegex(ValueError, "source device"):
            create_archive_plan(self.paths, utc_now(), source_device=True)

    def test_first_source_move_requires_persisted_canary(self) -> None:
        source = self.write_session("canary-gate")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        marker = self.paths.state / "archive-canary.json"
        real_replace = os.replace
        source_move_saw_marker = False

        def checked_replace(old, new):
            nonlocal source_move_saw_marker
            if Path(old).resolve() == source.resolve():
                source_move_saw_marker = marker.is_file()
            return real_replace(old, new)

        with mock.patch.object(
            archive_module.os, "replace", side_effect=checked_replace
        ):
            apply_archive_plan(self.paths, plan_path)

        self.assertTrue(source_move_saw_marker)
        self.assertFalse(source.exists())
        marker_payload = json.loads(marker.read_text(encoding="utf-8"))
        self.assertEqual("archive-restore-canary", marker_payload["kind"])
        with mock.patch.object(
            archive_module.tempfile,
            "TemporaryDirectory",
            side_effect=AssertionError("valid canary marker should skip the proof"),
        ):
            archive_module._ensure_archive_canary(self.paths, _zstd_binary())

    def test_failed_archive_canary_preserves_live_source(self) -> None:
        source = self.write_session("canary-failure")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        marker = self.paths.state / "archive-canary.json"

        with mock.patch.object(
            archive_module, "restore_manifest", side_effect=RuntimeError("injected")
        ):
            with self.assertRaisesRegex(
                RuntimeError, "canary failed; source removal was blocked"
            ):
                apply_archive_plan(self.paths, plan_path)

        self.assertTrue(source.exists())
        self.assertFalse(marker.exists())
        self.assertEqual([], list(iter_manifests(self.paths)))

    def test_directory_fsync_failure_preserves_live_source(self) -> None:
        source = self.write_session("directory-fsync-failure")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        archive_module._ensure_archive_canary(self.paths, _zstd_binary())
        real_fsync_dir = archive_module.fsync_dir

        def fail_quarantine_sync(path):
            if Path(path).name == "files":
                raise OSError(errno.EIO, "injected directory sync failure")
            return real_fsync_dir(path)

        with mock.patch.object(
            archive_module,
            "fsync_dir",
            side_effect=fail_quarantine_sync,
        ):
            with self.assertRaisesRegex(OSError, "directory sync failure"):
                apply_archive_plan(self.paths, plan_path)

        self.assertTrue(source.exists())
        self.assertEqual([], list(iter_manifests(self.paths)))

    def test_manifest_fsync_failure_leaves_recoverable_archive(self) -> None:
        source = self.write_session("manifest-fsync-failure")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        archive_module._ensure_archive_canary(self.paths, _zstd_binary())
        provider = self.paths.archive / "manifests" / "claude"
        real_fsync_dir = common_module.fsync_dir

        def fail_manifest_sync(path):
            if Path(path) == provider:
                raise OSError(errno.EIO, "injected manifest sync failure")
            return real_fsync_dir(path)

        with mock.patch.object(
            common_module, "fsync_dir", side_effect=fail_manifest_sync
        ):
            with self.assertRaisesRegex(OSError, "manifest sync failure"):
                apply_archive_plan(self.paths, plan_path)

        self.assertFalse(source.exists())
        self.assertEqual({"manifests": 1, "files": 1}, verify_all(self.paths))
        with mock.patch.object(
            archive_module,
            "fsync_dir",
            side_effect=OSError(errno.EIO, "injected recovery sync failure"),
        ):
            with self.assertRaisesRegex(OSError, "recovery sync failure"):
                recover_quarantine(self.paths)
        self.assertFalse(source.exists())
        self.assertTrue(any((self.paths.state / "quarantine").rglob("_restore.json")))
        self.assertEqual(
            {"restored": 0, "conflicts": 0}, recover_quarantine(self.paths)
        )
        self.assertFalse(source.exists())
        self.assertEqual({"manifests": 1, "files": 1}, verify_all(self.paths))

    def test_manifest_publication_never_replaces_a_late_collision(self) -> None:
        source = self.write_session("manifest-collision")
        session = self.plain_session("manifest-collision", source)
        self.paths.ensure_private()
        quarantine_run = self.paths.state / "quarantine" / "manifest-collision"
        manifest_path = None
        sentinel = {"kind": "sentinel"}

        def collide() -> None:
            nonlocal manifest_path
            staged = next(quarantine_run.rglob("_manifest.json"))
            archive_id = json.loads(staged.read_text(encoding="utf-8"))["archive_id"]
            manifest_path = (
                self.paths.archive / "manifests" / "claude" / f"{archive_id}.json"
            )
            atomic_json(manifest_path, sentinel)

        with self.assertRaises(FileExistsError):
            archive_planned_session(
                self.paths,
                session,
                zstd=_zstd_binary(),
                quarantine_run=quarantine_run,
                before_move=collide,
            )

        self.assertTrue(source.exists())
        self.assertIsNotNone(manifest_path)
        self.assertEqual(
            sentinel, json.loads(manifest_path.read_text(encoding="utf-8"))
        )

    def test_rearchive_creates_immutable_versions_and_updates_latest_index(
        self,
    ) -> None:
        source = self.write_session("versioned")
        original = source.read_bytes()
        session = self.plain_session("versioned", source)
        session_key = archive_module._manifest_key(session)

        first = self.archive_session(session, "versioned-first")
        first_path = Path(first["manifest"])
        first_manifest = json.loads(first_path.read_text(encoding="utf-8"))
        first_bytes = first_path.read_bytes()
        self.assertEqual(
            first_path,
            resolve_latest_manifest(self.paths, "claude", session_key),
        )

        restore_manifest(self.paths, str(first_path))
        source.write_bytes(b"second point in time\n")
        second = self.archive_session(
            self.plain_session("versioned", source), "versioned-second"
        )
        second_path = Path(second["manifest"])
        second_manifest = json.loads(second_path.read_text(encoding="utf-8"))

        self.assertNotEqual(first_path, second_path)
        self.assertEqual(1, archive_module._manifest_version(first_manifest))
        self.assertEqual(2, archive_module._manifest_version(second_manifest))
        self.assertEqual(first_bytes, first_path.read_bytes())
        self.assertEqual(2, len(list(iter_manifests(self.paths))))
        self.assertEqual(
            second_path,
            resolve_latest_manifest(self.paths, "claude", session_key),
        )

        first_restore = self.home / "versioned-first-restore"
        second_restore = self.home / "versioned-second-restore"
        restore_manifest(self.paths, str(first_path), first_restore)
        restore_manifest(self.paths, str(second_path), second_restore)
        self.assertEqual(original, (first_restore / source.name).read_bytes())
        self.assertEqual(
            b"second point in time\n", (second_restore / source.name).read_bytes()
        )

    def test_archive_listing_filters_versions_and_sorts_stably(self) -> None:
        source = self.write_session("listed", "2026-04-01T00:00:00Z")
        first = self.archive_session(
            self.plain_session("listed", source), "listed-first"
        )
        first_path = Path(first["manifest"])
        restore_manifest(self.paths, str(first_path))
        source.write_text("second listed version\n", encoding="utf-8")
        second = self.archive_session(
            self.plain_session("listed", source), "listed-second"
        )
        second_path = Path(second["manifest"])

        observer_source = self.write_session("observer-listed", "2026-04-02T00:00:00Z")
        observer_session = self.plain_session("observer-listed", observer_source)
        observer_session["provider"] = "claude-observer"
        observer = self.archive_session(observer_session, "observer-listed")
        observer_path = Path(observer["manifest"])

        for path, archived_at, last_activity in (
            (first_path, "2026-04-10T12:00:00Z", "2026-04-01T00:00:00Z"),
            (second_path, "2026-04-12T00:30:00+01:00", "2026-04-03T00:00:00Z"),
            (observer_path, "2026-04-10T12:00:00Z", "2026-04-02T00:00:00Z"),
        ):
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["archived_at"] = archived_at
            manifest["last_activity"] = last_activity
            atomic_json(path, manifest)

        first_manifest = json.loads(first_path.read_text(encoding="utf-8"))
        duplicate = {
            **first_manifest["files"][0],
            "path": str(self.project / "listed-copy.jsonl"),
            "relative": "listed-copy.jsonl",
        }
        first_manifest["files"].append(duplicate)
        atomic_json(first_path, first_manifest)

        observer_manifest = json.loads(observer_path.read_text(encoding="utf-8"))
        observer_manifest["archive_id"] = archive_module._manifest_key(
            observer_manifest
        )
        legacy_path = observer_path.with_name(f"{observer_manifest['archive_id']}.json")
        atomic_json(legacy_path, observer_manifest)
        observer_path.unlink()

        entries = list_archives(self.paths)
        self.assertEqual(
            ["claude", "claude-observer", "claude"],
            [entry["provider"] for entry in entries],
        )
        self.assertEqual([2, 0, 1], [entry["version"] for entry in entries])
        first_entry = entries[-1]
        first_manifest = validate_manifest(first_path)
        expected_raw = 2 * first_manifest["files"][0]["size"]
        expected_compressed = (
            (self.paths.archive / first_manifest["files"][0]["object"]).stat().st_size
        )
        self.assertEqual(expected_raw, first_entry["raw_bytes"])
        self.assertEqual(expected_compressed, first_entry["compressed_bytes"])
        self.assertEqual(
            round(expected_raw / expected_compressed, 3),
            first_entry["compression_ratio"],
        )
        self.assertEqual(
            {"claude-observer"},
            {
                entry["provider"]
                for entry in list_archives(self.paths, provider="claude-observer")
            },
        )
        self.assertEqual(
            [2, 1],
            [
                entry["version"]
                for entry in list_archives(
                    self.paths, session_id=f"{self.project.name}:listed"
                )
            ],
        )
        self.assertEqual(
            [2],
            [
                entry["version"]
                for entry in list_archives(self.paths, archived_on="2026-04-11")
            ],
        )
        self.assertEqual(
            [1],
            [entry["version"] for entry in list_archives(self.paths, version=1)],
        )
        for sort, field in (
            ("activity", "last_activity"),
            ("archive", "archived_at"),
            ("raw", "raw_bytes"),
            ("ratio", "compression_ratio"),
            ("version", "version"),
        ):
            with self.subTest(sort=sort):
                values = [
                    entry[field] for entry in list_archives(self.paths, sort=sort)
                ]
                self.assertEqual(sorted(values, reverse=True), values)
        self.assertEqual(
            [0, 1, 2],
            [
                entry["version"]
                for entry in list_archives(self.paths, sort="version", reverse=True)
            ],
        )
        with self.assertRaisesRegex(ValueError, "YYYY-MM-DD"):
            list_archives(self.paths, archived_on="2026-4-11")
        with self.assertRaisesRegex(ValueError, "non-negative"):
            list_archives(self.paths, version=-1)

    def test_archive_listing_binds_owned_location_and_filter_types(self) -> None:
        source = self.write_session("list-owned")
        result = self.archive_session(
            self.plain_session("list-owned", source), "list-owned"
        )
        manifest_path = Path(result["manifest"])
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))

        alias = manifest_path.with_name("alias.json")
        atomic_json(alias, payload)
        with self.assertRaisesRegex(ValueError, "owned location"):
            list_archives(self.paths)
        alias.unlink()

        forged_provider = self.paths.archive / "manifests/codex"
        forged_provider.mkdir(mode=0o700)
        misfiled = forged_provider / manifest_path.name
        atomic_json(misfiled, payload)
        with self.assertRaisesRegex(ValueError, "owned location"):
            list_archives(self.paths)
        misfiled.unlink()

        for filters in (
            {"provider": True},
            {"session_id": 1},
            {"archived_on": 20260410},
            {"version": True},
            {"sort": True},
            {"reverse": 1},
        ):
            with self.subTest(filters=filters):
                with self.assertRaisesRegex(ValueError, "archive list"):
                    list_archives(self.paths, **filters)

    def test_archive_listing_locks_and_validates_shared_object_once(self) -> None:
        source = self.write_session("list-shared")
        session = self.plain_session("list-shared", source)
        first = self.archive_session(session, "list-shared-first")
        restore_manifest(self.paths, first["manifest"])
        second = self.archive_session(
            self.plain_session("list-shared", source), "list-shared-second"
        )
        first_manifest = validate_manifest(Path(first["manifest"]))
        shared = first_manifest["files"][0]["object"]
        self.assertEqual(
            shared,
            validate_manifest(Path(second["manifest"]))["files"][0]["object"],
        )

        held = False
        calls: dict[str, int] = {}
        real_safe = archive_module.safe_cas_object_path

        @contextmanager
        def tracking_lock(paths):
            nonlocal held
            self.assertIs(paths, self.paths)
            held = True
            try:
                yield
            finally:
                held = False

        def checked_safe(archive, value, *, kind, **kwargs):
            self.assertTrue(held)
            calls[value] = calls.get(value, 0) + 1
            return real_safe(archive, value, kind=kind, **kwargs)

        with (
            mock.patch.object(archive_module, "app_lock", tracking_lock),
            mock.patch.object(
                archive_module, "safe_cas_object_path", side_effect=checked_safe
            ),
        ):
            entries = list_archives(self.paths)

        self.assertFalse(held)
        self.assertEqual(2, len(entries))
        self.assertEqual(1, calls[shared])

    def test_restore_resolves_only_an_exact_archive_identifier(self) -> None:
        source = self.write_session("exact-version")
        expected = source.read_bytes()
        result = self.archive_session(
            self.plain_session("exact-version", source), "exact-version"
        )
        manifest_path = Path(result["manifest"])

        destination = self.home / "exact-version-restore"
        restored = restore_manifest(self.paths, manifest_path.stem, destination)

        self.assertEqual(1, restored["files"])
        self.assertEqual(expected, (destination / source.name).read_bytes())
        shortened = manifest_path.stem[:-1]
        rejected = self.home / "fuzzy-version-restore"
        with self.assertRaisesRegex(ValueError, "matched 0 entries"):
            restore_manifest(self.paths, shortened, rejected)
        self.assertFalse(rejected.exists())

    def test_restore_provider_date_range_is_inclusive_and_namespaces_versions(
        self,
    ) -> None:
        archived: list[tuple[Path, bytes, str]] = []
        for name, archived_at in (
            ("date-first", "2026-04-10T00:00:00Z"),
            ("date-last", "2026-04-12T23:59:59Z"),
            ("date-outside", "2026-04-13T00:00:00Z"),
        ):
            source = self.write_session(name)
            expected = source.read_bytes()
            result = self.archive_session(
                self.plain_session(name, source), f"{name}-run"
            )
            manifest_path = Path(result["manifest"])
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["archived_at"] = archived_at
            atomic_json(manifest_path, manifest)
            archived.append((manifest_path, expected, source.name))

        destination = self.home / "date-range-restore"
        restored = restore_manifest_set(
            self.paths,
            "claude",
            "2026-04-10",
            "2026-04-12",
            destination,
        )

        self.assertEqual(2, restored["manifests"])
        self.assertEqual(2, restored["files"])
        for manifest_path, expected, name in archived[:2]:
            target = destination / "claude" / manifest_path.stem / name
            self.assertEqual(expected, target.read_bytes())
        excluded = destination / "claude" / archived[2][0].stem / archived[2][2]
        self.assertFalse(excluded.exists())

    def test_restore_provider_date_range_preflights_every_manifest(self) -> None:
        archived: list[tuple[Path, str]] = []
        for name in ("batch-first", "batch-second"):
            source = self.write_session(name)
            result = self.archive_session(
                self.plain_session(name, source), f"{name}-run"
            )
            manifest_path = Path(result["manifest"])
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["archived_at"] = "2026-05-01T12:00:00Z"
            atomic_json(manifest_path, manifest)
            archived.append((manifest_path, source.name))

        destination = self.home / "batch-preflight"
        collision = destination / "claude" / archived[1][0].stem / archived[1][1]
        collision.parent.mkdir(parents=True)
        collision.write_text("occupied", encoding="utf-8")

        with self.assertRaisesRegex(FileExistsError, "destination exists"):
            restore_manifest_set(
                self.paths,
                "claude",
                "2026-05-01",
                "2026-05-01",
                destination,
            )

        first_scope = destination / "claude" / archived[0][0].stem
        self.assertFalse(first_scope.exists())
        self.assertEqual("occupied", collision.read_text(encoding="utf-8"))

    def test_restore_selection_rejects_escapes_and_unsafe_batch_roots(self) -> None:
        source = self.write_session("selection-safety")
        result = self.archive_session(
            self.plain_session("selection-safety", source), "selection-safety"
        )
        manifest_path = Path(result["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["archived_at"] = "2026-06-01T12:00:00Z"
        atomic_json(manifest_path, manifest)

        member_destination = self.home / "selection-member-escape"
        with self.assertRaisesRegex(ValueError, "escaped its root"):
            restore_manifest(
                self.paths,
                result["manifest"],
                member_destination,
                member="../escape",
            )
        self.assertFalse(member_destination.exists())

        outside = self.home / "selection-outside"
        outside.mkdir()
        batch_destination = self.home / "selection-batch-root"
        batch_destination.mkdir()
        (batch_destination / "claude").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(FileExistsError, "not a real directory"):
            restore_manifest_set(
                self.paths,
                "claude",
                "2026-06-01",
                "2026-06-01",
                batch_destination,
            )
        self.assertEqual([], list(outside.iterdir()))

        (batch_destination / "claude").unlink()
        manifest["archive_id"] = "../escape"
        atomic_json(manifest_path, manifest)
        escaped_destination = self.home / "selection-id-escape"
        with self.assertRaisesRegex(ValueError, "safe restore component"):
            restore_manifest_set(
                self.paths,
                "claude",
                "2026-06-01",
                "2026-06-01",
                escaped_destination,
            )
        self.assertFalse(escaped_destination.exists())

    def test_selected_member_restore_rejects_destination_symlink_swap(self) -> None:
        session = self.bundle_session("selected-race")
        result = self.archive_session(session, "selected-race")
        destination = self.home / "selected-race-restore"
        outside = self.home / "selected-race-outside"
        outside.mkdir()
        real_decode = archive_module._decode_restore_member_to
        swapped = False

        def swapping_decode(*args, **kwargs):
            nonlocal swapped
            if not swapped:
                swapped = True
                parent = destination / "selected-race"
                parent.rename(destination / "selected-race-displaced")
                parent.symlink_to(outside, target_is_directory=True)
            return real_decode(*args, **kwargs)

        with mock.patch.object(
            archive_module,
            "_decode_restore_member_to",
            side_effect=swapping_decode,
        ):
            with self.assertRaisesRegex(RuntimeError, "directory binding changed"):
                restore_manifest(
                    self.paths,
                    result["manifest"],
                    destination,
                    member="selected-race/note.txt",
                )

        self.assertEqual([], list(outside.iterdir()))
        self.assertFalse((destination / "selected-race-displaced/note.txt").exists())

    def test_batch_restore_rejects_destination_symlink_swap(self) -> None:
        source = self.write_session("batch-race")
        result = self.archive_session(
            self.plain_session("batch-race", source), "batch-race"
        )
        manifest_path = Path(result["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["archived_at"] = "2026-06-02T12:00:00Z"
        atomic_json(manifest_path, manifest)
        destination = self.home / "batch-race-restore"
        outside = self.home / "batch-race-outside"
        outside.mkdir()
        real_decode = archive_module._decode_restore_member_to
        swapped = False

        def swapping_decode(*args, **kwargs):
            nonlocal swapped
            if not swapped:
                swapped = True
                scoped = destination / "claude" / manifest_path.stem
                scoped.rename(destination / "claude" / "batch-race-displaced")
                scoped.symlink_to(outside, target_is_directory=True)
            return real_decode(*args, **kwargs)

        with mock.patch.object(
            archive_module,
            "_decode_restore_member_to",
            side_effect=swapping_decode,
        ):
            with self.assertRaisesRegex(RuntimeError, "directory binding changed"):
                restore_manifest_set(
                    self.paths,
                    "claude",
                    "2026-06-02",
                    "2026-06-02",
                    destination,
                )

        self.assertEqual([], list(outside.iterdir()))
        self.assertFalse(
            (destination / "claude/batch-race-displaced" / source.name).exists()
        )

    def test_restore_rejects_destination_root_rename_without_foreign_unlink(
        self,
    ) -> None:
        source = self.write_session("root-rename-race")
        expected = source.read_bytes()
        result = self.archive_session(
            self.plain_session("root-rename-race", source),
            "root-rename-race",
        )
        manifest_path = Path(result["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["archived_at"] = "2026-06-03T12:00:00Z"
        atomic_json(manifest_path, manifest)

        cases = (
            (
                "direct",
                self.home / "root-rename-direct",
                lambda destination: restore_manifest(
                    self.paths, str(manifest_path), destination
                ),
            ),
            (
                "batch",
                self.home / "root-rename-batch" / "claude" / manifest_path.stem,
                lambda destination: restore_manifest_set(
                    self.paths,
                    "claude",
                    "2026-06-03",
                    "2026-06-03",
                    destination.parent.parent,
                ),
            ),
        )
        real_validate = archive_module._validate_restore_links
        for name, scoped_root, restore in cases:
            with self.subTest(name=name):
                outside = self.home / f"root-rename-{name}-outside"
                outside.mkdir()
                displaced = outside / "displaced"
                calls = 0

                def rename_after_validation(root, links):
                    nonlocal calls
                    calls += 1
                    result = real_validate(root, links)
                    if calls == 2:
                        scoped_root.rename(displaced)
                    return result

                with mock.patch.object(
                    archive_module,
                    "_validate_restore_links",
                    side_effect=rename_after_validation,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "directory binding changed"
                    ):
                        restore(scoped_root)

                self.assertEqual(expected, (displaced / source.name).read_bytes())

    def test_restore_preserves_foreign_target_after_directory_binding_drift(
        self,
    ) -> None:
        source = self.write_session("foreign-target-race")
        result = self.archive_session(
            self.plain_session("foreign-target-race", source),
            "foreign-target-race",
        )
        destination = self.home / "foreign-target-restore"
        displaced = self.home / "foreign-target-displaced"
        foreign = b"foreign concurrent replacement"
        calls = 0
        real_validate = archive_module._validate_restore_links

        def replace_after_publication(root, links):
            nonlocal calls
            calls += 1
            if calls == 3:
                target = displaced / source.name
                target.unlink()
                target.write_bytes(foreign)
            result = real_validate(root, links)
            if calls == 2:
                destination.rename(displaced)
            return result

        with mock.patch.object(
            archive_module,
            "_validate_restore_links",
            side_effect=replace_after_publication,
        ):
            with self.assertRaisesRegex(RuntimeError, "directory binding changed"):
                restore_manifest(self.paths, result["manifest"], destination)

        self.assertEqual(foreign, (displaced / source.name).read_bytes())

    def test_restore_rejects_replaced_temporary_file_without_foreign_unlink(
        self,
    ) -> None:
        source = self.write_session("foreign-temp-race")
        result = self.archive_session(
            self.plain_session("foreign-temp-race", source),
            "foreign-temp-race",
        )
        destination = self.home / "foreign-temp-restore"
        foreign = b"foreign temporary replacement"
        real_link = archive_module._link_restore_temp

        def replacing_link(parent_fd, source_name, target_name):
            os.unlink(source_name, dir_fd=parent_fd)
            foreign_fd = os.open(
                source_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_fd,
            )
            with os.fdopen(foreign_fd, "wb") as handle:
                handle.write(foreign)
                handle.flush()
                os.fsync(handle.fileno())
            return real_link(parent_fd, source_name, target_name)

        with mock.patch.object(
            archive_module, "_link_restore_temp", side_effect=replacing_link
        ):
            with self.assertRaisesRegex(RuntimeError, "published identity changed"):
                restore_manifest(self.paths, result["manifest"], destination)

        self.assertEqual(foreign, (destination / source.name).read_bytes())
        temporary = list(destination.glob(f".{source.name}.*.restore"))
        self.assertEqual(1, len(temporary))
        self.assertEqual(foreign, temporary[0].read_bytes())

    def test_restore_rejects_same_inode_temporary_content_mutation(self) -> None:
        source = self.write_session("same-inode-temp-race")
        result = self.archive_session(
            self.plain_session("same-inode-temp-race", source),
            "same-inode-temp-race",
        )
        destination = self.home / "same-inode-temp-restore"
        foreign = b"same inode, changed content"
        real_link = archive_module._link_restore_temp

        def mutate_after_link(parent_fd, source_name, target_name):
            real_link(parent_fd, source_name, target_name)
            foreign_fd = os.open(
                source_name,
                os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            with os.fdopen(foreign_fd, "wb") as handle:
                handle.write(foreign)
                handle.flush()
                os.fsync(handle.fileno())

        with mock.patch.object(
            archive_module,
            "_link_restore_temp",
            side_effect=mutate_after_link,
        ):
            with self.assertRaisesRegex(RuntimeError, "retained content changed"):
                restore_manifest(self.paths, result["manifest"], destination)

        target = destination / source.name
        self.assertEqual(foreign, target.read_bytes())
        temporary = list(destination.glob(f".{source.name}.*.restore"))
        self.assertEqual(1, len(temporary))
        self.assertEqual(foreign, temporary[0].read_bytes())

    def test_restore_preserves_temp_replacement_during_file_fsync(self) -> None:
        source = self.write_session("temp-cleanup-race")
        expected = source.read_bytes()
        result = self.archive_session(
            self.plain_session("temp-cleanup-race", source),
            "temp-cleanup-race",
        )
        destination = self.home / "temp-cleanup-restore"
        foreign = b"foreign replacement during file fsync"
        real_fsync = archive_module._fsync_restore_temp

        def replace_after_fsync(fd):
            real_fsync(fd)
            temporary = next(destination.glob(f".{source.name}.*.restore"))
            temporary.unlink()
            temporary.write_bytes(foreign)

        with mock.patch.object(
            archive_module,
            "_fsync_restore_temp",
            side_effect=replace_after_fsync,
        ):
            restored = restore_manifest(self.paths, result["manifest"], destination)

        self.assertEqual(1, restored["files"])
        self.assertEqual(expected, (destination / source.name).read_bytes())
        temporary = list(destination.glob(f".{source.name}.*.restore"))
        self.assertEqual(1, len(temporary))
        self.assertEqual(foreign, temporary[0].read_bytes())

    def test_restore_binds_store_owned_manifest_payload_to_location(self) -> None:
        source = self.write_session("owned-location")
        expected = source.read_bytes()
        result = self.archive_session(
            self.plain_session("owned-location", source), "owned-location"
        )
        manifest_path = Path(result["manifest"])
        original = json.loads(manifest_path.read_text(encoding="utf-8"))

        for field, value in (
            ("provider", "codex"),
            ("archive_id", f"{original['archive_id']}-other"),
        ):
            with self.subTest(field=field):
                changed = {**original, field: value}
                atomic_json(manifest_path, changed)
                destination = self.home / f"owned-location-{field}"
                with self.assertRaisesRegex(ValueError, "owned location"):
                    restore_manifest(self.paths, str(manifest_path), destination)
                self.assertFalse(destination.exists())

        atomic_json(manifest_path, original)
        outside = self.home / "owned-location-symlink.json"
        atomic_json(outside, original)
        manifest_path.unlink()
        manifest_path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            restore_manifest(
                self.paths,
                str(manifest_path),
                self.home / "owned-location-symlink-restore",
            )

        external = self.home / "external-manifest.json"
        external_payload = {
            **original,
            "provider": "external-provider",
            "archive_id": "external-identifier",
        }
        atomic_json(external, external_payload)
        destination = self.home / "external-location-restore"
        restored = restore_manifest(self.paths, str(external), destination)
        self.assertEqual(1, restored["files"])
        self.assertEqual(expected, (destination / source.name).read_bytes())

    def test_restore_rejects_manifest_drift_after_snapshot_verification(self) -> None:
        source = self.write_session("manifest-drift")
        result = self.archive_session(
            self.plain_session("manifest-drift", source), "manifest-drift"
        )
        manifest_path = Path(result["manifest"])
        destination = self.home / "manifest-drift-restore"
        real_verify = archive_module._verify_validated_manifest

        def drifting_verify(paths, path, manifest):
            verified = real_verify(paths, path, manifest)
            changed = json.loads(path.read_text(encoding="utf-8"))
            changed["session_id"] = "changed-after-verification"
            atomic_json(path, changed)
            return verified

        with mock.patch.object(
            archive_module,
            "_verify_validated_manifest",
            side_effect=drifting_verify,
        ):
            with self.assertRaisesRegex(RuntimeError, "changed after selection"):
                restore_manifest(self.paths, str(manifest_path), destination)

        self.assertFalse(destination.exists())

    def test_restore_rejects_manifest_drift_during_namespace_preflight(self) -> None:
        source = self.write_session("preflight-manifest-drift")
        result = self.archive_session(
            self.plain_session("preflight-manifest-drift", source),
            "preflight-manifest-drift",
        )
        manifest_path = Path(result["manifest"])
        original = json.loads(manifest_path.read_text(encoding="utf-8"))
        original["archived_at"] = "2026-06-04T12:00:00Z"
        atomic_json(manifest_path, original)

        cases = (
            (
                "direct",
                self.home / "preflight-drift-direct",
                lambda destination: restore_manifest(
                    self.paths, str(manifest_path), destination
                ),
            ),
            (
                "batch",
                self.home / "preflight-drift-batch",
                lambda destination: restore_manifest_set(
                    self.paths,
                    "claude",
                    "2026-06-04",
                    "2026-06-04",
                    destination,
                ),
            ),
        )
        real_preflight = archive_module._preflight_restore_namespace
        for name, destination, restore in cases:
            with self.subTest(name=name):
                atomic_json(manifest_path, original)
                changed = False

                def drifting_preflight(root, manifest):
                    nonlocal changed
                    prepared = real_preflight(root, manifest)
                    if not changed:
                        changed = True
                        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
                        payload["session_id"] = f"changed-during-{name}-preflight"
                        atomic_json(manifest_path, payload)
                    return prepared

                with mock.patch.object(
                    archive_module,
                    "_preflight_restore_namespace",
                    side_effect=drifting_preflight,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "changed after selection"
                    ):
                        restore(destination)

                self.assertFalse(destination.exists())

    def test_restore_provider_date_range_rejects_invalid_or_empty_selection(
        self,
    ) -> None:
        destination = self.home / "invalid-date-restore"
        cases = (
            ("2026-1-01", "2026-01-02", "YYYY-MM-DD"),
            ("2026-01-03", "2026-01-02", "after end date"),
            ("2026-01-01", "2026-01-02", "matched no"),
        )
        for date_from, date_to, message in cases:
            with self.subTest(date_from=date_from, date_to=date_to):
                with self.assertRaisesRegex(ValueError, message):
                    restore_manifest_set(
                        self.paths,
                        "claude",
                        date_from,
                        date_to,
                        destination,
                    )
                self.assertFalse(destination.exists())

    def test_recovery_finishes_latest_index_after_publication_failure(self) -> None:
        source = self.write_session("latest-index-recovery")
        session = self.plain_session("latest-index-recovery", source)
        session_key = archive_module._manifest_key(session)

        with mock.patch.object(
            archive_module,
            "_publish_latest_index",
            side_effect=OSError(errno.EIO, "latest index publication failed"),
        ):
            with self.assertRaisesRegex(OSError, "latest index publication failed"):
                self.archive_session(session, "latest-index-recovery")

        manifest_path = next(iter_manifests(self.paths))
        self.assertFalse(source.exists())
        index_path = self.paths.state / "latest" / f"claude-{session_key}.json"
        self.assertFalse(index_path.exists())

        self.assertEqual(
            {"restored": 0, "conflicts": 0}, recover_quarantine(self.paths)
        )
        self.assertEqual(
            manifest_path,
            resolve_latest_manifest(self.paths, "claude", session_key),
        )

    def test_pending_version_blocks_rearchive_before_cas_publication(self) -> None:
        source = self.write_session("pending-version")
        session = self.plain_session("pending-version", source)
        key = archive_module._manifest_key(session)
        pending = self.paths.state / "quarantine" / "older-run" / key
        pending.mkdir(parents=True)
        before = set((self.paths.archive / "objects/sha256").rglob("*"))

        with self.assertRaisesRegex(RuntimeError, "archive recover"):
            self.archive_session(session, "newer-run")

        self.assertTrue(source.exists())
        self.assertEqual(
            before, set((self.paths.archive / "objects/sha256").rglob("*"))
        )

    def test_latest_index_rejects_mismatched_target(self) -> None:
        source = self.write_session("latest-mismatch")
        session = self.plain_session("latest-mismatch", source)
        session_key = archive_module._manifest_key(session)
        self.archive_session(session, "latest-mismatch")
        index = self.paths.state / "latest" / f"claude-{session_key}.json"
        payload = json.loads(index.read_text(encoding="utf-8"))
        payload["manifest"] = "manifests/claude/not-the-version.json"
        atomic_json(index, payload)

        expected = next(iter_manifests(self.paths))
        self.assertEqual(
            expected,
            resolve_latest_manifest(self.paths, "claude", session_key),
        )
        repaired = json.loads(index.read_text(encoding="utf-8"))
        self.assertEqual(
            str(expected.relative_to(self.paths.archive)), repaired["manifest"]
        )

    def test_legacy_manifest_rebuilds_latest_index(self) -> None:
        source = self.write_session("legacy-latest")
        session = self.plain_session("legacy-latest", source)
        result = self.archive_session(session, "legacy-latest")
        version_path = Path(result["manifest"])
        manifest = json.loads(version_path.read_text(encoding="utf-8"))
        key = archive_module._manifest_key(manifest)
        legacy_path = version_path.with_name(f"{key}.json")
        manifest["archive_id"] = key
        atomic_json(legacy_path, manifest)
        version_path.unlink()
        index = self.paths.state / "latest" / f"claude-{key}.json"
        index.unlink()

        self.assertEqual(
            legacy_path,
            resolve_latest_manifest(self.paths, "claude", key),
        )
        self.assertEqual({"manifests": 1, "files": 1}, verify_all(self.paths))

    def test_archive_version_overflow_fails_before_source_or_cas_mutation(self) -> None:
        source = self.write_session("version-overflow")
        session = self.plain_session("version-overflow", source)
        key = archive_module._manifest_key(session)
        provider = self.paths.archive / "manifests/claude"
        provider.mkdir(parents=True, exist_ok=True)
        seed = {
            "schema_version": 1,
            "kind": "session-archive",
            "archive_id": f"{key}-v9999999999999999-{'f' * 32}",
            "provider": "claude",
            "session_id": session["session_id"],
            "source_root": session["source_root"],
            "last_activity": session["last_activity"],
            "archived_at": "2020-01-01T00:00:00Z",
            "zstd_version": "fixture",
            "files": [{"relative": source.name}],
            "directories": [],
        }
        # Allocation reads only the identity fields before rejecting exhaustion.
        atomic_json(provider / f"{seed['archive_id']}.json", seed)
        before = set((self.paths.archive / "objects/sha256").rglob("*"))

        with mock.patch.object(archive_module, "validate_manifest", return_value=seed):
            with self.assertRaisesRegex(OverflowError, "version space"):
                self.archive_session(session, "version-overflow")

        self.assertTrue(source.exists())
        self.assertEqual(
            before, set((self.paths.archive / "objects/sha256").rglob("*"))
        )
        self.assertFalse(
            any((self.paths.state / "quarantine/version-overflow").iterdir())
        )

    def test_restore_syncs_nested_empty_directory_metadata(self) -> None:
        source = self.write_session("restore-directory-sync")
        session = self.plain_session("restore-directory-sync", source)
        result = self.archive_session(session, "restore-directory-sync")
        manifest_path = Path(result["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        fixed_mtime_ns = 1_600_000_000_123_456_789
        manifest["directories"] = [
            {
                "path": str(self.project / relative),
                "relative": relative,
                "device": self.project.stat().st_dev,
                "inode": self.project.stat().st_ino,
                "mode": 0o750,
                "mtime_ns": fixed_mtime_ns,
            }
            for relative in ("nested", "nested/empty")
        ]
        atomic_json(manifest_path, manifest)
        destination = (self.home / "restore-directory-sync").resolve()
        synced = []
        real_fsync_directory = archive_module._fsync_restore_directory

        def tracking_sync(fd):
            info = os.fstat(fd)
            synced.append((info.st_dev, info.st_ino))
            return real_fsync_directory(fd)

        with mock.patch.object(
            archive_module,
            "_fsync_restore_directory",
            side_effect=tracking_sync,
        ):
            restore_manifest(self.paths, str(manifest_path), destination)

        for relative in ("nested", "nested/empty"):
            target = destination / relative
            parent_info = target.parent.stat()
            target_info = target.stat()
            self.assertIn((parent_info.st_dev, parent_info.st_ino), synced)
            self.assertIn((target_info.st_dev, target_info.st_ino), synced)
            self.assertEqual(0o750, target.stat().st_mode & 0o777)
            self.assertEqual(fixed_mtime_ns, target.stat().st_mtime_ns)

    def test_invalid_archive_canary_marker_reruns_proof(self) -> None:
        self.paths.ensure_private()
        marker = self.paths.state / "archive-canary.json"
        zstd = _zstd_binary()
        archive_module._ensure_archive_canary(self.paths, zstd)
        payload = json.loads(marker.read_text(encoding="utf-8"))
        payload["archive_sha256"] = "0" * 64
        atomic_json(marker, payload)

        with mock.patch.object(
            archive_module,
            "_ensure_object",
            wraps=archive_module._ensure_object,
        ) as ensure_object:
            archive_module._ensure_archive_canary(self.paths, zstd)

        ensure_object.assert_called_once()
        payload = json.loads(marker.read_text(encoding="utf-8"))
        self.assertEqual("archive-restore-canary", payload["kind"])
        self.assertEqual(archive_module._CANARY_PROTOCOL, payload["protocol"])
        codec = Path(zstd).resolve(strict=True)
        self.assertEqual(str(codec), payload["codec_path"])
        self.assertEqual(sha256_file(codec), payload["codec_sha256"])
        self.assertEqual(
            sha256_file(Path(archive_module.__file__).resolve(strict=True)),
            payload["archive_sha256"],
        )

        for key, value in (("protocol", True), ("schema_version", 2.0)):
            with self.subTest(key=key):
                forged = dict(payload)
                forged[key] = value
                atomic_json(marker, forged)
                with mock.patch.object(
                    archive_module,
                    "_ensure_object",
                    wraps=archive_module._ensure_object,
                ) as ensure_object:
                    archive_module._ensure_archive_canary(self.paths, zstd)
                ensure_object.assert_called_once()

    def test_archive_canary_never_trusts_non_regular_marker(self) -> None:
        self.paths.ensure_private()
        marker = self.paths.state / "archive-canary.json"
        outside = self.home / "outside.json"
        atomic_json(outside, {"kind": "archive-restore-canary"})
        marker.symlink_to(outside)

        with mock.patch.object(
            archive_module,
            "_ensure_object",
            wraps=archive_module._ensure_object,
        ) as ensure_object:
            archive_module._ensure_archive_canary(self.paths, _zstd_binary())

        ensure_object.assert_called_once()
        self.assertFalse(marker.is_symlink())
        self.assertEqual(
            {"kind": "archive-restore-canary"},
            json.loads(outside.read_text(encoding="utf-8")),
        )

        marker.unlink()
        marker.mkdir()
        with mock.patch.object(
            archive_module,
            "_ensure_object",
            wraps=archive_module._ensure_object,
        ) as ensure_object:
            with self.assertRaisesRegex(
                RuntimeError, "canary failed; source removal was blocked"
            ):
                archive_module._ensure_archive_canary(self.paths, _zstd_binary())
        ensure_object.assert_called_once()
        self.assertTrue(marker.is_dir())

    def test_archive_canary_rejects_unsafe_exact_marker(self) -> None:
        self.paths.ensure_private()
        marker = self.paths.state / "archive-canary.json"
        archive_module._ensure_archive_canary(self.paths, _zstd_binary())
        outside = self.home / "copied-canary.json"
        marker.rename(outside)
        os.link(outside, marker)

        with mock.patch.object(
            archive_module,
            "_ensure_object",
            wraps=archive_module._ensure_object,
        ) as ensure_object:
            archive_module._ensure_archive_canary(self.paths, _zstd_binary())

        ensure_object.assert_called_once()
        info = marker.lstat()
        self.assertEqual(1, info.st_nlink)
        self.assertEqual(0o600, info.st_mode & 0o777)
        self.assertEqual(1, outside.stat().st_nlink)
        self.assertEqual(0o600, outside.stat().st_mode & 0o777)

        marker.chmod(0o666)
        with mock.patch.object(
            archive_module,
            "_ensure_object",
            wraps=archive_module._ensure_object,
        ) as ensure_object:
            archive_module._ensure_archive_canary(self.paths, _zstd_binary())

        ensure_object.assert_called_once()
        self.assertEqual(0o600, marker.stat().st_mode & 0o777)
        self.assertEqual(0o600, outside.stat().st_mode & 0o777)

    def test_direct_archive_transaction_acquires_application_lock(self) -> None:
        session = self.bundle_session("direct-lock")
        events = []

        @contextmanager
        def tracking_lock(paths):
            self.assertEqual(self.paths, paths)
            events.append("enter")
            yield
            events.append("exit")

        with mock.patch.object(archive_module, "app_lock", tracking_lock):
            self.archive_session(session, "direct-lock")

        self.assertEqual(["enter", "exit"], events)

    def test_recent_and_malformed_sessions_are_preserved(self) -> None:
        recent = self.write_session("recent", "2026-07-11T00:00:00Z")
        malformed = self.project / "bad.jsonl"
        malformed.write_text(
            '{"timestamp":"2020-01-01T00:00:00Z"}\nnot-json\n', encoding="utf-8"
        )
        _, plan = create_archive_plan(self.paths, datetime(2026, 7, 12, tzinfo=UTC))
        self.assertEqual([], plan["sessions"])
        self.assertTrue(recent.exists())
        self.assertTrue(malformed.exists())
        self.assertGreaterEqual(plan["skipped"].get("recent", 0), 1)

    def test_generic_archive_excludes_observer_sessions(self) -> None:
        observer = ClaudeMemPaths.discover(self.paths, environ={}).observer_project
        observer.mkdir(parents=True)
        source = observer / "12345678-1234-1234-1234-123456789abc.jsonl"
        source.write_text('{"timestamp":"2020-01-01T00:00:00Z"}\n', encoding="utf-8")

        _, plan = create_archive_plan(self.paths, utc_now())

        self.assertEqual([], plan["sessions"])
        self.assertTrue(source.exists())

    def test_malformed_later_plan_entry_causes_zero_mutation(self) -> None:
        first = self.write_session("session-first")
        second = self.write_session("session-second")
        plan_path, plan = create_archive_plan(self.paths, utc_now())
        plan["sessions"][1]["files"][0]["size"] = "invalid"
        atomic_json(plan_path, plan)

        with self.assertRaisesRegex(ValueError, "identity is invalid"):
            apply_archive_plan(self.paths, plan_path)

        self.assertTrue(first.exists())
        self.assertTrue(second.exists())
        self.assertEqual([], list((self.paths.archive / "manifests").rglob("*.json")))

    def test_archive_planned_session_rolls_back_system_exit_during_partial_moves(
        self,
    ) -> None:
        self.paths.ensure_private()
        session = self.bundle_session("system-exit")
        second_source = Path(session["files"][1]["path"])
        real_replace = archive_module.os.replace
        patcher = None

        def faulting_replace(src, dst, *args, **kwargs):
            if Path(src) == second_source:
                raise SystemExit("move crash")
            return real_replace(src, dst, *args, **kwargs)

        def before_move() -> None:
            nonlocal patcher
            patcher = mock.patch.object(
                archive_module.os, "replace", side_effect=faulting_replace
            )
            patcher.start()

        try:
            with self.assertRaises(SystemExit):
                archive_planned_session(
                    self.paths,
                    session,
                    zstd=_zstd_binary(),
                    quarantine_run=self.paths.state / "quarantine" / "system-exit",
                    before_move=before_move,
                )
        finally:
            if patcher is not None:
                patcher.stop()

        for member in session["files"]:
            self.assertTrue(Path(member["path"]).is_file())
        self.assertEqual(
            {"restored": 0, "conflicts": 0}, recover_quarantine(self.paths)
        )
        self.assertEqual([], list(iter_manifests(self.paths)))

    def test_recover_finalizes_post_publication_partial_cleanup(self) -> None:
        source = self.write_session("published-cleanup")
        session = self.plain_session("published-cleanup", source)
        crashed = self.post_publish_crash(
            session, "published-cleanup", delete_payload=True
        )

        self.assertFalse(source.exists())
        self.assertTrue(crashed["manifest"].is_file())
        result = recover_quarantine(self.paths)
        self.assertEqual({"restored": 0, "conflicts": 0}, result)
        self.assertFalse(crashed["item_root"].exists())
        self.assertEqual({"manifests": 1, "files": 1}, verify_all(self.paths))

    def test_recover_accepts_published_manifest_with_exact_rolled_back_source(
        self,
    ) -> None:
        source = self.write_session("published-rolled-back")
        session = self.plain_session("published-rolled-back", source)
        crashed = self.post_publish_crash(
            session, "published-rolled-back", delete_payload=False
        )
        quarantined = crashed["item_root"] / "files" / session["files"][0]["relative"]
        source.parent.mkdir(parents=True, exist_ok=True)
        os.replace(quarantined, source)
        shutil.rmtree(crashed["item_root"] / "files")

        self.assertEqual(
            {"restored": 0, "conflicts": 0}, recover_quarantine(self.paths)
        )
        self.assertTrue(source.is_file())
        self.assertFalse(crashed["item_root"].exists())

    def test_recover_missing_payload_requires_matching_published_manifest(self) -> None:
        source = self.write_session("published-mismatch")
        session = self.plain_session("published-mismatch", source)
        crashed = self.post_publish_crash(
            session, "published-mismatch", delete_payload=True
        )
        manifest = json.loads(crashed["manifest"].read_text(encoding="utf-8"))
        manifest["session_id"] = "forged"
        atomic_json(crashed["manifest"], manifest)

        with self.assertRaisesRegex(ValueError, "missing from source and quarantine"):
            recover_quarantine(self.paths)

        self.assertTrue(crashed["item_root"].exists())

    def test_recover_rejects_escaping_and_absolute_relatives(self) -> None:
        for run, invalid in (
            ("empty", ""),
            ("escaping", "../escaped"),
            ("absolute", str(self.home / "escaped")),
        ):
            with self.subTest(relative=invalid):
                staged = self.stage_recovery_item(run)
                journal = json.loads(staged["record"].read_text(encoding="utf-8"))
                manifest = json.loads(staged["staged"].read_text(encoding="utf-8"))
                journal["files"] = [invalid]
                manifest["files"][0]["relative"] = invalid
                manifest["files"][0]["path"] = str(staged["source_root"] / invalid)
                atomic_json(staged["record"], journal)
                atomic_json(staged["staged"], manifest)

                with self.assertRaisesRegex(
                    ValueError, "(relative path|escaped its source root)"
                ):
                    recover_quarantine(self.paths)

                self.assertTrue(staged["quarantined"].is_file())
                self.assertFalse((self.home / "escaped").exists())
                shutil.rmtree(staged["item_root"].parent)

    def test_recover_rejects_unbound_journal_and_forged_archive_key(self) -> None:
        staged = self.stage_recovery_item("relative-manifest")
        journal = json.loads(staged["record"].read_text(encoding="utf-8"))
        journal["manifest"] = "manifest.json"
        atomic_json(staged["record"], journal)

        with self.assertRaisesRegex(ValueError, "not bound"):
            recover_quarantine(self.paths)

        self.assertTrue(staged["quarantined"].is_file())
        self.assertFalse(staged["source"].exists())
        shutil.rmtree(staged["item_root"].parent)

        staged = self.stage_recovery_item("forged-key")
        manifest = json.loads(staged["staged"].read_text(encoding="utf-8"))
        manifest["session_id"] = "forged"
        atomic_json(staged["staged"], manifest)

        with self.assertRaisesRegex(ValueError, "archive id"):
            recover_quarantine(self.paths)

    def test_recover_rejects_duplicate_file_and_directory_destination(self) -> None:
        staged = self.stage_recovery_item("duplicate")
        journal = json.loads(staged["record"].read_text(encoding="utf-8"))
        manifest = json.loads(staged["staged"].read_text(encoding="utf-8"))
        duplicate = dict(manifest["files"][0])
        manifest["directories"] = [duplicate]
        journal["directories"] = [duplicate["relative"]]
        atomic_json(staged["record"], journal)
        atomic_json(staged["staged"], manifest)

        with self.assertRaisesRegex(ValueError, "duplicate"):
            recover_quarantine(self.paths)

        self.assertTrue(staged["quarantined"].is_file())
        self.assertFalse(staged["source"].exists())

    def test_recover_rejects_destination_symlink_escape(self) -> None:
        staged = self.stage_recovery_item("destination-symlink")
        outside = self.home / "outside"
        outside.mkdir()
        staged["source"].parent.rmdir()
        staged["source"].parent.symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "not a real directory"):
            recover_quarantine(self.paths)

        self.assertTrue(staged["quarantined"].is_file())
        self.assertFalse((outside / staged["source"].name).exists())

    def test_recover_rejects_symlinked_quarantine_member(self) -> None:
        staged = self.stage_recovery_item("quarantine-symlink")
        outside = self.home / "outside-payload"
        outside.write_text("payload", encoding="utf-8")
        staged["quarantined"].unlink()
        staged["quarantined"].symlink_to(outside)

        with self.assertRaisesRegex(ValueError, "not regular"):
            recover_quarantine(self.paths)

        self.assertFalse(staged["source"].exists())
        self.assertEqual("payload", outside.read_text(encoding="utf-8"))

    def test_recover_rejects_symlinked_journal_and_staged_manifest(self) -> None:
        for run, key in (("journal-symlink", "record"), ("manifest-symlink", "staged")):
            with self.subTest(input=key):
                staged = self.stage_recovery_item(run)
                path = staged[key]
                payload = json.loads(path.read_text(encoding="utf-8"))
                external = self.home / f"{run}.json"
                atomic_json(external, payload)
                path.unlink()
                path.symlink_to(external)

                with self.assertRaisesRegex(ValueError, "not a regular file"):
                    recover_quarantine(self.paths)

                self.assertTrue(staged["quarantined"].is_file())
                self.assertFalse(staged["source"].exists())
                path.unlink()
                atomic_json(path, payload)
                self.assertEqual(
                    {"restored": 1, "conflicts": 0}, recover_quarantine(self.paths)
                )

    def test_malformed_later_recovery_journal_causes_zero_mutation(self) -> None:
        first = self.stage_recovery_item("a-first")
        second = self.stage_recovery_item("z-second")
        journal = json.loads(second["record"].read_text(encoding="utf-8"))
        journal["schema_version"] = 99
        atomic_json(second["record"], journal)

        with self.assertRaisesRegex(ValueError, "unsupported recovery journal schema"):
            recover_quarantine(self.paths)

        for staged in (first, second):
            self.assertTrue(staged["quarantined"].is_file())
            self.assertFalse(staged["source"].exists())

    def test_recover_preserves_conflicts_and_completed_moves(self) -> None:
        conflict = self.stage_recovery_item("conflict")
        conflict["source"].write_text("new live data", encoding="utf-8")

        self.assertEqual(
            {"restored": 0, "conflicts": 1}, recover_quarantine(self.paths)
        )
        self.assertEqual(
            "new live data", conflict["source"].read_text(encoding="utf-8")
        )
        self.assertTrue(conflict["quarantined"].is_file())

        conflict["source"].unlink()
        os.replace(conflict["quarantined"], conflict["source"])
        self.assertEqual(
            {"restored": 0, "conflicts": 0}, recover_quarantine(self.paths)
        )
        self.assertFalse(conflict["record"].exists())

    def test_recover_does_not_overwrite_destination_created_after_preflight(
        self,
    ) -> None:
        staged = self.stage_recovery_item("no-clobber-race")
        real_link = archive_module.os.link

        def racing_link(source, destination, *args, **kwargs):
            staged["source"].write_text("new live data", encoding="utf-8")
            return real_link(source, destination, *args, **kwargs)

        with (
            mock.patch.object(archive_module.os, "link", side_effect=racing_link),
            mock.patch.object(archive_module, "_require_recovery_primitives"),
        ):
            self.assertEqual(
                {"restored": 0, "conflicts": 1}, recover_quarantine(self.paths)
            )

        self.assertEqual("new live data", staged["source"].read_text(encoding="utf-8"))
        self.assertTrue(staged["quarantined"].is_file())

    def test_recover_restarts_after_link_before_quarantine_unlink(self) -> None:
        staged = self.stage_recovery_item("linked-restart")
        real_unlink = archive_module.os.unlink

        def crashing_unlink(path, *args, **kwargs):
            if path == staged["quarantined"].name and kwargs.get("dir_fd") is not None:
                raise SystemExit("link published before quarantine unlink")
            return real_unlink(path, *args, **kwargs)

        with (
            mock.patch.object(archive_module.os, "unlink", side_effect=crashing_unlink),
            mock.patch.object(archive_module, "_require_recovery_primitives"),
        ):
            with self.assertRaises(SystemExit):
                recover_quarantine(self.paths)

        self.assertTrue(staged["source"].samefile(staged["quarantined"]))
        self.assertEqual(
            {"restored": 0, "conflicts": 0}, recover_quarantine(self.paths)
        )
        self.assertTrue(staged["source"].is_file())
        self.assertFalse(staged["item_root"].exists())

    def test_recover_retries_destination_fsync_before_quarantine_unlink(self) -> None:
        staged = self.stage_recovery_item("fsync-retry")
        real_fsync = archive_module.os.fsync
        failed = False

        def fail_first_fsync(fd):
            nonlocal failed
            if not failed:
                failed = True
                raise OSError("destination fsync failed")
            return real_fsync(fd)

        with mock.patch.object(
            archive_module.os, "fsync", side_effect=fail_first_fsync
        ):
            with self.assertRaisesRegex(OSError, "destination fsync failed"):
                recover_quarantine(self.paths)

        self.assertTrue(staged["source"].samefile(staged["quarantined"]))
        events = []
        real_unlink = archive_module.os.unlink

        def tracking_fsync(fd):
            events.append("fsync")
            return real_fsync(fd)

        def tracking_unlink(path, *args, **kwargs):
            if path == staged["quarantined"].name:
                events.append("quarantine-unlink")
                self.assertEqual("fsync", events[-2])
            return real_unlink(path, *args, **kwargs)

        with (
            mock.patch.object(archive_module.os, "fsync", side_effect=tracking_fsync),
            mock.patch.object(archive_module.os, "unlink", side_effect=tracking_unlink),
            mock.patch.object(archive_module, "_require_recovery_primitives"),
        ):
            self.assertEqual(
                {"restored": 0, "conflicts": 0}, recover_quarantine(self.paths)
            )

        self.assertIn("quarantine-unlink", events)
        self.assertFalse(staged["item_root"].exists())

    def test_recover_closes_destination_parent_when_quarantine_parent_open_fails(
        self,
    ) -> None:
        staged = self.stage_recovery_item("parent-fd-cleanup")
        files_info = (staged["item_root"] / "files").stat()
        real_open_parent = archive_module._open_recovery_parent
        quarantine_calls = 0

        def failing_open_parent(root_fd, relative, *, create=False, created=None):
            nonlocal quarantine_calls
            info = os.fstat(root_fd)
            if (info.st_dev, info.st_ino) == (files_info.st_dev, files_info.st_ino):
                quarantine_calls += 1
                if quarantine_calls == 2:
                    raise OSError("quarantine parent open failed")
            return real_open_parent(root_fd, relative, create=create, created=created)

        descriptors_before = len(os.listdir("/dev/fd"))
        with mock.patch.object(
            archive_module, "_open_recovery_parent", side_effect=failing_open_parent
        ):
            with self.assertRaisesRegex(OSError, "quarantine parent open failed"):
                recover_quarantine(self.paths)

        self.assertEqual(descriptors_before, len(os.listdir("/dev/fd")))
        self.assertTrue(staged["quarantined"].is_file())
        self.assertFalse(staged["source"].exists())

    def test_recover_cleans_valid_singleton_metadata(self) -> None:
        for run, survivor in (
            ("manifest-singleton", "staged"),
            ("journal-singleton", "record"),
        ):
            with self.subTest(survivor=survivor):
                staged = self.stage_recovery_item(run)
                os.replace(staged["quarantined"], staged["source"])
                shutil.rmtree(staged["item_root"] / "files")
                discarded = "record" if survivor == "staged" else "staged"
                staged[discarded].unlink()

                self.assertEqual(
                    {"restored": 0, "conflicts": 0}, recover_quarantine(self.paths)
                )
                self.assertFalse(staged["item_root"].exists())

    def test_recover_rejects_malformed_singleton_metadata(self) -> None:
        for run, survivor, invalid_schema in (
            ("invalid-json-singleton", "staged", False),
            ("invalid-schema-singleton", "record", True),
        ):
            with self.subTest(survivor=survivor):
                staged = self.stage_recovery_item(run)
                os.replace(staged["quarantined"], staged["source"])
                shutil.rmtree(staged["item_root"] / "files")
                discarded = "record" if survivor == "staged" else "staged"
                staged[discarded].unlink()
                if invalid_schema:
                    payload = json.loads(staged[survivor].read_text(encoding="utf-8"))
                    payload["schema_version"] = 99
                    atomic_json(staged[survivor], payload)
                    expected_error = ValueError
                else:
                    staged[survivor].write_text("{", encoding="utf-8")
                    expected_error = json.JSONDecodeError

                with self.assertRaises(expected_error):
                    recover_quarantine(self.paths)

                self.assertTrue(staged["item_root"].exists())
                shutil.rmtree(staged["item_root"].parent)

    def test_recover_accepts_only_payload_free_atomic_json_temps(self) -> None:
        staged = self.stage_recovery_item("atomic-temp")
        os.replace(staged["quarantined"], staged["source"])
        shutil.rmtree(staged["item_root"] / "files")
        staged["record"].unlink()
        (staged["item_root"] / "._restore.json.abc123_4.tmp").write_text(
            "partial", encoding="utf-8"
        )

        self.assertEqual(
            {"restored": 0, "conflicts": 0}, recover_quarantine(self.paths)
        )
        self.assertFalse(staged["item_root"].exists())

        for run, setup in (
            ("temp-with-payload", "temp"),
            ("files-only", "files"),
            ("near-miss-temp", "near-miss"),
        ):
            with self.subTest(layout=setup):
                staged = self.stage_recovery_item(run)
                if setup == "temp":
                    (staged["item_root"] / "._manifest.json.abc123_4.tmp").touch()
                elif setup == "files":
                    staged["record"].unlink()
                    staged["staged"].unlink()
                else:
                    (staged["item_root"] / "._manifest.json.short.tmp").touch()

                with self.assertRaisesRegex(ValueError, "unknown layout"):
                    recover_quarantine(self.paths)

                self.assertTrue(staged["quarantined"].is_file())
                shutil.rmtree(staged["item_root"].parent)

    def test_recover_rejects_legacy_final_source_root_symlink(self) -> None:
        staged = self.stage_recovery_item(
            "source-root-symlink", source_root_symlink=True
        )
        journal = json.loads(staged["record"].read_text(encoding="utf-8"))
        self.assertNotIn("source_root_identity", journal)

        with self.assertRaisesRegex(ValueError, "must not be a symlink"):
            recover_quarantine(self.paths)

        self.assertTrue(staged["quarantined"].is_file())
        self.assertFalse(staged["source"].exists())
        self.assertTrue(staged["source_root"].is_symlink())

    def test_recover_accepts_identity_bound_final_source_root_symlink(self) -> None:
        actual = self.home / "identity-root-actual"
        actual.mkdir()
        source_root = self.home / "identity-root-link"
        source_root.symlink_to(actual, target_is_directory=True)
        source = source_root / "session.jsonl"
        source.write_text("payload", encoding="utf-8")
        session = {
            "provider": "claude",
            "session_id": "identity-root",
            "source_root": str(source_root),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {
                    "path": str(source),
                    "relative": source.name,
                    **regular_file_stat(source),
                }
            ],
        }
        crashed = self.post_publish_crash(
            session, "identity-root", delete_payload=False
        )

        self.assertEqual(
            {"restored": 0, "conflicts": 0}, recover_quarantine(self.paths)
        )
        self.assertFalse(crashed["item_root"].exists())
        self.assertTrue(source_root.is_symlink())

    def test_recover_accepts_legacy_intermediate_source_root_symlink(self) -> None:
        staged = self.stage_recovery_item(
            "intermediate-root-symlink", source_root_intermediate_symlink=True
        )
        journal = json.loads(staged["record"].read_text(encoding="utf-8"))
        self.assertNotIn("source_root_identity", journal)
        self.assertFalse(staged["source_root"].is_symlink())
        self.assertTrue(staged["source_root"].parent.is_symlink())

        self.assertEqual(
            {"restored": 1, "conflicts": 0}, recover_quarantine(self.paths)
        )
        self.assertTrue(staged["source"].is_file())

    def test_recover_rejects_retargeted_journal_source_root(self) -> None:
        original = self.home / "source-root-original"
        replacement = self.home / "source-root-replacement"
        original.mkdir()
        replacement.mkdir()
        source_root = self.home / "source-root-link"
        source_root.symlink_to(original, target_is_directory=True)
        source = source_root / "session.jsonl"
        source.write_text("payload", encoding="utf-8")
        session = {
            "provider": "claude",
            "session_id": "retargeted-root",
            "source_root": str(source_root),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {
                    "path": str(source),
                    "relative": source.name,
                    **regular_file_stat(source),
                }
            ],
        }
        crashed = self.post_publish_crash(
            session, "retargeted-root", delete_payload=False
        )
        journal = json.loads(
            (crashed["item_root"] / "_restore.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            str(original.resolve()), journal["source_root_identity"]["resolved_path"]
        )
        source_root.unlink()
        source_root.symlink_to(replacement, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "source root identity changed"):
            recover_quarantine(self.paths)

        self.assertTrue((crashed["item_root"] / "files/session.jsonl").is_file())
        self.assertEqual([], list(replacement.iterdir()))

    def test_archive_rejects_provider_traversal(self) -> None:
        source = self.write_session("provider-traversal")
        session = self.plain_session("provider-traversal", source)
        session["provider"] = ".."

        with self.assertRaisesRegex(ValueError, "one path component"):
            archive_planned_session(
                self.paths,
                session,
                zstd="unused",
                quarantine_run=self.paths.state / "quarantine/provider-traversal",
            )

        self.assertTrue(source.is_file())

    def test_archive_refuses_existing_quarantine_until_recover(self) -> None:
        self.paths.ensure_private()
        cas_root = self.paths.archive / "objects"
        for symlink_item in (False, True):
            with self.subTest(symlink_item=symlink_item):
                run = f"existing-item-{'symlink' if symlink_item else 'directory'}"
                staged = self.stage_recovery_item(run)
                preserved_root = staged["item_root"]
                if symlink_item:
                    preserved_root = self.home / f"{run}-target"
                    staged["item_root"].rename(preserved_root)
                    staged["item_root"].symlink_to(
                        preserved_root, target_is_directory=True
                    )
                old_bytes = {
                    path.relative_to(preserved_root): path.read_bytes()
                    for path in preserved_root.rglob("*")
                    if path.is_file()
                }
                old_cas = {
                    path.relative_to(cas_root): path.read_bytes()
                    for path in cas_root.rglob("*")
                    if path.is_file()
                }
                new_source_bytes = b"different live source"
                staged["source"].write_bytes(new_source_bytes)
                old_manifest = json.loads(
                    (preserved_root / "_manifest.json").read_text(encoding="utf-8")
                )
                session = {
                    "provider": old_manifest["provider"],
                    "session_id": old_manifest["session_id"],
                    "source_root": old_manifest["source_root"],
                    "last_activity": old_manifest["last_activity"],
                    "files": [
                        {
                            "path": str(staged["source"]),
                            "relative": old_manifest["files"][0]["relative"],
                            **regular_file_stat(staged["source"]),
                        }
                    ],
                }
                self.assertEqual(
                    staged["item_root"].name, archive_module._manifest_key(session)
                )

                with self.assertRaisesRegex(RuntimeError, "run archive recover"):
                    archive_planned_session(
                        self.paths,
                        session,
                        zstd=_zstd_binary(),
                        quarantine_run=staged["item_root"].parent,
                    )

                self.assertEqual(new_source_bytes, staged["source"].read_bytes())
                self.assertEqual(
                    old_bytes,
                    {
                        path.relative_to(preserved_root): path.read_bytes()
                        for path in preserved_root.rglob("*")
                        if path.is_file()
                    },
                )
                self.assertEqual(
                    old_cas,
                    {
                        path.relative_to(cas_root): path.read_bytes()
                        for path in cas_root.rglob("*")
                        if path.is_file()
                    },
                )
                if symlink_item:
                    self.assertTrue(staged["item_root"].is_symlink())

    def test_recover_removes_empty_runs_and_propagates_other_rmdir_errors(self) -> None:
        self.paths.ensure_private()
        quarantine = self.paths.state / "quarantine"
        empty_run = quarantine / "empty-run"
        empty_run.mkdir(parents=True)

        self.assertEqual(
            {"restored": 0, "conflicts": 0}, recover_quarantine(self.paths)
        )
        self.assertFalse(empty_run.exists())

        blocked_run = quarantine / "blocked-run"
        blocked_run.mkdir()
        real_rmdir = archive_module.os.rmdir

        def blocked_rmdir(path, *args, **kwargs):
            if path == blocked_run.name:
                raise PermissionError("run removal denied")
            return real_rmdir(path, *args, **kwargs)

        with (
            mock.patch.object(archive_module.os, "rmdir", side_effect=blocked_rmdir),
            mock.patch.object(archive_module, "_require_recovery_primitives"),
        ):
            with self.assertRaisesRegex(PermissionError, "run removal denied"):
                recover_quarantine(self.paths)

        self.assertTrue(blocked_run.is_dir())

    def test_recover_rejects_unknown_nonempty_item_layout(self) -> None:
        staged = self.stage_recovery_item("unknown-layout")
        (staged["item_root"] / "surprise.txt").write_text("nope", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "unknown layout"):
            recover_quarantine(self.paths)

    def test_recover_holds_application_lock_around_locked_helper(self) -> None:
        held = False

        @contextmanager
        def fake_lock(paths):
            nonlocal held
            self.assertIs(paths, self.paths)
            held = True
            try:
                yield
            finally:
                held = False

        def fake_recover(paths):
            self.assertIs(paths, self.paths)
            self.assertTrue(held)
            return {"restored": 3, "conflicts": 2}

        with (
            mock.patch.object(archive_module, "app_lock", fake_lock),
            mock.patch.object(
                archive_module,
                "_recover_quarantine_locked",
                side_effect=fake_recover,
            ),
        ):
            self.assertEqual(
                {"restored": 3, "conflicts": 2}, recover_quarantine(self.paths)
            )
        self.assertFalse(held)

    def test_same_stem_codex_rollouts_get_distinct_manifests(self) -> None:
        root = self.home / ".codex/sessions"
        sources = []
        for day in ("2024/01/02", "2024/02/03"):
            directory = root / day
            directory.mkdir(parents=True)
            source = directory / "rollout-duplicate.jsonl"
            source.write_text(
                json.dumps(
                    {
                        "type": "user",
                        "timestamp": "2020-01-01T00:00:00Z",
                        "content": day,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            sources.append(source)

        plan_path, plan = create_archive_plan(self.paths, utc_now())
        self.assertEqual(2, len(plan["sessions"]))
        result = apply_archive_plan(self.paths, plan_path)

        self.assertEqual(2, result["sessions"])
        self.assertEqual(2, len(list(iter_manifests(self.paths))))
        self.assertEqual({"manifests": 2, "files": 2}, verify_all(self.paths))
        for source in sources:
            self.assertFalse(source.exists())

    def test_manifest_records_zstd_version_and_empty_directories(self) -> None:
        self.write_session("versioned")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        apply_archive_plan(self.paths, plan_path)

        manifest = json.loads(
            next(iter_manifests(self.paths)).read_text(encoding="utf-8")
        )
        self.assertIsInstance(manifest["zstd_version"], str)
        self.assertTrue(manifest["zstd_version"])
        self.assertEqual([], manifest["directories"])

    def test_all_providers_scan_nested_files_and_empty_directories(self) -> None:
        primaries = {
            "claude": self.project / "claude-bundle.jsonl",
            "codex": self.home / ".codex/sessions/2020/01/codex-bundle.jsonl",
            "codex-archived": self.home
            / ".codex/archived_sessions/codex-archived-bundle.jsonl",
        }
        expected_mtime_ns = 1_600_000_000_123_456_789
        for primary in primaries.values():
            primary.parent.mkdir(parents=True, exist_ok=True)
            primary.write_text(
                '{"timestamp":"2020-01-01T00:00:00Z"}\n', encoding="utf-8"
            )
            companion = primary.with_suffix("")
            empty = companion / "nested/empty"
            empty.mkdir(parents=True)
            (companion / "nested/events.jsonl").write_text(
                '{"timestamp":"2020-01-01T00:00:00Z"}\n', encoding="utf-8"
            )
            for directory in (companion, companion / "nested", empty):
                os.chmod(directory, 0o750)
                os.utime(directory, ns=(expected_mtime_ns, expected_mtime_ns))

        _, plan = create_archive_plan(self.paths, utc_now())

        self.assertEqual(len(primaries), len(plan["sessions"]))
        sessions = {session["provider"]: session for session in plan["sessions"]}
        self.assertEqual(set(primaries), set(sessions))
        for provider, primary in primaries.items():
            with self.subTest(provider=provider):
                session = sessions[provider]
                self.assertEqual(2, len(session["files"]))
                self.assertEqual(3, len(session["directories"]))
                empty = next(
                    item
                    for item in session["directories"]
                    if item["relative"].endswith("nested/empty")
                )
                self.assertEqual(0o750, empty["mode"])
                self.assertEqual(expected_mtime_ns, empty["mtime_ns"])
                if provider == "codex":
                    self.assertNotIn(
                        str(primary.parent.relative_to(primary.parents[2])),
                        {item["relative"] for item in session["directories"]},
                    )

    def test_all_providers_reject_unsafe_bundle_entries(self) -> None:
        primaries = {
            "claude": self.project / "unsafe-claude.jsonl",
            "codex": self.home / ".codex/sessions/unsafe-codex.jsonl",
            "codex-archived": self.home
            / ".codex/archived_sessions/unsafe-codex-archived.jsonl",
        }
        outside = self.home / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        for index, primary in enumerate(primaries.values()):
            primary.parent.mkdir(parents=True, exist_ok=True)
            primary.write_text(
                '{"timestamp":"2020-01-01T00:00:00Z"}\n', encoding="utf-8"
            )
            companion = primary.with_suffix("")
            companion.mkdir()
            if index == 0:
                (companion / "escape").symlink_to(outside)
            else:
                os.mkfifo(companion / "special")

        with self.assertRaisesRegex(ValueError, "symlink|special"):
            create_archive_plan(self.paths, utc_now())

        self.assertEqual([], list((self.paths.state / "plans").glob("*.json")))
        self.assertEqual("outside", outside.read_text(encoding="utf-8"))
        self.assertTrue(all(primary.exists() for primary in primaries.values()))

    def test_unsafe_claude_bundle_blocks_the_whole_plan(self) -> None:
        safe = self.write_session("a-safe")
        unsafe = self.write_session("z-unsafe")
        companion = unsafe.with_suffix("")
        companion.mkdir()
        os.mkfifo(companion / "special")

        with self.assertRaisesRegex(UnsafeSessionTreeError, "special"):
            create_archive_plan(self.paths, utc_now())

        self.assertTrue(safe.exists())
        self.assertTrue(unsafe.exists())
        self.assertEqual([], list((self.paths.state / "plans").glob("*.json")))

        real_scandir = archive_module.os.scandir

        def deny_companion(path):
            if Path(path).resolve() == companion.resolve():
                raise PermissionError("denied bundle")
            return real_scandir(path)

        (companion / "special").unlink()
        with mock.patch.object(
            archive_module.os, "scandir", side_effect=deny_companion
        ):
            with self.assertRaisesRegex(UnsafeSessionTreeError, "cannot scan"):
                create_archive_plan(self.paths, utc_now())
        self.assertEqual([], list((self.paths.state / "plans").glob("*.json")))

        real_file_stat = archive_module.regular_file_stat

        def changed_primary(path):
            if Path(path).resolve() == unsafe.resolve():
                raise ValueError("source became a symlink")
            return real_file_stat(path)

        with mock.patch.object(
            archive_module, "regular_file_stat", side_effect=changed_primary
        ):
            with self.assertRaisesRegex(UnsafeSessionTreeError, "cannot scan"):
                create_archive_plan(self.paths, utc_now())
        self.assertEqual([], list((self.paths.state / "plans").glob("*.json")))

    def test_apply_rejects_replaced_bundle_directory(self) -> None:
        session = self.bundle_session("directory-identity")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        directory = Path(session["directories"][0]["path"])
        moved = directory.with_name("directory-identity-old")
        directory.rename(moved)
        directory.mkdir()
        os.link(moved / "note.txt", directory / "note.txt")

        with self.assertRaisesRegex(SourceChangedError, "directory changed"):
            apply_archive_plan(self.paths, plan_path)

        self.assertTrue(Path(session["files"][0]["path"]).exists())
        self.assertTrue(directory.exists())
        self.assertTrue((moved / "note.txt").exists())

    def test_provider_discovery_rejects_unsafe_structure_without_partial_plan(
        self,
    ) -> None:
        safe = self.write_session("safe-before-unsafe")
        outside = self.home / "outside-provider"
        outside.mkdir()
        cases = (
            (self.home / ".codex/sessions", lambda path: path.symlink_to(outside)),
            (self.home / ".codex", lambda path: path.symlink_to(outside)),
            (
                self.home / ".codex/archived_sessions/link",
                lambda path: path.symlink_to(outside),
            ),
            (
                self.home / ".claude/projects/linked-project",
                lambda path: path.symlink_to(outside),
            ),
            (self.home / ".codex/sessions/special", os.mkfifo),
        )
        for index, (unsafe, create) in enumerate(cases):
            with self.subTest(index=index):
                if unsafe.is_dir() and not unsafe.is_symlink():
                    shutil.rmtree(unsafe)
                elif unsafe.exists() or unsafe.is_symlink():
                    unsafe.unlink()
                unsafe.parent.mkdir(parents=True, exist_ok=True)
                create(unsafe)
                with self.assertRaisesRegex(ValueError, "unsafe|symlink|special"):
                    create_archive_plan(self.paths, utc_now())
                self.assertTrue(safe.exists())
                self.assertEqual([], list((self.paths.state / "plans").glob("*.json")))
                unsafe.unlink()

    def test_restore_recreates_bundle_directories_with_metadata(self) -> None:
        source = self.write_session("bundled")
        companion = self.project / "bundled"
        nested = companion / "notes"
        empty = nested / "empty"
        empty.mkdir(parents=True)
        fixed_mtime_ns = 1_600_000_000_123_456_789
        for directory in (companion, nested, empty):
            os.chmod(directory, 0o750)
            os.utime(directory, ns=(fixed_mtime_ns, fixed_mtime_ns))

        def directory_entry(path: Path) -> dict:
            return {
                "path": str(path),
                "relative": str(path.relative_to(self.project)),
                **regular_directory_stat(path),
            }

        session = {
            "provider": "claude",
            "session_id": f"{self.project.name}:bundled",
            "source_root": str(self.project),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {
                    "path": str(source),
                    "relative": source.name,
                    **regular_file_stat(source),
                }
            ],
            "directories": [
                directory_entry(path) for path in (companion, nested, empty)
            ],
        }
        self.paths.ensure_private()
        result = archive_planned_session(
            self.paths,
            session,
            zstd=_zstd_binary(),
            quarantine_run=self.paths.state / "quarantine" / "bundle-test",
        )
        self.assertFalse(source.exists())
        self.assertFalse(companion.exists())
        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual(3, len(manifest["directories"]))

        destination = self.home / "restore-bundle"
        restored = restore_manifest(self.paths, result["manifest"], destination)

        self.assertEqual(1, restored["files"])
        self.assertEqual(3, restored["directories"])
        restored_dir = destination / "bundled"
        self.assertTrue((restored_dir / "notes/empty").is_dir())
        self.assertEqual(0o750, restored_dir.stat().st_mode & 0o777)
        self.assertEqual(fixed_mtime_ns, restored_dir.stat().st_mtime_ns)
        self.assertEqual(
            fixed_mtime_ns, (restored_dir / "notes/empty").stat().st_mtime_ns
        )

    def test_apply_fails_closed_when_lsof_is_unavailable(self) -> None:
        source = self.write_session("liveness")
        plan_path, _ = create_archive_plan(self.paths, utc_now())

        with mock.patch.object(common_module, "_lsof_binary", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "lsof was not found"):
                apply_archive_plan(self.paths, plan_path)

        self.assertTrue(source.exists())

    def archive_session(self, session: dict, run: str) -> dict:
        self.paths.ensure_private()
        return archive_planned_session(
            self.paths,
            session,
            zstd=_zstd_binary(),
            quarantine_run=self.paths.state / "quarantine" / run,
        )

    def bundle_session(self, name: str) -> dict:
        source = self.write_session(name)
        companion = self.project / name
        companion.mkdir()
        member = companion / "note.txt"
        member.write_text("companion", encoding="utf-8")
        return {
            "provider": "claude",
            "session_id": f"{self.project.name}:{name}",
            "source_root": str(self.project),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {
                    "path": str(source),
                    "relative": source.name,
                    **regular_file_stat(source),
                },
                {
                    "path": str(member),
                    "relative": f"{name}/note.txt",
                    **regular_file_stat(member),
                },
            ],
            "directories": [
                {
                    "path": str(companion),
                    "relative": name,
                    **regular_directory_stat(companion),
                }
            ],
        }

    def test_private_anchors_preflight_structure_before_creation(self) -> None:
        outside = self.paths.home / "anchor-outside"
        outside.mkdir()
        linked_archive = self.paths.home / "linked-archive"
        linked_archive.symlink_to(outside, target_is_directory=True)
        missing_state = self.paths.home / "missing-state"
        unsafe = AppPaths(self.paths.home, linked_archive, missing_state)

        with self.assertRaisesRegex(ValueError, "symlinked ancestor"):
            unsafe.ensure_private()

        self.assertFalse(missing_state.exists())
        self.assertEqual([], list(outside.iterdir()))

        real_parent = self.paths.home / "real-anchor-parent"
        real_parent.mkdir()
        linked_parent = self.paths.home / "linked-anchor-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        missing_state = self.paths.home / "third-missing-state"
        unsafe = AppPaths(self.paths.home, linked_parent / "archive", missing_state)

        with self.assertRaisesRegex(ValueError, "symlinked ancestor"):
            unsafe.ensure_private()

        self.assertFalse((real_parent / "archive").exists())
        self.assertFalse(missing_state.exists())

        archive = self.paths.home / "fixed-anchor-archive"
        archive.mkdir(mode=0o700)
        manifests_outside = self.paths.home / "manifests-outside"
        manifests_outside.mkdir()
        (archive / "manifests").symlink_to(manifests_outside, target_is_directory=True)
        missing_state = self.paths.home / "second-missing-state"
        unsafe = AppPaths(self.paths.home, archive, missing_state)

        with self.assertRaisesRegex(ValueError, "symlinked ancestor"):
            unsafe.ensure_private()

        self.assertFalse(missing_state.exists())
        self.assertEqual([], list(manifests_outside.iterdir()))
        self.assertFalse((archive / "objects").exists())

    def test_private_anchors_are_canonical_and_private(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"XDG_DATA_HOME": "relative-data", "XDG_STATE_HOME": "relative-state"},
        ):
            with self.assertRaisesRegex(ValueError, "must be absolute"):
                AppPaths.discover()

        archive = self.paths.home / "mode-archive"
        state = self.paths.home / "mode-state"
        archive.mkdir(mode=0o755)
        state.mkdir(mode=0o755)
        (archive / "manifests").mkdir(mode=0o755)
        paths = AppPaths(self.paths.home, archive, state)

        paths.ensure_private()

        anchors = [
            archive,
            state,
            archive / "manifests",
            archive / "dictionaries",
            archive / "objects",
            archive / "objects/sha256",
            state / "plans",
            state / "quarantine",
        ]
        self.assertTrue(
            all(path.is_absolute() and path.resolve() == path for path in anchors)
        )
        if os.name != "nt":
            self.assertTrue(
                all(path.stat().st_mode & 0o777 == 0o700 for path in anchors)
            )

    def test_dynamic_archive_anchors_fail_before_cas_or_source_write(self) -> None:
        self.paths.ensure_private()
        session = self.bundle_session("unsafe-anchor")
        source_paths = [Path(item["path"]) for item in session["files"]]
        outside = self.home / "provider-outside"
        outside.mkdir()
        provider = self.paths.archive / "manifests/claude"
        provider.symlink_to(outside, target_is_directory=True)
        quarantine_run = self.paths.state / "quarantine/provider-anchor"

        with self.assertRaisesRegex(ValueError, "symlinked ancestor"):
            archive_planned_session(
                self.paths,
                session,
                zstd="missing-zstd",
                quarantine_run=quarantine_run,
            )

        self.assertTrue(all(path.exists() for path in source_paths))
        self.assertFalse(quarantine_run.exists())
        self.assertEqual([], list(outside.iterdir()))
        self.assertEqual(
            [],
            [
                path
                for path in (self.paths.archive / "objects/sha256").rglob("*")
                if path.is_file()
            ],
        )

        provider.unlink()
        quarantine_outside = self.home / "quarantine-outside"
        quarantine_outside.mkdir()
        quarantine_run.symlink_to(quarantine_outside, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symlinked ancestor"):
            archive_planned_session(
                self.paths,
                session,
                zstd="missing-zstd",
                quarantine_run=quarantine_run,
            )

        self.assertTrue(all(path.exists() for path in source_paths))
        self.assertFalse(provider.exists())
        self.assertEqual([], list(quarantine_outside.iterdir()))

    def test_direct_manifest_restore_rejects_unsafe_anchor_before_destination_write(
        self,
    ) -> None:
        result = self.archive_session(
            self.bundle_session("restore-anchor"), "restore-anchor-run"
        )
        manifest = Path(result["manifest"])
        outside = self.paths.home / "restore-state-outside"
        outside.mkdir()
        shutil.rmtree(self.paths.state)
        self.paths.state.symlink_to(outside, target_is_directory=True)
        destination = self.paths.home / "restore-anchor-destination"

        with self.assertRaisesRegex(ValueError, "symlinked ancestor"):
            restore_manifest(self.paths, str(manifest), destination)

        self.assertFalse(destination.exists())
        self.assertEqual([], list(outside.iterdir()))

    def test_restore_rejects_escaping_member_relative(self) -> None:
        self.write_session("escape")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        apply_archive_plan(self.paths, plan_path)
        manifest_path = next(iter_manifests(self.paths))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"][0]["relative"] = "../escape.jsonl"
        atomic_json(manifest_path, manifest)

        with self.assertRaisesRegex(ValueError, "escaped its root"):
            restore_manifest(
                self.paths, str(manifest_path), self.home / "restore-escape"
            )

    def test_restore_preflights_later_directory_collision_without_writes(self) -> None:
        result = self.archive_session(
            self.bundle_session("preflight"), "preflight-test"
        )
        destination = self.home / "restore-preflight"
        destination.mkdir()
        sentinel = destination / "keep.txt"
        sentinel.write_text("keep", encoding="utf-8")
        blocking = destination / "preflight"
        blocking.mkdir()
        (blocking / "note.txt").write_text("occupied", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            restore_manifest(self.paths, result["manifest"], destination)

        self.assertFalse((destination / "preflight.jsonl").exists())
        self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))
        self.assertEqual(
            "occupied", (blocking / "note.txt").read_text(encoding="utf-8")
        )

    def test_restore_rejects_duplicate_and_file_parent_targets_without_writes(
        self,
    ) -> None:
        result = self.archive_session(
            self.bundle_session("namespace"), "namespace-test"
        )
        manifest_path = Path(result["manifest"])
        original = json.loads(manifest_path.read_text(encoding="utf-8"))

        def update_relative(manifest: dict, member: dict, relative: str) -> None:
            member.update(
                relative=relative,
                path=str(Path(manifest["source_root"]) / relative),
            )

        cases = {
            "duplicate-file": lambda manifest: manifest["files"].append(
                dict(manifest["files"][0])
            ),
            "duplicate-directory": lambda manifest: manifest["directories"].append(
                dict(manifest["directories"][0])
            ),
            "file-directory": lambda manifest: update_relative(
                manifest,
                manifest["directories"][0],
                manifest["files"][0]["relative"],
            ),
            "file-parent": lambda manifest: update_relative(
                manifest,
                manifest["files"][1],
                f"{manifest['files'][0]['relative']}/child",
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                manifest = json.loads(json.dumps(original))
                mutate(manifest)
                atomic_json(manifest_path, manifest)
                destination = self.home / f"restore-{name}"
                destination.mkdir()
                sentinel = destination / "keep.txt"
                sentinel.write_text(name, encoding="utf-8")

                with self.assertRaisesRegex(ValueError, "duplicate|restore parent"):
                    restore_manifest(self.paths, str(manifest_path), destination)

                self.assertEqual([sentinel], list(destination.iterdir()))
                self.assertEqual(name, sentinel.read_text(encoding="utf-8"))

    def test_restore_rejects_case_and_unicode_namespace_aliases(self) -> None:
        result = self.archive_session(self.bundle_session("aliases"), "aliases-test")
        manifest_path = Path(result["manifest"])
        original = json.loads(manifest_path.read_text(encoding="utf-8"))

        def case_duplicate(manifest: dict) -> None:
            directory = manifest["directories"][0]
            root = Path(manifest["source_root"])
            manifest["directories"] = [
                {**directory, "relative": "Folder", "path": str(root / "Folder")},
                {**directory, "relative": "folder", "path": str(root / "folder")},
            ]

        def unicode_duplicate(manifest: dict) -> None:
            directory = manifest["directories"][0]
            root = Path(manifest["source_root"])
            manifest["directories"] = [
                {**directory, "relative": "Caf\u00e9", "path": str(root / "Caf\u00e9")},
                {
                    **directory,
                    "relative": "Cafe\u0301",
                    "path": str(root / "Cafe\u0301"),
                },
            ]

        def unicode_file_parent(manifest: dict) -> None:
            root = Path(manifest["source_root"])
            manifest["files"][0]["relative"] = "Caf\u00e9"
            manifest["files"][0]["path"] = str(root / "Caf\u00e9")
            manifest["files"][1]["relative"] = "Cafe\u0301/child"
            manifest["files"][1]["path"] = str(root / "Cafe\u0301/child")
            manifest["files"][1]["reference"] = "Caf\u00e9"
            manifest["directories"] = []

        for name, mutate in {
            "case-duplicate": case_duplicate,
            "unicode-duplicate": unicode_duplicate,
            "unicode-file-parent": unicode_file_parent,
        }.items():
            with self.subTest(name=name):
                manifest = json.loads(json.dumps(original))
                mutate(manifest)
                atomic_json(manifest_path, manifest)
                destination = self.home / f"restore-{name}"
                destination.mkdir()
                sentinel = destination / "keep.txt"
                sentinel.write_text(name, encoding="utf-8")

                with self.assertRaisesRegex(ValueError, "duplicate|restore parent"):
                    restore_manifest(self.paths, str(manifest_path), destination)

                self.assertEqual([sentinel], list(destination.iterdir()))

    def test_restore_requires_absolute_default_source_root(self) -> None:
        self.write_session("relative-source-root")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        apply_archive_plan(self.paths, plan_path)
        manifest_path = next(iter_manifests(self.paths))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        relative_root = f".b05-{self.home.name}"
        manifest["source_root"] = relative_root
        atomic_json(manifest_path, manifest)

        with self.assertRaisesRegex(ValueError, "source root must be absolute"):
            restore_manifest(self.paths, str(manifest_path))

        self.assertFalse((Path.cwd() / relative_root).exists())

    def test_restore_rejects_unsafe_existing_parent_components(self) -> None:
        self.write_session("parent-component")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        apply_archive_plan(self.paths, plan_path)
        manifest_path = next(iter_manifests(self.paths))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"][0]["relative"] = "parent/member.jsonl"
        manifest["files"][0]["path"] = str(
            Path(manifest["source_root"]) / "parent/member.jsonl"
        )
        atomic_json(manifest_path, manifest)

        regular_root = self.home / "restore-regular-parent"
        regular_root.mkdir()
        regular_parent = regular_root / "parent"
        regular_parent.write_text("occupied", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            restore_manifest(self.paths, str(manifest_path), regular_root)
        self.assertEqual("occupied", regular_parent.read_text(encoding="utf-8"))

        outside = self.home / "outside-parent"
        outside.mkdir()
        symlink_root = self.home / "restore-symlink-parent"
        symlink_root.mkdir()
        (symlink_root / "parent").symlink_to(outside, target_is_directory=True)
        with self.assertRaises((FileExistsError, ValueError)):
            restore_manifest(self.paths, str(manifest_path), symlink_root)
        self.assertEqual([], list(outside.iterdir()))

        fifo_root = self.home / "restore-fifo-parent"
        fifo_root.mkdir()
        fifo_parent = fifo_root / "parent"
        os.mkfifo(fifo_parent)
        with self.assertRaises(FileExistsError):
            restore_manifest(self.paths, str(manifest_path), fifo_root)
        self.assertTrue(fifo_parent.is_fifo())

    def test_restore_rejects_non_directory_roots_without_writes(self) -> None:
        self.write_session("root-type")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        apply_archive_plan(self.paths, plan_path)
        manifest_path = next(iter_manifests(self.paths))

        file_root = self.home / "restore-file-root"
        file_root.write_text("occupied", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            restore_manifest(self.paths, str(manifest_path), file_root)
        self.assertEqual("occupied", file_root.read_text(encoding="utf-8"))

        outside = self.home / "restore-root-outside"
        outside.mkdir()
        symlink_root = self.home / "restore-symlink-root"
        symlink_root.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            restore_manifest(self.paths, str(manifest_path), symlink_root)
        self.assertEqual([], list(outside.iterdir()))

        fifo_root = self.home / "restore-fifo-root"
        os.mkfifo(fifo_root)
        with self.assertRaises(FileExistsError):
            restore_manifest(self.paths, str(manifest_path), fifo_root)
        self.assertTrue(fifo_root.is_fifo())

    def test_restore_accepts_existing_real_root_and_preserves_unowned_entries(
        self,
    ) -> None:
        source = self.write_session("existing-root")
        expected = source.read_bytes()
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        apply_archive_plan(self.paths, plan_path)
        manifest_path = next(iter_manifests(self.paths))
        destination = self.home / "restore-existing-root"
        destination.mkdir()
        sentinel = destination / "keep.txt"
        sentinel.write_text("keep", encoding="utf-8")

        result = restore_manifest(self.paths, str(manifest_path), destination)

        self.assertEqual(1, result["files"])
        self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))
        self.assertEqual(expected, (destination / source.name).read_bytes())

    def test_false_variant_suffix_fails_closed_without_moving_object(self) -> None:
        payload = "".join(
            json.dumps(
                {
                    "type": "user",
                    "timestamp": "2020-01-01T00:00:00Z",
                    "content": "x" * 5000,
                }
            )
            + "\n"
            for _ in range(3)
        )
        (self.project / "dup-a.jsonl").write_text(payload, encoding="utf-8")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        apply_archive_plan(self.paths, plan_path)

        manifest = json.loads(
            next(iter_manifests(self.paths)).read_text(encoding="utf-8")
        )
        object_path = self.paths.archive / manifest["files"][0]["object"]
        object_path.write_bytes(b"corrupt")
        corrupt_bytes = object_path.read_bytes()

        (self.project / "dup-b.jsonl").write_text(payload, encoding="utf-8")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        with self.assertRaisesRegex(ValueError, "compressed digest mismatch"):
            apply_archive_plan(self.paths, plan_path)

        self.assertEqual(corrupt_bytes, object_path.read_bytes())
        self.assertEqual([], list(object_path.parent.glob("*.corrupt-*")))
        self.assertTrue((self.project / "dup-b.jsonl").exists())

    def test_safe_cas_object_path_enforces_names_shards_and_temp_shape(self) -> None:
        self.paths.ensure_private()
        digest = "a" * 64
        shard = ensure_safe_cas_shard(self.paths.archive, "aa")

        legacy = shard / f"{digest}.zst"
        legacy.write_bytes(b"legacy")
        self.assertEqual(
            legacy,
            safe_cas_object_path(
                self.paths.archive,
                f"objects/sha256/aa/{digest}.zst",
                kind="zstd",
            ),
        )

        variant_payload = b"variant"
        compressed_digest = hashlib.sha256(variant_payload).hexdigest()
        variant = shard / f"{digest}.{compressed_digest}.zst"
        variant.write_bytes(variant_payload)
        self.assertEqual(
            variant,
            safe_cas_object_path(
                self.paths.archive,
                str(variant.relative_to(self.paths.archive)),
                kind="zstd",
            ),
        )

        dictionary = shard / f"{digest}.dict"
        dictionary.write_bytes(b"dictionary")
        self.assertEqual(
            dictionary,
            safe_cas_object_path(
                self.paths.archive,
                str(dictionary.relative_to(self.paths.archive)),
                kind="dictionary",
            ),
        )

        fd, raw_temp = tempfile.mkstemp(prefix=f".{digest}.", suffix=".part", dir=shard)
        os.close(fd)
        crash_temp = Path(raw_temp)
        self.assertEqual(
            crash_temp,
            safe_cas_object_path(
                self.paths.archive,
                str(crash_temp.relative_to(self.paths.archive)),
                kind="temporary",
            ),
        )

        invalid_names = (
            "not-a-cas-object",
            f"{digest}.{'b' * 64}.dict",
            f".{digest}.short.part",
        )
        for name in invalid_names:
            path = shard / name
            path.write_bytes(b"invalid")
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "invalid CAS name"):
                    safe_cas_object_path(
                        self.paths.archive,
                        str(path.relative_to(self.paths.archive)),
                        kind="zstd",
                    )

        wrong_shard = self.paths.archive / "objects/sha256/bb" / f"{digest}.zst"
        wrong_shard.parent.mkdir()
        wrong_shard.write_bytes(b"wrong shard")
        with self.assertRaisesRegex(ValueError, "wrong CAS shard"):
            safe_cas_object_path(
                self.paths.archive,
                str(wrong_shard.relative_to(self.paths.archive)),
                kind="zstd",
            )

    def test_schema_1_and_2_members_reject_dictionary_and_temp_objects(self) -> None:
        source = self.write_session("role-confusion")
        result = self.archive_session(
            self.plain_session("role-confusion", source), "role-confusion-run"
        )
        manifest_path = Path(result["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        member = manifest["files"][0]
        stored = self.paths.archive / member["object"]
        raw_digest = member["raw_sha256"]
        wrong_relatives = (
            f"objects/sha256/{raw_digest[:2]}/{raw_digest}.dict",
            f"objects/sha256/{raw_digest[:2]}/.{raw_digest}.abc12345.part",
        )
        for relative in wrong_relatives:
            (self.paths.archive / relative).write_bytes(stored.read_bytes())

        for schema_version in (1, 2):
            for relative in wrong_relatives:
                with self.subTest(schema_version=schema_version, object=relative):
                    manifest["schema_version"] = schema_version
                    member["object"] = relative
                    atomic_json(manifest_path, manifest)
                    with self.assertRaisesRegex(
                        ValueError, "invalid CAS name for zstd"
                    ):
                        verify_all(self.paths)

    def test_recover_recreates_bundle_directories_with_metadata(self) -> None:
        staged = self.stage_recovery_item(
            "schema-2",
            schema_version=2,
            journal_schema_version=1,
            directories=("bundle/empty",),
        )
        manifest = json.loads(staged["staged"].read_text(encoding="utf-8"))
        expected = manifest["directories"][0]
        result = recover_quarantine(self.paths)
        self.assertEqual({"restored": 1, "conflicts": 0}, result)
        restored = staged["source_root"] / "bundle/empty"
        self.assertTrue(restored.is_dir())
        self.assertEqual(expected["mode"], restored.stat().st_mode & 0o777)
        self.assertEqual(expected["mtime_ns"], restored.stat().st_mtime_ns)

    def test_recover_recreates_fully_removed_nested_directory_chain(self) -> None:
        staged = self.stage_recovery_item(
            "nested-directory-chain", directories=("bundle", "bundle/empty")
        )

        self.assertEqual(
            {"restored": 1, "conflicts": 0}, recover_quarantine(self.paths)
        )
        self.assertTrue((staged["source_root"] / "bundle/empty").is_dir())

    def test_recover_preserves_existing_directory_metadata(self) -> None:
        staged = self.stage_recovery_item(
            "existing-directory", directories=("bundle/empty",)
        )
        existing = staged["source_root"] / "bundle/empty"
        existing.mkdir(parents=True)
        current_mtime_ns = 1_700_000_000_123_456_789
        os.chmod(existing, 0o711)
        os.utime(existing, ns=(current_mtime_ns, current_mtime_ns))

        self.assertEqual(
            {"restored": 1, "conflicts": 0}, recover_quarantine(self.paths)
        )
        self.assertEqual(0o711, existing.stat().st_mode & 0o777)
        self.assertEqual(current_mtime_ns, existing.stat().st_mtime_ns)

    def test_recover_fsyncs_parent_after_final_directory_mkdir(self) -> None:
        staged = self.stage_recovery_item(
            "directory-parent-fsync", directories=("bundle/empty",)
        )
        events = []
        real_mkdir = archive_module.os.mkdir
        real_fsync = archive_module.os.fsync

        def tracking_mkdir(path, *args, **kwargs):
            result = real_mkdir(path, *args, **kwargs)
            if path == "empty":
                events.append("mkdir")
            return result

        def tracking_fsync(fd):
            events.append("fsync")
            return real_fsync(fd)

        with (
            mock.patch.object(archive_module.os, "mkdir", side_effect=tracking_mkdir),
            mock.patch.object(archive_module.os, "fsync", side_effect=tracking_fsync),
            mock.patch.object(archive_module, "_require_recovery_primitives"),
        ):
            self.assertEqual(
                {"restored": 1, "conflicts": 0}, recover_quarantine(self.paths)
            )

        mkdir_index = events.index("mkdir")
        self.assertEqual("fsync", events[mkdir_index + 1])
        self.assertFalse(staged["item_root"].exists())

    def test_recover_preserves_directory_created_during_final_mkdir_race(self) -> None:
        staged = self.stage_recovery_item(
            "directory-mkdir-race", directories=("bundle/empty",)
        )
        target = staged["source_root"] / "bundle/empty"
        current_mtime_ns = 1_710_000_000_123_456_789
        real_mkdir = archive_module.os.mkdir
        injected = False

        def racing_mkdir(path, *args, **kwargs):
            nonlocal injected
            if path == "empty" and not injected:
                injected = True
                real_mkdir(path, *args, **kwargs)
                os.chmod(target, 0o711)
                os.utime(target, ns=(current_mtime_ns, current_mtime_ns))
            return real_mkdir(path, *args, **kwargs)

        with (
            mock.patch.object(archive_module.os, "mkdir", side_effect=racing_mkdir),
            mock.patch.object(archive_module, "_require_recovery_primitives"),
        ):
            self.assertEqual(
                {"restored": 1, "conflicts": 1}, recover_quarantine(self.paths)
            )

        self.assertEqual(0o711, target.stat().st_mode & 0o777)
        self.assertEqual(current_mtime_ns, target.stat().st_mtime_ns)
        self.assertTrue(staged["item_root"].exists())

    def test_archive_rollback_restores_directory_metadata_after_files(self) -> None:
        session = self.bundle_session("rollback-directory-metadata")
        directory = Path(session["directories"][0]["path"])
        expected_mtime_ns = 1_620_000_000_123_456_789
        os.chmod(directory, 0o750)
        os.utime(directory, ns=(expected_mtime_ns, expected_mtime_ns))
        session["directories"][0].update(regular_directory_stat(directory))
        manifest_root = self.paths.archive / "manifests" / session["provider"]
        real_atomic_json = archive_module.atomic_json

        def fail_manifest_publication(path, payload, **kwargs):
            if (
                path.parent == manifest_root
                and payload.get("kind") == "session-archive"
            ):
                raise RuntimeError("manifest publication failed")
            return real_atomic_json(path, payload, **kwargs)

        self.paths.ensure_private()
        with mock.patch.object(
            archive_module, "atomic_json", side_effect=fail_manifest_publication
        ):
            with self.assertRaisesRegex(RuntimeError, "manifest publication failed"):
                archive_planned_session(
                    self.paths,
                    session,
                    zstd=_zstd_binary(),
                    quarantine_run=self.paths.state / "quarantine/rollback-metadata",
                )

        for member in session["files"]:
            self.assertTrue(Path(member["path"]).is_file())
        self.assertEqual(0o750, directory.stat().st_mode & 0o777)
        self.assertEqual(expected_mtime_ns, directory.stat().st_mtime_ns)

    def test_apply_aborts_when_quarantine_device_differs(self) -> None:
        source = self.write_session("device")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        real_stat = os.stat
        resolved_project = self.project.resolve()

        def fake_stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if Path(path) == resolved_project:
                fields = tuple(result)[:10]
                return os.stat_result(
                    (fields[0], fields[1], fields[2] + 1) + fields[3:10]
                )
            return result

        with mock.patch.object(archive_module.os, "stat", side_effect=fake_stat):
            with self.assertRaisesRegex(RuntimeError, "quarantine device differs"):
                apply_archive_plan(self.paths, plan_path)

        self.assertTrue(source.exists())
        self.assertEqual([], list(iter_manifests(self.paths)))

    def test_compression_effort_adapts_to_member_size(self) -> None:
        self.paths.ensure_private()
        archive_module._ensure_archive_canary(self.paths, _zstd_binary())
        sizes = (32 * 1024, 2 * 1024**2, 9 * 1024**2)
        run_calls: list[list[str]] = []
        popen_calls: list[list[str]] = []
        real_run = archive_module.subprocess.run
        real_popen = archive_module.subprocess.Popen

        def tracking_run(args, *run_args, **run_kwargs):
            run_calls.append([str(value) for value in args])
            return real_run(args, *run_args, **run_kwargs)

        def tracking_popen(args, *popen_args, **popen_kwargs):
            popen_calls.append([str(value) for value in args])
            return real_popen(args, *popen_args, **popen_kwargs)

        def single_member_session(name: str, size: int) -> dict:
            source = self.project / f"{name}.jsonl"
            prefix = '{"timestamp":"2020-01-01T00:00:00Z","content":"'
            source.write_text(
                prefix + "x" * (size - len(prefix) - 3) + '"}\n', encoding="utf-8"
            )
            return {
                "provider": "claude",
                "session_id": f"{self.project.name}:{name}",
                "source_root": str(self.project),
                "last_activity": "2020-01-01T00:00:00Z",
                "files": [
                    {
                        "path": str(source),
                        "relative": source.name,
                        **regular_file_stat(source),
                    }
                ],
            }

        with (
            mock.patch.object(
                archive_module.subprocess, "run", side_effect=tracking_run
            ),
            mock.patch.object(
                archive_module.subprocess, "Popen", side_effect=tracking_popen
            ),
        ):
            results = [
                self.archive_session(
                    single_member_session(f"tier-{index}", size), f"tier-{index}"
                )
                for index, size in enumerate(sizes)
            ]

        # The sub-1 MiB member takes the whole-file path; larger members are
        # chunked and compressed through stdin with per-chunk effort.
        whole_file = [
            call for call in run_calls if "-o" in call and "--version" not in call
        ]
        self.assertEqual(1, len(whole_file))
        self.assertIn("-6", whole_file[0])
        chunked = [
            call
            for call in popen_calls
            if all(
                flag not in call for flag in ("-d", "-t", "-o", "--version", "--train")
            )
        ]
        self.assertEqual(2, len(chunked))
        self.assertIn("-12", chunked[0])
        self.assertIn("-19", chunked[1])
        self.assertIn("--long=27", chunked[1])
        self.assertEqual({"manifests": 3, "files": 3}, verify_all(self.paths))

        destination = self.home / "restore-tier"
        restore_manifest(self.paths, results[2]["manifest"], destination)
        self.assertEqual(sizes[2], (destination / "tier-2.jsonl").stat().st_size)

    def test_companion_uses_primary_as_compression_reference(self) -> None:
        blocks = b"".join(
            hashlib.sha256(f"block-{index}".encode()).digest() for index in range(2048)
        )
        primary = self.project / "ref-bundle.jsonl"
        primary.write_bytes(blocks)
        companion_dir = self.project / "ref-bundle"
        companion_dir.mkdir()
        companion = companion_dir / "copy.bin"
        companion_bytes = blocks + b"unique-suffix"
        companion.write_bytes(companion_bytes)
        session = {
            "provider": "claude",
            "session_id": f"{self.project.name}:ref-bundle",
            "source_root": str(self.project),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {
                    "path": str(primary),
                    "relative": primary.name,
                    **regular_file_stat(primary),
                },
                {
                    "path": str(companion),
                    "relative": "ref-bundle/copy.bin",
                    **regular_file_stat(companion),
                },
            ],
            "directories": [
                {
                    "path": str(companion_dir),
                    "relative": "ref-bundle",
                    **regular_directory_stat(companion_dir),
                }
            ],
        }

        result = self.archive_session(session, "ref-bundle-run")

        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        entry = manifest["files"][1]
        self.assertEqual("ref-bundle.jsonl", entry["reference"])
        referenced_size = (self.paths.archive / entry["object"]).stat().st_size
        standalone_size = (
            (self.paths.archive / manifest["files"][0]["object"]).stat().st_size
        )
        self.assertLess(referenced_size, standalone_size // 4)

        destination = self.home / "restore-ref"
        restore_manifest(self.paths, result["manifest"], destination)
        self.assertEqual(
            hashlib.sha256(companion_bytes).hexdigest(),
            sha256_file(destination / "ref-bundle/copy.bin"),
        )
        self.assertEqual(
            hashlib.sha256(blocks).hexdigest(),
            sha256_file(destination / "ref-bundle.jsonl"),
        )

    def test_restore_selects_one_exact_member_with_internal_reference(self) -> None:
        session = self.bundle_session("selected-member")
        expected = Path(session["files"][1]["path"]).read_bytes()
        result = self.archive_session(session, "selected-member")

        destination = self.home / "selected-member-restore"
        restored = restore_manifest(
            self.paths,
            result["manifest"],
            destination,
            member="selected-member/note.txt",
        )

        self.assertEqual(1, restored["files"])
        self.assertEqual(1, restored["directories"])
        self.assertEqual("selected-member/note.txt", restored["member"])
        self.assertEqual(
            expected, (destination / "selected-member/note.txt").read_bytes()
        )
        self.assertFalse((destination / "selected-member.jsonl").exists())

        rejected = self.home / "selected-member-missing"
        with self.assertRaisesRegex(ValueError, "archive member matched 0 entries"):
            restore_manifest(
                self.paths,
                result["manifest"],
                rejected,
                member="selected-member/note",
            )
        self.assertFalse(rejected.exists())

    def test_identical_companions_keep_distinct_reference_frames(self) -> None:
        first_half = b"".join(
            hashlib.sha256(f"first-{index}".encode()).digest() for index in range(2048)
        )
        second_half = b"".join(
            hashlib.sha256(f"second-{index}".encode()).digest() for index in range(2048)
        )
        companion_bytes = first_half + second_half

        def archive_bundle(name: str, primary_bytes: bytes) -> dict:
            primary = self.project / f"{name}.jsonl"
            primary.write_bytes(primary_bytes)
            companion_dir = self.project / name
            companion_dir.mkdir()
            companion = companion_dir / "copy.bin"
            companion.write_bytes(companion_bytes)
            return self.archive_session(
                {
                    "provider": "claude",
                    "session_id": f"{self.project.name}:{name}",
                    "source_root": str(self.project),
                    "last_activity": "2020-01-01T00:00:00Z",
                    "files": [
                        {
                            "path": str(primary),
                            "relative": primary.name,
                            **regular_file_stat(primary),
                        },
                        {
                            "path": str(companion),
                            "relative": f"{name}/copy.bin",
                            **regular_file_stat(companion),
                        },
                    ],
                    "directories": [
                        {
                            "path": str(companion_dir),
                            "relative": name,
                            **regular_directory_stat(companion_dir),
                        }
                    ],
                },
                f"{name}-run",
            )

        first_result = archive_bundle("recipe-a", first_half + b"A" * len(second_half))
        first_manifest_path = Path(first_result["manifest"])
        first_manifest = json.loads(first_manifest_path.read_text(encoding="utf-8"))
        first_entry = first_manifest["files"][1]
        legacy_relative = (
            f"objects/sha256/{first_entry['raw_sha256'][:2]}/"
            f"{first_entry['raw_sha256']}.zst"
        )
        legacy_path = self.paths.archive / legacy_relative
        os.replace(self.paths.archive / first_entry["object"], legacy_path)
        first_entry["object"] = legacy_relative
        atomic_json(first_manifest_path, first_manifest)

        results = [
            first_result,
            archive_bundle("recipe-b", b"B" * len(first_half) + second_half),
        ]
        manifests = [
            json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
            for result in results
        ]
        companion_entries = [manifest["files"][1] for manifest in manifests]

        self.assertTrue(all("reference" in entry for entry in companion_entries))
        self.assertNotEqual(
            companion_entries[0]["object"], companion_entries[1]["object"]
        )
        self.assertEqual({"manifests": 2, "files": 4}, verify_all(self.paths))
        for index, (result, primary_bytes) in enumerate(
            zip(
                results,
                (
                    first_half + b"A" * len(second_half),
                    b"B" * len(first_half) + second_half,
                ),
                strict=True,
            )
        ):
            destination = self.home / f"restore-recipe-{index}"
            restore_manifest(self.paths, result["manifest"], destination)
            name = f"recipe-{'a' if index == 0 else 'b'}"
            self.assertEqual(
                primary_bytes, (destination / f"{name}.jsonl").read_bytes()
            )
            self.assertEqual(
                companion_bytes, (destination / name / "copy.bin").read_bytes()
            )

        legacy_frame_hash = sha256_file(legacy_path)
        with self.assertRaisesRegex(RuntimeError, "cannot be reused safely"):
            archive_module._ensure_chunk_object(
                self.paths, companion_bytes, _zstd_binary()
            )
        self.assertEqual(legacy_frame_hash, sha256_file(legacy_path))
        self.assertEqual({"manifests": 2, "files": 4}, verify_all(self.paths))

    def test_requested_recipe_is_recorded_for_exact_variant(self) -> None:
        payload = b"".join(
            hashlib.sha256(f"solo-{index}".encode()).digest() for index in range(64)
        )
        solo = self.project / "solo.jsonl"
        solo.write_bytes(payload)
        self.archive_session(
            {
                "provider": "claude",
                "session_id": f"{self.project.name}:solo",
                "source_root": str(self.project),
                "last_activity": "2020-01-01T00:00:00Z",
                "files": [
                    {
                        "path": str(solo),
                        "relative": solo.name,
                        **regular_file_stat(solo),
                    }
                ],
            },
            "solo-run",
        )

        primary = self.project / "pair.jsonl"
        primary.write_bytes(b"distinct primary " * 100)
        companion_dir = self.project / "pair"
        companion_dir.mkdir()
        companion = companion_dir / "dup.bin"
        companion.write_bytes(payload)
        pair = {
            "provider": "claude",
            "session_id": f"{self.project.name}:pair",
            "source_root": str(self.project),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {
                    "path": str(primary),
                    "relative": primary.name,
                    **regular_file_stat(primary),
                },
                {
                    "path": str(companion),
                    "relative": "pair/dup.bin",
                    **regular_file_stat(companion),
                },
            ],
            "directories": [
                {
                    "path": str(companion_dir),
                    "relative": "pair",
                    **regular_directory_stat(companion_dir),
                }
            ],
        }

        result = self.archive_session(pair, "pair-run")

        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual("pair.jsonl", manifest["files"][1]["reference"])
        object_name = Path(manifest["files"][1]["object"]).name
        self.assertEqual(
            manifest["files"][1]["compressed_sha256"], object_name.split(".")[1]
        )
        self.assertEqual({"manifests": 2, "files": 3}, verify_all(self.paths))
        destination = self.home / "restore-pair"
        restore_manifest(self.paths, result["manifest"], destination)
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            sha256_file(destination / "pair/dup.bin"),
        )

    def write_template_corpus(self, count: int) -> None:
        for index in range(count):
            lines = "".join(
                json.dumps(
                    {
                        "type": "user",
                        "timestamp": "2020-01-01T00:00:00Z",
                        "sessionId": "abcdef01-2345-6789-abcd-ef0123456789",
                        "cwd": "/Users/fixture/project",
                        "gitBranch": "main",
                        "content": f"shared vocabulary block {(index + record) % 7} "
                        + "common phrasing " * 50,
                        "requestId": f"req-{index * 100 + record:04d}",
                    }
                )
                + "\n"
                for record in range(6)
            )
            (self.project / f"corpus-{index:03d}.jsonl").write_text(
                lines, encoding="utf-8"
            )

    def test_dictionary_training_and_round_trip(self) -> None:
        self.write_template_corpus(80)
        held = False
        publications = []
        synced_inodes = set()

        @contextmanager
        def tracking_lock(paths):
            nonlocal held
            self.assertIs(paths, self.paths)
            held = True
            try:
                yield
            finally:
                held = False

        real_link = os.link
        real_fsync = os.fsync
        real_atomic_json = archive_module.atomic_json

        def tracking_fsync(fd):
            info = os.fstat(fd)
            if stat.S_ISREG(info.st_mode):
                synced_inodes.add(info.st_ino)
            return real_fsync(fd)

        def tracking_link(source, destination, **kwargs):
            if Path(destination).suffix == ".dict":
                self.assertTrue(held)
                self.assertIn(Path(source).stat().st_ino, synced_inodes)
                publications.append("object")
            return real_link(source, destination, **kwargs)

        def tracking_atomic_json(path, payload):
            if path.parent.name == "dictionaries":
                self.assertTrue(held)
                publications.append("pointer")
            return real_atomic_json(path, payload)

        with (
            mock.patch.object(archive_module, "app_lock", tracking_lock),
            mock.patch.object(archive_module.os, "fsync", side_effect=tracking_fsync),
            mock.patch.object(archive_module.os, "link", tracking_link),
            mock.patch.object(archive_module, "atomic_json", tracking_atomic_json),
        ):
            pointer = train_dictionary(self.paths, "claude", max_dict_bytes=1024)

        self.assertFalse(held)
        self.assertEqual(["object", "pointer"], publications)

        self.assertEqual("compression-dictionary", pointer["kind"])
        dictionary_path = self.paths.archive / pointer["object"]
        self.assertTrue(dictionary_path.is_file())
        self.assertEqual(pointer["raw_sha256"], sha256_file(dictionary_path))
        self.assertEqual(
            dictionary_path, load_provider_dictionary(self.paths, "claude")
        )

        target = self.project / "dict-target.jsonl"
        target.write_text(
            json.dumps(
                {
                    "type": "user",
                    "timestamp": "2020-01-01T00:00:00Z",
                    "sessionId": "abcdef01-2345-6789-abcd-ef0123456789",
                    "cwd": "/Users/fixture/project",
                    "gitBranch": "main",
                    "content": "shared vocabulary block 3 " + "common phrasing " * 200,
                    "requestId": "req-9999",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        target_bytes = target.read_bytes()
        with tempfile.TemporaryDirectory() as scratch:
            standalone = Path(scratch) / "standalone.zst"
            subprocess.run(
                [_zstd_binary(), "-q", "-6", "-f", str(target), "-o", str(standalone)],
                check=True,
            )
            standalone_size = standalone.stat().st_size

        result = archive_planned_session(
            self.paths,
            {
                "provider": "claude",
                "session_id": f"{self.project.name}:dict-target",
                "source_root": str(self.project),
                "last_activity": "2020-01-01T00:00:00Z",
                "files": [
                    {
                        "path": str(target),
                        "relative": target.name,
                        **regular_file_stat(target),
                    }
                ],
            },
            zstd=_zstd_binary(),
            quarantine_run=self.paths.state / "quarantine" / "dict-run",
            dictionary=load_provider_dictionary(self.paths, "claude"),
        )

        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        entry = manifest["files"][0]
        self.assertEqual(pointer["object"], entry["dictionary"])
        compressed_size = (self.paths.archive / entry["object"]).stat().st_size
        dictionary_size = (self.paths.archive / entry["dictionary"]).stat().st_size
        self.assertLess(compressed_size, standalone_size)
        self.assertEqual(1, result["dictionary_objects"])
        self.assertEqual(dictionary_size, result["dictionary_bytes"])
        self.assertEqual(
            result["compressed_bytes"] + dictionary_size,
            result["unique_cas_bytes"],
        )

        stats = archive_stats(self.paths)
        self.assertEqual(1, stats["dictionary_objects"])
        self.assertEqual(dictionary_size, stats["dictionary_bytes"])
        self.assertEqual(
            stats["compressed_bytes"] + dictionary_size, stats["unique_cas_bytes"]
        )

        self.assertEqual({"manifests": 1, "files": 1}, verify_all(self.paths))
        destination = self.home / "restore-dict"
        restore_manifest(self.paths, result["manifest"], destination)
        self.assertEqual(
            hashlib.sha256(target_bytes).hexdigest(),
            sha256_file(destination / "dict-target.jsonl"),
        )

    def test_dictionary_benchmark_and_rejected_training_leave_store_exact(self) -> None:
        self.write_template_corpus(80)
        pointer = train_dictionary(self.paths, "claude", max_dict_bytes=1024)

        def snapshot() -> dict[str, bytes | None]:
            return {
                str(path.relative_to(self.paths.archive)): (
                    None if path.is_dir() else path.read_bytes()
                )
                for path in sorted(self.paths.archive.rglob("*"))
            }

        before = snapshot()
        benchmark = benchmark_dictionary(
            self.paths,
            "claude",
            sample_limit=80,
            max_dict_bytes=1024,
        )
        self.assertEqual("dictionary", benchmark["incumbent"])
        self.assertEqual(before, snapshot())

        rejected = train_dictionary(
            self.paths,
            "claude",
            sample_limit=80,
            max_dict_bytes=1024,
            minimum_benefit_bytes=10**9,
        )
        self.assertFalse(rejected["promoted"])
        self.assertEqual(
            pointer["object"],
            load_provider_dictionary(self.paths, "claude")
            .relative_to(self.paths.archive)
            .as_posix(),
        )
        self.assertEqual(before, snapshot())

    def test_dictionary_candidates_use_only_discovered_primaries(self) -> None:
        primary = self.write_session("primary")
        companion = self.project / "companion.txt"
        companion.write_text("not a training record", encoding="utf-8")
        unit = archive_module.SessionUnit(
            provider="claude",
            session_id="primary",
            source_root=self.project,
            primary=primary,
            retention_days=30,
        )

        with mock.patch.object(
            archive_module, "discover_sessions", return_value=[unit]
        ):
            self.assertEqual(
                [primary], archive_module._dictionary_candidates(self.paths, "claude")
            )

        self.assertNotIn(
            companion, archive_module._dictionary_candidates(self.paths, "codex")
        )

    def test_dictionary_option_types_fail_before_store_mutation(self) -> None:
        self.paths.ensure_private()
        before = sorted(
            str(path.relative_to(self.paths.archive))
            for path in self.paths.archive.rglob("*")
        )

        for kwargs in (
            {"sample_limit": True},
            {"max_dict_bytes": True},
            {"minimum_benefit_bytes": True},
            {"minimum_benefit_bytes": -1},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                train_dictionary(self.paths, "claude", **kwargs)

        self.assertEqual(
            before,
            sorted(
                str(path.relative_to(self.paths.archive))
                for path in self.paths.archive.rglob("*")
            ),
        )

    def test_dictionary_history_uses_allocated_delta_and_deduplicates_reuse(self) -> None:
        self.paths.ensure_private()
        dictionary = "objects/sha256/ab/" + "ab" * 32 + ".dict"
        target = self.paths.archive / dictionary
        target.parent.mkdir(parents=True)
        target.write_bytes(b"fixture dictionary")
        stat_result = target.stat(follow_symlinks=False)
        before = {
            str(target.relative_to(self.paths.archive)): (
                stat_result.st_size,
                stat_result.st_blocks * 512,
            )
        }
        after_new = {
            **before,
            "objects/sha256/cd/" + "cd" * 32 + ".dict": (23, 8192),
        }
        promoted = {"promoted": True, "object": dictionary}

        with (
            mock.patch.object(
                archive_module,
                "_train_dictionary_locked",
                side_effect=[promoted, promoted],
            ),
            mock.patch.object(
                archive_module,
                "_cas_inventory",
                side_effect=[before, after_new, after_new, after_new],
            ),
        ):
            train_dictionary(self.paths, "claude")
            train_dictionary(self.paths, "claude")

        history = history_summary(self.paths)
        self.assertEqual(2, history["events"])
        self.assertEqual(8192, history["physical_allocated_bytes_delta"])
        self.assertEqual(stat_result.st_size, history["unique_cas_bytes"])

    def test_dictionary_publication_excludes_concurrent_expiry(self) -> None:
        lock = threading.Lock()
        object_published = threading.Event()
        expiry_attempted = threading.Event()
        expiry_entered = threading.Event()
        publish_pointer = threading.Event()
        failures = []

        @contextmanager
        def shared_lock(paths):
            self.assertIs(paths, self.paths)
            with lock:
                yield

        def train_locked(paths, provider, **kwargs):
            object_published.set()
            if not publish_pointer.wait(2):
                raise RuntimeError("test did not release pointer publication")
            return {"provider": provider}

        def expire_locked(paths, plan_path):
            expiry_entered.set()
            return {"objects_removed": 0}

        def run_train() -> None:
            try:
                train_dictionary(self.paths, "claude")
            except BaseException as exc:
                failures.append(exc)

        def run_expiry() -> None:
            try:
                expiry_attempted.set()
                observer_module.apply_observer_expiry_plan(
                    self.paths, self.paths.state / "expiry.json"
                )
            except BaseException as exc:
                failures.append(exc)

        with (
            mock.patch.object(archive_module, "app_lock", shared_lock),
            mock.patch.object(observer_module, "app_lock", shared_lock),
            mock.patch.object(
                archive_module, "_train_dictionary_locked", side_effect=train_locked
            ),
            mock.patch.object(
                observer_module,
                "_apply_observer_expiry_plan_locked",
                side_effect=expire_locked,
            ),
        ):
            trainer = threading.Thread(target=run_train)
            trainer.start()
            self.assertTrue(object_published.wait(1))
            expiry = threading.Thread(target=run_expiry)
            expiry.start()
            self.assertTrue(expiry_attempted.wait(1))
            self.assertFalse(expiry_entered.wait(0.1))
            publish_pointer.set()
            trainer.join(2)
            expiry.join(2)

        self.assertFalse(trainer.is_alive())
        self.assertFalse(expiry.is_alive())
        self.assertEqual([], failures)
        self.assertTrue(expiry_entered.is_set())

    def test_dangling_dictionary_pointer_falls_back(self) -> None:
        digest = "a" * 64
        atomic_json(
            self.paths.archive / "dictionaries" / "claude.json",
            {
                "schema_version": 1,
                "kind": "compression-dictionary",
                "provider": "claude",
                "object": f"objects/sha256/{digest[:2]}/{digest}.dict",
                "raw_sha256": digest,
            },
        )

        self.assertIsNone(load_provider_dictionary(self.paths, "claude", warn=False))
        result = self.archive_session(
            {
                "provider": "claude",
                "session_id": f"{self.project.name}:fallback",
                "source_root": str(self.project),
                "last_activity": "2020-01-01T00:00:00Z",
                "files": [
                    {
                        "path": str(source := self.write_session("fallback")),
                        "relative": source.name,
                        **regular_file_stat(source),
                    }
                ],
            },
            "fallback-run",
        )
        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        self.assertNotIn("dictionary", manifest["files"][0])

    def plain_session(self, name: str, source: Path) -> dict:
        return {
            "provider": "claude",
            "session_id": f"{self.project.name}:{name}",
            "source_root": str(self.project),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {
                    "path": str(source),
                    "relative": source.name,
                    **regular_file_stat(source),
                }
            ],
        }

    def write_large_session(self, name: str, size: int) -> Path:
        path = self.project / f"{name}.jsonl"
        record = (
            json.dumps(
                {
                    "type": "user",
                    "timestamp": "2020-01-01T00:00:00Z",
                    "content": "chunky " * 1000,
                }
            )
            + "\n"
        )
        path.write_text(record * (size // len(record) + 1), encoding="utf-8")
        os.chmod(path, 0o640)
        return path

    def test_chunk_boundaries(self) -> None:
        source = self.project / "boundaries.jsonl"
        line = b"x" * 1023 + b"\n"
        source.write_bytes(line * (CHUNK_TARGET_BYTES // 1024))
        chunks = list(_chunk_records(source))
        self.assertEqual(1, len(chunks))
        self.assertEqual(CHUNK_TARGET_BYTES, len(chunks[0]))

        source.write_bytes(b"y" * (CHUNK_TARGET_BYTES + 500) + b"\n" + b"small\n")
        chunks = list(_chunk_records(source))
        self.assertEqual(2, len(chunks))
        self.assertEqual(CHUNK_TARGET_BYTES + 501, len(chunks[0]))
        self.assertEqual(b"small\n", chunks[1])

    def test_chunked_round_trip(self) -> None:
        source = self.write_large_session("chunked", 2_600_000)
        original_hash = sha256_file(source)
        original_mode = source.stat().st_mode & 0o777
        original_mtime = source.stat().st_mtime_ns

        result = self.archive_session(
            self.plain_session("chunked", source), "chunk-run"
        )

        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual(2, manifest["schema_version"])
        entry = manifest["files"][0]
        self.assertNotIn("object", entry)
        self.assertEqual(3, len(entry["chunks"]))
        self.assertEqual({"manifests": 1, "files": 1}, verify_all(self.paths))

        destination = self.home / "restore-chunked"
        restore_manifest(self.paths, result["manifest"], destination)
        restored = destination / "chunked.jsonl"
        self.assertEqual(original_hash, sha256_file(restored))
        self.assertEqual(original_mode, restored.stat().st_mode & 0o777)
        self.assertEqual(original_mtime, restored.stat().st_mtime_ns)

    def test_verify_rejects_reordered_chunk_stream(self) -> None:
        source = self.project / "reordered-chunks.jsonl"
        source.write_text(
            "".join(
                json.dumps(
                    {
                        "timestamp": f"2020-01-01T00:00:0{index}Z",
                        "content": character * (CHUNK_TARGET_BYTES + 100),
                    }
                )
                + "\n"
                for index, character in enumerate("abc")
            ),
            encoding="utf-8",
        )
        result = self.archive_session(
            self.plain_session("reordered-chunks", source), "reordered-chunks"
        )
        manifest_path = Path(result["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        chunks = manifest["files"][0]["chunks"]
        self.assertEqual(3, len({chunk["sha256"] for chunk in chunks}))
        chunks.reverse()
        atomic_json(manifest_path, manifest)

        with self.assertRaisesRegex(RuntimeError, "raw SHA-256 mismatch"):
            verify_manifest(self.paths, manifest_path)

    def test_chunked_sessions_share_prefix_objects(self) -> None:
        first = self.write_large_session("chunk-a", 2_600_000)
        content = first.read_bytes()
        result_a = self.archive_session(
            self.plain_session("chunk-a", first), "chunk-a-run"
        )

        second = self.project / "chunk-b.jsonl"
        second.write_bytes(content + b'{"timestamp":"2020-01-02T00:00:00Z"}\n')
        result_b = self.archive_session(
            self.plain_session("chunk-b", second), "chunk-b-run"
        )

        chunks_a = [
            chunk["sha256"]
            for chunk in json.loads(Path(result_a["manifest"]).read_text())["files"][0][
                "chunks"
            ]
        ]
        entry_b = json.loads(Path(result_b["manifest"]).read_text())["files"][0][
            "chunks"
        ]
        chunks_b = [chunk["sha256"] for chunk in entry_b]
        self.assertEqual(chunks_a[:2], chunks_b[:2])
        self.assertNotEqual(chunks_a[2], chunks_b[2])
        self.assertEqual(3, len(entry_b))
        self.assertEqual({"manifests": 2, "files": 2}, verify_all(self.paths))

        destination = self.home / "restore-chunk-b"
        restore_manifest(self.paths, result_b["manifest"], destination)
        self.assertEqual(
            hashlib.sha256(
                content + b'{"timestamp":"2020-01-02T00:00:00Z"}\n'
            ).hexdigest(),
            sha256_file(destination / "chunk-b.jsonl"),
        )

    def test_rearchive_reuses_chunk_lineage_and_compresses_only_complete_append(
        self,
    ) -> None:
        source = self.write_large_session("incremental", 2_600_000)
        original = source.read_bytes()
        first = self.archive_session(
            self.plain_session("incremental", source), "incremental-first"
        )
        first_path = Path(first["manifest"])
        first_bytes = first_path.read_bytes()
        first_entry = json.loads(first_bytes)["files"][0]
        restore_manifest(self.paths, str(first_path))

        appended = (
            b'{"timestamp":"2020-01-02T00:00:00Z","type":"user"}\n'
            b'{"timestamp":"2020-01-02T00:00:01Z","type":"assistant"}\n'
        )
        with source.open("ab") as handle:
            handle.write(appended)
        with mock.patch.object(
            archive_module,
            "_ensure_chunk_object",
            wraps=archive_module._ensure_chunk_object,
        ) as ensure_chunk:
            second = self.archive_session(
                self.plain_session("incremental", source), "incremental-second"
            )

        second_path = Path(second["manifest"])
        second_entry = json.loads(second_path.read_text(encoding="utf-8"))["files"][0]
        self.assertEqual(
            [appended], [call.args[1] for call in ensure_chunk.call_args_list]
        )
        self.assertEqual(first_entry["chunks"], second_entry["chunks"][:-1])
        self.assertEqual(
            hashlib.sha256(appended).hexdigest(), second_entry["chunks"][-1]["sha256"]
        )
        self.assertEqual(first_bytes, first_path.read_bytes())
        self.assertEqual(
            len({chunk["sha256"] for chunk in first_entry["chunks"]}),
            second["reused_objects"],
        )

        first_restore = self.home / "incremental-first-restore"
        second_restore = self.home / "incremental-second-restore"
        restore_manifest(self.paths, str(first_path), first_restore)
        restore_manifest(self.paths, str(second_path), second_restore)
        self.assertEqual(original, (first_restore / source.name).read_bytes())
        self.assertEqual(
            original + appended, (second_restore / source.name).read_bytes()
        )

    def test_rearchive_rejects_chunk_lineage_rewrite_truncate_and_bad_tail(
        self,
    ) -> None:
        source = self.write_large_session("incremental-invalid", 1_500_000)
        original = source.read_bytes()
        first = self.archive_session(
            self.plain_session("incremental-invalid", source),
            "incremental-invalid-first",
        )
        restore_manifest(self.paths, first["manifest"])

        cases = (
            ("truncated", original[: CHUNK_TARGET_BYTES // 2], "truncated"),
            ("rewritten", original.replace(b"chunky", b"chunKy", 1), "rewritten"),
            (
                "incomplete",
                original + b'{"timestamp":"2020-01-02T00:00:00Z"',
                "incomplete JSONL record",
            ),
            ("malformed", original + b'{"timestamp":]\n', "malformed JSONL"),
            ("whitespace", original + b"   \n", "malformed JSONL"),
        )
        for run, content, message in cases:
            with self.subTest(change=run):
                source.write_bytes(content)
                with mock.patch.object(
                    archive_module, "_ensure_chunk_object"
                ) as ensure:
                    with self.assertRaisesRegex(SourceChangedError, message):
                        self.archive_session(
                            self.plain_session("incremental-invalid", source),
                            f"incremental-invalid-{run}",
                        )
                ensure.assert_not_called()
                self.assertEqual(content, source.read_bytes())
                self.assertEqual(1, len(list(iter_manifests(self.paths))))

        manifest_path = Path(first["manifest"])
        tampered = json.loads(manifest_path.read_text(encoding="utf-8"))
        chunks = tampered["files"][0]["chunks"]
        chunks[0]["sha256"] = chunks[-1]["sha256"]
        atomic_json(manifest_path, tampered)
        source.write_bytes(original + b'{"timestamp":"2020-01-02T00:00:00Z"}\n')
        with mock.patch.object(archive_module, "_ensure_chunk_object") as ensure:
            with self.assertRaisesRegex(RuntimeError, "prior chunked archive"):
                self.archive_session(
                    self.plain_session("incremental-invalid", source),
                    "incremental-invalid-tampered-prefix",
                )
        ensure.assert_not_called()
        self.assertTrue(source.exists())
        self.assertEqual(first["manifest"], str(next(iter_manifests(self.paths))))

    def test_chunked_primary_serves_as_companion_reference(self) -> None:
        primary = self.write_large_session("bigref", 1_500_000)
        primary_bytes = primary.read_bytes()
        companion_dir = self.project / "bigref"
        companion_dir.mkdir()
        companion = companion_dir / "copy.jsonl"
        companion_bytes = primary_bytes + b'{"extra":true}\n'
        companion.write_bytes(companion_bytes)
        session = {
            "provider": "claude",
            "session_id": f"{self.project.name}:bigref",
            "source_root": str(self.project),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {
                    "path": str(primary),
                    "relative": primary.name,
                    **regular_file_stat(primary),
                },
                {
                    "path": str(companion),
                    "relative": "bigref/copy.jsonl",
                    **regular_file_stat(companion),
                },
            ],
            "directories": [
                {
                    "path": str(companion_dir),
                    "relative": "bigref",
                    **regular_directory_stat(companion_dir),
                }
            ],
        }

        result = self.archive_session(session, "bigref-run")

        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        self.assertIn("chunks", manifest["files"][0])
        self.assertEqual("bigref.jsonl", manifest["files"][1]["reference"])
        self.assertEqual({"manifests": 1, "files": 2}, verify_all(self.paths))

        destination = self.home / "restore-bigref"
        restore_manifest(self.paths, result["manifest"], destination)
        self.assertEqual(
            hashlib.sha256(primary_bytes).hexdigest(),
            sha256_file(destination / "bigref.jsonl"),
        )
        self.assertEqual(
            hashlib.sha256(companion_bytes).hexdigest(),
            sha256_file(destination / "bigref/copy.jsonl"),
        )

    def test_archive_stats_aggregates_manifest_graph(self) -> None:
        self.write_session("stats-a")
        self.archive_session(self.bundle_session("stats-b"), "stats-run")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        apply_archive_plan(self.paths, plan_path)

        stats = archive_stats(self.paths)

        self.assertEqual(2, stats["manifests"])
        self.assertEqual(3, stats["objects"])
        claude = stats["providers"]["claude"]
        self.assertEqual(2, claude["manifests"])
        self.assertEqual(3, claude["files"])
        self.assertGreater(claude["companion_raw_bytes"], 0)
        self.assertEqual(claude["files"], sum(claude["size_histogram"].values()))
        self.assertGreater(stats["ratio"], 1)

    def test_archive_metrics_count_reused_storage_once(self) -> None:
        self.paths.ensure_private()
        archive_module._ensure_archive_canary(self.paths, _zstd_binary())
        root = self.home / ".codex/sessions"
        payload = (
            json.dumps(
                {
                    "type": "user",
                    "timestamp": "2020-01-01T00:00:00Z",
                    "content": "same archive payload " * 5000,
                }
            )
            + "\n"
        )
        for day, name in (("2024/01/02", "one"), ("2024/02/03", "two")):
            directory = root / day
            directory.mkdir(parents=True)
            (directory / f"rollout-{name}.jsonl").write_text(payload, encoding="utf-8")

        plan_path, plan = create_archive_plan(self.paths, utc_now())
        self.assertEqual(2, len(plan["sessions"]))
        with mock.patch.object(
            archive_module.shutil,
            "disk_usage",
            side_effect=[mock.Mock(free=10_000), mock.Mock(free=8_000)],
        ):
            result = apply_archive_plan(self.paths, plan_path)

        logical = len(payload.encode()) * 2
        self.assertEqual(logical, result["logical_raw_bytes"])
        self.assertEqual(logical, result["raw_bytes"])
        self.assertEqual(1, result["new_objects"])
        self.assertEqual(1, result["reused_objects"])
        self.assertEqual(0, result["dictionary_objects"])
        self.assertEqual(result["compressed_bytes"], result["unique_new_cas_bytes"])
        self.assertEqual(result["compressed_bytes"], result["unique_cas_bytes"])
        self.assertGreaterEqual(
            result["cas_allocated_bytes_change"], result["unique_new_cas_bytes"]
        )
        self.assertEqual(-2_000, result["filesystem_free_bytes_change"])
        self.assertEqual(
            logical - result["compressed_bytes"], result["logical_savings_bytes"]
        )

    def test_manifest_validation_rejects_malformed_shapes_with_controlled_errors(
        self,
    ) -> None:
        result = self.archive_session(
            self.bundle_session("manifest-validation"), "manifest-validation-run"
        )
        manifest_path = Path(result["manifest"])
        original = json.loads(manifest_path.read_text(encoding="utf-8"))
        cases = {
            "schema bool": lambda value: value.update(schema_version=True),
            "missing files": lambda value: value.pop("files"),
            "files object": lambda value: value.update(files={}),
            "member missing object": lambda value: value["files"][0].pop("object"),
            "member size bool": lambda value: value["files"][0].update(size=True),
            "reference null": lambda value: value["files"][1].update(reference=None),
            "directories object": lambda value: value.update(directories={}),
            "absolute object": lambda value: value["files"][0].update(
                object="/etc/passwd"
            ),
            "object hash mismatch": lambda value: value["files"][0].update(
                raw_sha256="0" * 64
            ),
            "absolute dictionary": lambda value: value["files"][0].update(
                dictionary="/etc/passwd"
            ),
            "noncanonical relative": lambda value: value["files"][0].update(
                relative="a//b"
            ),
            "nul source root": lambda value: value.update(source_root="/fixture\0bad"),
            "nul member": lambda value: value["files"][0].update(relative="a\0b"),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                malformed = json.loads(json.dumps(original))
                mutate(malformed)
                atomic_json(manifest_path, malformed)
                with self.assertRaises(ValueError):
                    validate_manifest(manifest_path)

        malformed = json.loads(json.dumps(original))
        malformed["files"][0].pop("size")
        atomic_json(manifest_path, malformed)
        destination = self.home / "malformed-restore"
        for index in range(33):
            atomic_json(
                self.paths.state / "plans" / f"b16-expired-{index}.json",
                {"expires_at": "2000-01-01T00:00:00Z"},
            )
        plans_before = set((self.paths.state / "plans").glob("*.json"))
        for reader in (
            lambda: verify_manifest(self.paths, manifest_path),
            lambda: archive_stats(self.paths),
            lambda: restore_manifest(self.paths, str(manifest_path), destination),
        ):
            with self.assertRaisesRegex(ValueError, "member shape"):
                reader()
        with self.assertRaisesRegex(
            RuntimeError, "cannot evaluate archive reachability"
        ):
            observer_module.create_observer_expiry_plan(self.paths)
        self.assertFalse(destination.exists())
        self.assertEqual(plans_before, set((self.paths.state / "plans").glob("*.json")))

    def test_pre_recipe_schema_one_manifest_remains_readable(self) -> None:
        source = self.write_session("legacy-manifest")
        result = self.archive_session(
            self.plain_session("legacy-manifest", source), "legacy-manifest-run"
        )
        manifest_path = Path(result["manifest"])
        legacy = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(1, legacy["schema_version"])
        legacy.pop("zstd_version")
        legacy.pop("directories")
        atomic_json(manifest_path, legacy)

        normalized = validate_manifest(manifest_path)
        self.assertEqual("unknown", normalized["zstd_version"])
        self.assertEqual([], normalized["directories"])
        self.assertEqual({"manifests": 1, "files": 1}, verify_all(self.paths))
        self.assertEqual(1, archive_stats(self.paths)["manifests"])
        observer_module.create_observer_expiry_plan(self.paths)
        destination = self.home / "legacy-manifest-restore"
        self.assertEqual(
            1, restore_manifest(self.paths, str(manifest_path), destination)["files"]
        )


if __name__ == "__main__":
    unittest.main()
