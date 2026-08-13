from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

import sesh_compresh.clean as clean_module
import sesh_compresh.common as common_module
import sesh_compresh.history as history_module
from sesh_compresh.clean import (
    apply_clean_expiry_plan,
    apply_clean_plan,
    create_clean_expiry_plan,
    undo_clean,
)
from sesh_compresh.common import (
    AppPaths,
    any_open,
    atomic_json,
    iso_utc,
    open_file_paths_for,
    regular_file_stat,
    utc_now,
)
from sesh_compresh.history import history_summary


class CleanupSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.paths = AppPaths.discover(self.home)
        self.paths.ensure_private()
        self.open_files_patcher = mock.patch.object(
            clean_module, "open_file_paths_for", return_value=set()
        )
        self.open_files = self.open_files_patcher.start()
        self.addCleanup(self.open_files_patcher.stop)
        self.discovered: list[dict[str, object]] = []
        self.discovery_patcher = mock.patch.object(
            clean_module, "discover_practical", side_effect=self.discover
        )
        self.discovery_patcher.start()
        self.addCleanup(self.discovery_patcher.stop)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_item(self, path: Path, action: str = "delete-tree") -> dict[str, object]:
        allocated, tree_fingerprint = clean_module._tree_snapshot(path)
        return {
            "path": str(path),
            "family": "fixture",
            "marker": "fixture",
            "action": action,
            "allocated_bytes": allocated,
            "tree_fingerprint": tree_fingerprint,
            **clean_module._fingerprint(path),
        }

    def discover(
        self, paths: AppPaths, *, only: Path | None = None
    ) -> list[dict[str, object]]:
        self.assertEqual(self.paths, paths)
        found = (
            clean_module._candidate(
                Path(item["path"]),
                str(item["family"]),
                str(item["marker"]),
                str(item["action"]),
            )
            for item in self.discovered
        )
        return [
            item
            for item in found
            if item is not None and (only is None or Path(item["path"]) == only)
        ]

    def write_plan(
        self,
        items: list[object],
        *,
        allowed: list[dict[str, object]] | None = None,
        profile: str = "practical",
    ) -> Path:
        allowed_items = items if allowed is None else allowed
        self.discovered = [
            dict(item) for item in allowed_items if isinstance(item, dict)
        ]
        now = utc_now()
        plan = self.paths.state / "plans/test-clean.json"
        atomic_json(
            plan,
            {
                "schema_version": 1,
                "kind": "clean-plan",
                "profile": profile,
                "run_id": "test",
                "created_at": iso_utc(now),
                "expires_at": iso_utc(now + timedelta(hours=1)),
                "allocated_bytes": sum(
                    item["allocated_bytes"]
                    for item in items
                    if isinstance(item, dict)
                    and type(item.get("allocated_bytes")) is int
                ),
                "candidates": items,
                "skipped_open": [],
                "policy": None,
            },
        )
        return plan

    def apply_aged_plan(self, plan: Path, *, days: int) -> dict[str, object]:
        with mock.patch.object(
            clean_module, "utc_now", return_value=utc_now() - timedelta(days=days)
        ):
            return apply_clean_plan(self.paths, plan)

    def write_policy(
        self,
        root: Path,
        *,
        name: str = "custom-cache",
        retention_days: int = 7,
        markers: list[str] | None = None,
        action: str = "delete-tree",
    ) -> Path:
        policy = self.paths.home / "cleanup-policy.json"
        atomic_json(
            policy,
            {
                "schema_version": 1,
                "kind": "clean-policy",
                "rules": [
                    {
                        "root": str(root.resolve()),
                        "name": name,
                        "retention_days": retention_days,
                        "markers": ["CACHEDIR.TAG"] if markers is None else markers,
                        "action": action,
                    }
                ],
            },
        )
        return policy

    def age_tree(self, path: Path, *, days: int) -> None:
        timestamp = int((utc_now() - timedelta(days=days)).timestamp() * 1_000_000_000)
        for current, dirs, files in os.walk(path, followlinks=False):
            for name in (*dirs, *files):
                os.utime(
                    Path(current, name),
                    ns=(timestamp, timestamp),
                    follow_symlinks=False,
                )
        os.utime(path, ns=(timestamp, timestamp), follow_symlinks=False)

    def test_delete_exact_planned_directory(self) -> None:
        cache = self.home / "cache"
        cache.mkdir()
        (cache / "artifact").write_text("generated")
        plan = self.write_plan([self.make_item(cache)])
        result = apply_clean_plan(self.paths, plan)
        self.assertFalse(cache.exists())
        self.assertEqual([], result["skipped"])

    def test_cleanup_quarantine_undo_restores_exact_tree(self) -> None:
        cache = self.home / "undo-cache"
        nested = cache / "nested"
        nested.mkdir(parents=True)
        artifact = nested / "artifact"
        artifact.write_bytes(b"recoverable cache bytes")
        plan = self.write_plan([self.make_item(cache)])

        applied = apply_clean_plan(self.paths, plan)

        self.assertFalse(cache.exists())
        self.assertEqual(0, applied["reclaimed_bytes"])
        self.assertGreater(applied["quarantined_bytes"], 0)
        journal = Path(applied["quarantine"])
        self.assertTrue(journal.is_file())

        undone = undo_clean(self.paths, journal)

        self.assertEqual(1, undone["restored"])
        self.assertEqual(b"recoverable cache bytes", artifact.read_bytes())
        self.assertFalse(journal.exists())

    def test_mixed_cache_undo_restores_only_pruned_children(self) -> None:
        cache = self.home / "mixed-undo"
        cache.mkdir()
        keep = cache / "README.md"
        keep.write_text("keep")
        dropped = cache / "bucket"
        dropped.mkdir()
        (dropped / "data").write_text("drop")
        fixed_mtime = 1_600_000_000_123_456_789
        os.utime(cache, ns=(fixed_mtime, fixed_mtime))
        before_mode = cache.stat().st_mode & 0o777
        plan = self.write_plan([self.make_item(cache, "prune-mixed-cache")])

        applied = apply_clean_plan(self.paths, plan)
        self.assertTrue(keep.is_file())
        self.assertFalse(dropped.exists())

        undo_clean(self.paths, Path(applied["quarantine"]))
        self.assertEqual("keep", keep.read_text())
        self.assertEqual("drop", (dropped / "data").read_text())
        self.assertEqual(before_mode, cache.stat().st_mode & 0o777)
        self.assertEqual(fixed_mtime, cache.stat().st_mtime_ns)

    def test_mixed_cache_undo_restores_symlink_without_touching_target(self) -> None:
        outside = self.home / "outside-mixed"
        outside.mkdir()
        (outside / "data").write_text("outside")
        cache = self.home / "mixed-symlink"
        cache.mkdir()
        link = cache / "linked"
        link.symlink_to(outside, target_is_directory=True)
        plan = self.write_plan([self.make_item(cache, "prune-mixed-cache")])

        applied = apply_clean_plan(self.paths, plan)
        self.assertFalse(link.exists())
        self.assertEqual("outside", (outside / "data").read_text())

        undo_clean(self.paths, Path(applied["quarantine"]))
        self.assertTrue(link.is_symlink())
        self.assertEqual("outside", (outside / "data").read_text())

    def test_cleanup_quarantine_expiry_is_explicit_and_dry_run(self) -> None:
        cache = self.home / "expiry-cache"
        cache.mkdir()
        (cache / "artifact").write_text("expired")
        plan = self.write_plan([self.make_item(cache)])
        applied = self.apply_aged_plan(plan, days=8)
        journal = Path(applied["quarantine"])

        expiry_path, expiry = create_clean_expiry_plan(self.paths, retention_days=7)
        self.assertTrue(journal.exists())
        self.assertEqual([str(journal)], [item["path"] for item in expiry["journals"]])

        result = apply_clean_expiry_plan(self.paths, expiry_path)

        self.assertEqual(1, result["journals_removed"])
        self.assertGreater(result["reclaimed_bytes"], 0)
        self.assertFalse(journal.exists())
        self.assertFalse(cache.exists())

    def test_cleanup_primitives_record_only_confirmed_physical_reclamation(self) -> None:
        cache = self.home / "history-expiry-cache"
        cache.mkdir()
        (cache / "artifact").write_bytes(b"expired" * 1024)
        plan = self.write_plan([self.make_item(cache)])
        applied = self.apply_aged_plan(plan, days=8)
        expiry_path, _ = create_clean_expiry_plan(self.paths, retention_days=7)

        result = apply_clean_expiry_plan(self.paths, expiry_path)
        summary = history_summary(self.paths)

        self.assertGreater(applied["quarantined_bytes"], 0)
        self.assertEqual(-result["reclaimed_bytes"], summary["physical_allocated_bytes_delta"])
        self.assertEqual(
            applied["quarantined_bytes"],
            summary["logical_reclaimed_bytes_delta"],
        )
        self.assertEqual(0, summary["observed_free_bytes_delta"])
        self.assertEqual(2, summary["events"])

    def test_cleanup_append_failure_does_not_hide_completed_mutation(self) -> None:
        cache = self.home / "history-failure-cache"
        cache.mkdir()
        (cache / "artifact").write_text("generated", encoding="utf-8")
        plan = self.write_plan([self.make_item(cache)])

        with mock.patch.object(
            history_module,
            "append_history_event",
            side_effect=OSError("history unavailable"),
        ):
            result = apply_clean_plan(self.paths, plan)

        self.assertFalse(cache.exists())
        self.assertFalse(result["history_recorded"])
        self.assertEqual(
            "maintenance history append failed", result["history_warning"]
        )

    def test_cleanup_expiry_retries_after_post_delete_sync_failure(self) -> None:
        cache = self.home / "expiry-retry"
        cache.mkdir()
        plan = self.write_plan([self.make_item(cache)])
        applied = self.apply_aged_plan(plan, days=8)
        journal = Path(applied["quarantine"])
        payload = common_module.load_json(journal)
        expiry_path, _ = create_clean_expiry_plan(self.paths, retention_days=7)
        quarantine = Path(payload["moves"][0]["quarantine"])
        real_sync = clean_module.fsync_dir
        failed = False

        def fail_after_delete(path: Path) -> None:
            nonlocal failed
            if (
                Path(path) == quarantine.parent
                and not quarantine.exists()
                and not failed
            ):
                failed = True
                raise OSError("injected quarantine sync failure")
            real_sync(path)

        with mock.patch.object(
            clean_module, "fsync_dir", side_effect=fail_after_delete
        ):
            with self.assertRaisesRegex(OSError, "quarantine sync failure"):
                apply_clean_expiry_plan(self.paths, expiry_path)

        self.assertTrue(journal.exists())
        result = apply_clean_expiry_plan(self.paths, expiry_path)
        self.assertEqual(1, result["journals_removed"])
        self.assertFalse(journal.exists())

    def test_cleanup_expiry_retries_partial_recursive_delete(self) -> None:
        cache = self.home / "expiry-partial"
        cache.mkdir()
        for name in ("first", "second"):
            (cache / name).write_text(name)
        plan = self.write_plan([self.make_item(cache)])
        applied = self.apply_aged_plan(plan, days=8)
        journal = Path(applied["quarantine"])
        expiry_path, _ = create_clean_expiry_plan(self.paths, retention_days=7)
        real_delete = clean_module._delete_tree
        failed = False

        def fail_partially(path: Path) -> None:
            nonlocal failed
            if not failed:
                failed = True
                next(Path(path).iterdir()).unlink()
                raise OSError("injected partial deletion")
            real_delete(path)

        with mock.patch.object(
            clean_module, "_delete_tree", side_effect=fail_partially
        ):
            with self.assertRaisesRegex(OSError, "partial deletion"):
                apply_clean_expiry_plan(self.paths, expiry_path)

        self.assertTrue(journal.exists())
        result = apply_clean_expiry_plan(self.paths, expiry_path)
        self.assertEqual(1, result["journals_removed"])
        self.assertFalse(journal.exists())

    def test_cleanup_expiry_retries_journal_parent_sync(self) -> None:
        cache = self.home / "expiry-journal-sync"
        cache.mkdir()
        plan = self.write_plan([self.make_item(cache)])
        applied = self.apply_aged_plan(plan, days=8)
        journal = Path(applied["quarantine"])
        expiry_path, _ = create_clean_expiry_plan(self.paths, retention_days=7)
        real_sync = clean_module.fsync_dir
        failed = False

        def fail_after_journal_unlink(path: Path) -> None:
            nonlocal failed
            if Path(path) == journal.parent and not journal.exists() and not failed:
                failed = True
                raise OSError("injected journal sync failure")
            real_sync(path)

        with mock.patch.object(
            clean_module, "fsync_dir", side_effect=fail_after_journal_unlink
        ):
            with self.assertRaisesRegex(OSError, "journal sync failure"):
                apply_clean_expiry_plan(self.paths, expiry_path)

        self.assertFalse(journal.exists())
        result = apply_clean_expiry_plan(self.paths, expiry_path)
        self.assertEqual(1, result["journals_removed"])

    def test_cleanup_expiry_plan_binds_retention_policy(self) -> None:
        cache = self.home / "expiry-policy"
        cache.mkdir()
        plan = self.write_plan([self.make_item(cache)])
        applied = self.apply_aged_plan(plan, days=1)
        journal = Path(applied["quarantine"])
        expiry_path, expiry = create_clean_expiry_plan(self.paths, retention_days=7)
        expiry["retention_days"] = 0
        expiry["journals"] = [{"path": str(journal), **regular_file_stat(journal)}]
        atomic_json(expiry_path, expiry)

        with self.assertRaisesRegex(ValueError, "identity"):
            apply_clean_expiry_plan(self.paths, expiry_path)

        self.assertTrue(journal.exists())
        self.assertFalse(cache.exists())

    def test_cleanup_undo_collision_preserves_quarantine(self) -> None:
        cache = self.home / "undo-collision"
        cache.mkdir()
        plan = self.write_plan([self.make_item(cache)])
        applied = apply_clean_plan(self.paths, plan)
        journal = Path(applied["quarantine"])
        cache.mkdir()

        with self.assertRaises(FileExistsError):
            undo_clean(self.paths, journal)

        self.assertTrue(cache.is_dir())
        self.assertTrue(journal.is_file())
        quarantined = common_module.load_json(journal)["moves"][0]["quarantine"]
        self.assertTrue(Path(quarantined).exists())

    def test_cleanup_journal_binds_mixed_source_to_quarantine_name(self) -> None:
        cache = self.home / "undo-binding"
        cache.mkdir()
        dropped = cache / "bucket"
        dropped.mkdir()
        plan = self.write_plan([self.make_item(cache, "prune-mixed-cache")])
        applied = apply_clean_plan(self.paths, plan)
        journal = Path(applied["quarantine"])
        payload = common_module.load_json(journal)
        payload["moves"][0]["source"] = str(cache / "different-child")
        atomic_json(journal, payload)

        with self.assertRaisesRegex(ValueError, "journal is invalid"):
            undo_clean(self.paths, journal)

        self.assertFalse((cache / "different-child").exists())
        self.assertTrue(Path(payload["moves"][0]["quarantine"]).exists())

    def test_cleanup_journal_rejects_coordinated_path_tampering(self) -> None:
        cache = self.home / "undo-coordinated"
        cache.mkdir()
        dropped = cache / "bucket"
        dropped.mkdir()
        plan = self.write_plan([self.make_item(cache, "prune-mixed-cache")])
        applied = apply_clean_plan(self.paths, plan)
        journal = Path(applied["quarantine"])
        payload = common_module.load_json(journal)
        move = payload["moves"][0]
        forged_source = cache / "different-child"
        forged_quarantine = Path(move["quarantine"]).with_name(
            "0000-"
            + clean_module.hashlib.sha256(os.fsencode(str(forged_source))).hexdigest()[
                :20
            ]
        )
        Path(move["quarantine"]).rename(forged_quarantine)
        move["source"] = str(forged_source)
        move["quarantine"] = str(forged_quarantine)
        forged = journal.with_name(
            f"test-{clean_module._canonical_json_digest(payload)}.json"
        )
        atomic_json(forged, payload, replace=False)

        with self.assertRaisesRegex(ValueError, "identity changed"):
            undo_clean(self.paths, forged)

        self.assertFalse(forged_source.exists())
        self.assertTrue(forged_quarantine.exists())

    def test_cleanup_undo_rejects_replaced_quarantine_ancestor(self) -> None:
        cache = self.home / "undo-ancestor"
        cache.mkdir()
        plan = self.write_plan([self.make_item(cache)])
        applied = apply_clean_plan(self.paths, plan)
        journal = Path(applied["quarantine"])
        local = self.home / clean_module.LOCAL_QUARANTINE_NAME
        relocated = self.home / "relocated-quarantine"
        local.rename(relocated)
        local.symlink_to(relocated, target_is_directory=True)

        with self.assertRaises(ValueError):
            undo_clean(self.paths, journal)

        self.assertFalse(cache.exists())
        self.assertTrue(local.is_symlink())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFOs")
    def test_mixed_cache_rejects_special_child_before_journal(self) -> None:
        cache = self.home / "mixed-special"
        cache.mkdir()
        os.mkfifo(cache / "pipe")
        plan = self.write_plan([self.make_item(cache, "prune-mixed-cache")])

        with self.assertRaisesRegex(ValueError, "unsupported entry"):
            apply_clean_plan(self.paths, plan)

        self.assertTrue((cache / "pipe").exists())
        self.assertFalse((self.paths.state / "clean-quarantine/test.intent").exists())

    def test_cleanup_quarantine_rejects_symlinked_run_before_journal(self) -> None:
        cache = self.home / "unsafe-quarantine"
        cache.mkdir()
        outside = self.home / "outside-quarantine"
        outside.mkdir()
        local = self.home / clean_module.LOCAL_QUARANTINE_NAME
        local.mkdir()
        (local / "test").symlink_to(outside, target_is_directory=True)
        plan = self.write_plan([self.make_item(cache)])

        with self.assertRaises(ValueError):
            apply_clean_plan(self.paths, plan)

        self.assertTrue(cache.is_dir())
        self.assertEqual([], list(outside.iterdir()))
        self.assertEqual(
            [], list((self.paths.state / "clean-quarantine").glob("test-*.json"))
        )

    def test_cleanup_apply_propagates_post_move_sync_failure(self) -> None:
        cache = self.home / "move-sync"
        cache.mkdir()
        plan = self.write_plan([self.make_item(cache)])
        real_sync = clean_module.fsync_dir
        failed = False

        def fail_after_move(path: Path) -> None:
            nonlocal failed
            if Path(path) == cache.parent and not cache.exists() and not failed:
                failed = True
                raise OSError("injected move sync failure")
            real_sync(path)

        with mock.patch.object(clean_module, "fsync_dir", side_effect=fail_after_move):
            with self.assertRaisesRegex(OSError, "move sync failure"):
                apply_clean_plan(self.paths, plan)

        journal = next((self.paths.state / "clean-quarantine").glob("test-*.json"))
        self.assertTrue(journal.exists())
        self.assertEqual(1, undo_clean(self.paths, journal)["restored"])
        self.assertTrue(cache.is_dir())

    def test_cleanup_apply_propagates_quarantine_sync_failure(self) -> None:
        cache = self.home / "quarantine-sync"
        cache.mkdir()
        plan = self.write_plan([self.make_item(cache)])
        local = self.home / clean_module.LOCAL_QUARANTINE_NAME
        real_sync = clean_module.fsync_dir

        def fail_local(path: Path) -> None:
            if Path(path) == local:
                raise OSError("injected local quarantine sync failure")
            real_sync(path)

        with mock.patch.object(clean_module, "fsync_dir", side_effect=fail_local):
            with self.assertRaisesRegex(OSError, "local quarantine sync failure"):
                apply_clean_plan(self.paths, plan)

        self.assertTrue(cache.is_dir())

    def test_cleanup_undo_retries_journal_parent_sync(self) -> None:
        cache = self.home / "undo-journal-sync"
        cache.mkdir()
        plan = self.write_plan([self.make_item(cache)])
        applied = apply_clean_plan(self.paths, plan)
        journal = Path(applied["quarantine"])
        real_sync = clean_module.fsync_dir
        failed = False

        def fail_after_completion(path: Path) -> None:
            nonlocal failed
            if Path(path) == journal.parent and not journal.exists() and not failed:
                failed = True
                raise OSError("injected undo journal sync failure")
            real_sync(path)

        with mock.patch.object(
            clean_module, "fsync_dir", side_effect=fail_after_completion
        ):
            with self.assertRaisesRegex(OSError, "undo journal sync failure"):
                undo_clean(self.paths, journal)

        self.assertTrue(cache.is_dir())
        self.assertEqual(0, undo_clean(self.paths, journal)["restored"])

    def test_cleanup_expiry_rejects_replaced_deletion_tombstone(self) -> None:
        cache = self.home / "expiry-tombstone"
        cache.mkdir()
        for name in ("first", "second"):
            (cache / name).write_text(name)
        plan = self.write_plan([self.make_item(cache)])
        applied = self.apply_aged_plan(plan, days=8)
        journal = Path(applied["quarantine"])
        payload = common_module.load_json(journal)
        quarantine = Path(payload["moves"][0]["quarantine"])
        tombstone = clean_module._clean_tombstone(quarantine)
        expiry_path, _ = create_clean_expiry_plan(self.paths, retention_days=7)

        def fail_partially(path: Path) -> None:
            next(Path(path).iterdir()).unlink()
            raise OSError("injected partial deletion")

        with mock.patch.object(
            clean_module, "_delete_tree", side_effect=fail_partially
        ):
            with self.assertRaises(OSError):
                apply_clean_expiry_plan(self.paths, expiry_path)
        shutil.rmtree(tombstone)
        tombstone.mkdir()
        (tombstone / "unrelated").write_text("preserve")

        with self.assertRaisesRegex(RuntimeError, "staging identity changed"):
            apply_clean_expiry_plan(self.paths, expiry_path)

        self.assertEqual("preserve", (tombstone / "unrelated").read_text())

    def test_cleanup_expiry_requires_completion_for_missing_journal(self) -> None:
        cache = self.home / "expiry-missing-journal"
        cache.mkdir()
        plan = self.write_plan([self.make_item(cache)])
        applied = self.apply_aged_plan(plan, days=8)
        journal = Path(applied["quarantine"])
        payload = common_module.load_json(journal)
        quarantine = Path(payload["moves"][0]["quarantine"])
        expiry_path, _ = create_clean_expiry_plan(self.paths, retention_days=7)
        journal.unlink()

        with self.assertRaises(ValueError):
            apply_clean_expiry_plan(self.paths, expiry_path)

        self.assertTrue(quarantine.exists())

    def test_cleanup_expiry_ignores_skipped_candidate_drift(self) -> None:
        first = self.home / "expiry-first"
        second = self.home / "expiry-second"
        first.mkdir()
        second.mkdir()
        changed = second / "artifact"
        changed.write_text("planned")
        plan = self.write_plan([self.make_item(first), self.make_item(second)])
        calls = 0

        def drift_second(candidates, *, recursive=False, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                changed.write_text("changed")
            return set()

        self.open_files.side_effect = drift_second
        with mock.patch.object(
            clean_module, "utc_now", return_value=utc_now() - timedelta(days=8)
        ):
            apply_clean_plan(self.paths, plan)
        expiry_path, _ = create_clean_expiry_plan(self.paths, retention_days=7)

        result = apply_clean_expiry_plan(self.paths, expiry_path)

        self.assertEqual(1, result["journals_removed"])
        self.assertEqual("changed", changed.read_text())
        self.assertFalse(first.exists())

    def test_cleanup_undo_rechecks_each_destination(self) -> None:
        cache = self.home / "undo-race"
        cache.mkdir()
        for name in ("first", "second"):
            (cache / name).write_text(name)
        plan = self.write_plan([self.make_item(cache, "prune-mixed-cache")])
        applied = apply_clean_plan(self.paths, plan)
        journal = Path(applied["quarantine"])
        real_replace = clean_module.os.replace
        calls = 0

        def recreate_later(source: Path, destination: Path) -> None:
            nonlocal calls
            real_replace(source, destination)
            calls += 1
            if calls == 1:
                (cache / "first").write_text("live replacement")

        with mock.patch.object(clean_module.os, "replace", side_effect=recreate_later):
            with self.assertRaises(FileExistsError):
                undo_clean(self.paths, journal)

        self.assertEqual("live replacement", (cache / "first").read_text())
        self.assertTrue(journal.exists())

    def test_cleanup_undo_ignores_skipped_candidate_drift(self) -> None:
        first = self.home / "first-quarantined"
        second = self.home / "second-drifted"
        first.mkdir()
        second.mkdir()
        changed = second / "artifact"
        changed.write_text("planned")
        plan = self.write_plan([self.make_item(first), self.make_item(second)])
        calls = 0

        def drift_second(candidates, *, recursive=False, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                changed.write_text("changed")
            return set()

        self.open_files.side_effect = drift_second
        applied = apply_clean_plan(self.paths, plan)

        self.assertFalse(first.exists())
        self.assertTrue(second.exists())
        self.assertEqual("marker or content drift", applied["skipped"][0]["reason"])
        result = undo_clean(self.paths, Path(applied["quarantine"]))
        self.assertEqual(1, result["restored"])
        self.assertTrue(first.exists())
        self.assertEqual("changed", changed.read_text())

    def test_cleanup_undo_recovers_interrupted_pre_move_intent(self) -> None:
        cache = self.home / "interrupted-clean"
        cache.mkdir()
        (cache / "artifact").write_text("still live")
        plan = self.write_plan([self.make_item(cache)])

        with mock.patch.object(
            clean_module.os, "replace", side_effect=SystemExit("crash before move")
        ):
            with self.assertRaises(SystemExit):
                apply_clean_plan(self.paths, plan)

        journal = next((self.paths.state / "clean-quarantine").glob("test-*.json"))
        self.assertTrue(cache.is_dir())
        self.assertTrue(journal.is_file())
        result = undo_clean(self.paths, journal)
        self.assertEqual(0, result["restored"])
        self.assertTrue((cache / "artifact").is_file())
        self.assertFalse(journal.exists())

    def test_cleanup_apply_resumes_intent_only_publication_crash(self) -> None:
        cache = self.home / "intent-only"
        cache.mkdir()
        plan = self.write_plan([self.make_item(cache)])
        real_write = clean_module.atomic_json
        calls = 0

        def crash_after_intent(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise SystemExit("crash after intent")
            return real_write(*args, **kwargs)

        with mock.patch.object(
            clean_module, "atomic_json", side_effect=crash_after_intent
        ):
            with self.assertRaises(SystemExit):
                apply_clean_plan(self.paths, plan)

        self.assertTrue(cache.is_dir())
        self.assertTrue((self.paths.state / "clean-quarantine/test.intent").is_file())
        applied = apply_clean_plan(self.paths, plan)
        self.assertFalse(cache.exists())
        self.assertTrue(Path(applied["quarantine"]).is_file())

    def test_clean_plan_names_are_unique_and_publish_without_replacement(self) -> None:
        current = utc_now()
        events = []

        def publish(*args, **kwargs):
            events.append("publish")
            return common_module.atomic_json(*args, **kwargs)

        def prune(*args, **kwargs):
            events.append("prune")
            return common_module._prune_expired_plans_locked(*args, **kwargs)

        with (
            mock.patch.object(clean_module, "utc_now", return_value=current),
            mock.patch.object(clean_module, "open_file_paths", return_value=set()),
            mock.patch.object(
                clean_module, "atomic_json", side_effect=publish
            ) as write,
            mock.patch.object(
                clean_module, "_prune_expired_plans_locked", side_effect=prune
            ),
        ):
            first_path, first = clean_module.create_clean_plan(self.paths)
            second_path, second = clean_module.create_clean_plan(self.paths)

        self.assertNotEqual(first["run_id"], second["run_id"])
        self.assertNotEqual(first_path, second_path)
        self.assertTrue(first_path.is_file())
        self.assertTrue(second_path.is_file())
        self.assertEqual(["prune", "publish", "prune", "publish"], events)
        self.assertEqual(
            [False, False], [call.kwargs["replace"] for call in write.call_args_list]
        )

    def test_clean_plan_filters_exact_source_device(self) -> None:
        cache = self.home / "source-device-cache"
        cache.mkdir()
        item = self.make_item(cache)
        self.discovered = [item]

        with mock.patch.object(clean_module, "open_file_paths", return_value=set()):
            _, included = clean_module.create_clean_plan(
                self.paths, source_device=item["device"]
            )
            _, excluded = clean_module.create_clean_plan(
                self.paths, source_device=item["device"] + 1
            )

        self.assertEqual(
            [str(cache)], [entry["path"] for entry in included["candidates"]]
        )
        self.assertEqual([], excluded["candidates"])
        self.assertEqual([], excluded["skipped_open"])
        with self.assertRaisesRegex(ValueError, "source device"):
            clean_module.create_clean_plan(self.paths, source_device=True)

    def test_clean_plan_rejects_cross_device_descendant(self) -> None:
        cache = self.home / "cross-device-cache"
        cache.mkdir()
        child = cache / "child"
        child.write_text("data", encoding="utf-8")
        self.discovered = [self.make_item(cache)]
        source_device = cache.stat().st_dev
        real_snapshot = clean_module._tree_snapshot

        def reject_scoped_snapshot(path, *, source_device=None):
            if source_device is not None:
                raise clean_module._DifferentFilesystemError("cross-device child")
            return real_snapshot(path)

        with (
            mock.patch.object(clean_module, "open_file_paths", return_value=set()),
            mock.patch.object(
                clean_module,
                "_tree_snapshot",
                side_effect=reject_scoped_snapshot,
            ) as snapshot,
        ):
            _, plan = clean_module.create_clean_plan(
                self.paths, source_device=source_device
            )

        self.assertEqual([], plan["candidates"])
        self.assertTrue(
            any(call.kwargs.get("source_device") == source_device for call in snapshot.call_args_list)
        )

    def test_additive_policy_plans_applies_and_binds_path_and_sha(self) -> None:
        root = self.home / "policy-root"
        cache = root / "custom-cache"
        cache.mkdir(parents=True)
        (cache / "CACHEDIR.TAG").write_text(
            "Signature: 8a477f597d28d172789f06886806bc55"
        )
        (cache / "artifact").write_text("generated")
        self.age_tree(cache, days=8)
        policy_path = self.write_policy(root)

        with mock.patch.object(clean_module, "open_file_paths", return_value=set()):
            plan_path, plan = clean_module.create_clean_plan(
                self.paths, policy_path=policy_path
            )

        self.assertEqual(str(policy_path.resolve()), plan["policy"]["path"])
        self.assertEqual(
            clean_module.hashlib.sha256(policy_path.read_bytes()).hexdigest(),
            plan["policy"]["sha256"],
        )
        self.assertEqual(
            [str(cache.resolve())], [item["path"] for item in plan["candidates"]]
        )
        self.assertEqual("policy:custom-cache", plan["candidates"][0]["family"])

        result = apply_clean_plan(self.paths, plan_path)

        self.assertEqual([str(cache.resolve(strict=False))], result["removed"])
        self.assertFalse(cache.exists())

    def test_legacy_schema_two_plan_without_policy_applies(self) -> None:
        cache = self.home / "legacy-schema-two"
        cache.mkdir()
        plan_path = self.write_plan([self.make_item(cache)])
        plan = common_module.load_json(plan_path)
        plan["schema_version"] = 2
        plan.pop("policy")
        atomic_json(plan_path, plan)

        result = apply_clean_plan(self.paths, plan_path)

        self.assertEqual([str(cache)], result["removed"])
        self.assertFalse(cache.exists())

    def test_policy_retention_uses_newest_no_follow_tree_mtime(self) -> None:
        root = self.home / "retention-root"
        cache = root / "custom-cache"
        cache.mkdir(parents=True)
        (cache / "CACHEDIR.TAG").write_text("marker")
        outside = self.home / "outside-target"
        outside.write_text("recent target")
        (cache / "outside-link").symlink_to(outside)
        self.age_tree(cache, days=8)
        policy_path = self.write_policy(root)

        with mock.patch.object(clean_module, "open_file_paths", return_value=set()):
            _, old_plan = clean_module.create_clean_plan(
                self.paths, policy_path=policy_path
            )
        self.assertEqual(
            [str(cache.resolve())], [item["path"] for item in old_plan["candidates"]]
        )

        (cache / "recent-child").write_text("new")
        with mock.patch.object(clean_module, "open_file_paths", return_value=set()):
            _, recent_plan = clean_module.create_clean_plan(
                self.paths, policy_path=policy_path
            )
        self.assertEqual([], recent_plan["candidates"])

    def test_policy_unknown_keys_types_and_unsafe_paths_fail_before_lsof(self) -> None:
        root = self.home / "strict-policy-root"
        root.mkdir()
        policy_path = self.write_policy(root)
        original = common_module.load_json(policy_path)
        cases = {
            "top key": lambda value: value.update(hook="command"),
            "rule key": lambda value: value["rules"][0].update(pattern="*"),
            "schema bool": lambda value: value.update(schema_version=True),
            "retention bool": lambda value: value["rules"][0].update(
                retention_days=True
            ),
            "unsorted markers": lambda value: value["rules"][0].update(
                markers=["second", "first"]
            ),
            "pattern name": lambda value: value["rules"][0].update(name="cache*"),
            "relative root": lambda value: value["rules"][0].update(root="relative"),
            "protected state": lambda value: value["rules"][0].update(
                root=str(self.paths.home), name=".local"
            ),
            "inside state": lambda value: value["rules"][0].update(
                root=str(self.paths.state), name="plans"
            ),
            "policy self-delete": lambda value: value["rules"][0].update(
                root=str(policy_path.parent), name=policy_path.name, markers=[]
            ),
        }
        for name, change in cases.items():
            with self.subTest(name=name):
                malformed = json.loads(json.dumps(original))
                change(malformed)
                atomic_json(policy_path, malformed)
                with mock.patch.object(
                    clean_module, "open_file_paths", return_value=set()
                ) as open_files:
                    with self.assertRaises(ValueError):
                        clean_module.create_clean_plan(
                            self.paths, policy_path=policy_path
                        )
                open_files.assert_not_called()

        nested = json.loads(json.dumps(original))
        nested["rules"].append(
            {
                **nested["rules"][0],
                "root": str((root / nested["rules"][0]["name"]).resolve()),
                "name": "nested-cache",
            }
        )
        (root / nested["rules"][0]["name"]).mkdir()
        atomic_json(policy_path, nested)
        with mock.patch.object(clean_module, "open_file_paths") as open_files:
            with self.assertRaisesRegex(ValueError, "targets overlap"):
                clean_module.create_clean_plan(self.paths, policy_path=policy_path)
        open_files.assert_not_called()

    def test_policy_file_safety_and_duplicate_json_keys_fail_before_lsof(self) -> None:
        root = self.home / "policy-file-root"
        root.mkdir()
        policy_path = self.write_policy(root)
        linked = self.home / "linked-policy.json"
        linked.symlink_to(policy_path)
        with mock.patch.object(clean_module, "open_file_paths") as open_files:
            with self.assertRaises(ValueError):
                clean_module.create_clean_plan(self.paths, policy_path=linked)
        open_files.assert_not_called()

        linked.unlink()
        os.link(policy_path, linked)
        with mock.patch.object(clean_module, "open_file_paths") as open_files:
            with self.assertRaisesRegex(ValueError, "safe regular file"):
                clean_module.create_clean_plan(self.paths, policy_path=policy_path)
        open_files.assert_not_called()
        linked.unlink()

        policy_path.write_text(
            '{"schema_version":1,"schema_version":1,"kind":"clean-policy","rules":[]}',
            encoding="utf-8",
        )
        with mock.patch.object(clean_module, "open_file_paths") as open_files:
            with self.assertRaisesRegex(ValueError, "duplicate key"):
                clean_module.create_clean_plan(self.paths, policy_path=policy_path)
        open_files.assert_not_called()

    def test_policy_change_after_plan_and_during_preflight_causes_zero_mutation(
        self,
    ) -> None:
        root = self.home / "bound-policy-root"
        cache = root / "custom-cache"
        cache.mkdir(parents=True)
        (cache / "CACHEDIR.TAG").write_text("marker")
        self.age_tree(cache, days=8)
        policy_path = self.write_policy(root)
        with mock.patch.object(clean_module, "open_file_paths", return_value=set()):
            plan_path, _ = clean_module.create_clean_plan(
                self.paths, policy_path=policy_path
            )

        policy = common_module.load_json(policy_path)
        policy["rules"][0]["retention_days"] = 8
        atomic_json(policy_path, policy)
        self.open_files.reset_mock()
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            apply_clean_plan(self.paths, plan_path)
        self.open_files.assert_not_called()
        self.assertTrue(cache.is_dir())

        policy["rules"][0]["retention_days"] = 7
        atomic_json(policy_path, policy)
        with mock.patch.object(clean_module, "open_file_paths", return_value=set()):
            later_path, _ = clean_module.create_clean_plan(
                self.paths, policy_path=policy_path
            )
        changed = False

        def change_policy(_paths, *, recursive=False):
            nonlocal changed
            if not changed:
                changed = True
                updated = common_module.load_json(policy_path)
                updated["rules"][0]["retention_days"] = 8
                atomic_json(policy_path, updated)
            return set()

        self.open_files.side_effect = change_policy
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            apply_clean_plan(self.paths, later_path)
        self.assertTrue(cache.is_dir())
        self.assertFalse(
            (
                self.paths.state
                / "clean-quarantine"
                / f"{common_module.load_json(later_path)['run_id']}.intent"
            ).exists()
        )

    def test_policy_marker_change_during_final_lsof_is_preserved(self) -> None:
        root = self.home / "policy-race-root"
        cache = root / "custom-cache"
        cache.mkdir(parents=True)
        marker = cache / "CACHEDIR.TAG"
        marker.write_text("old")
        self.age_tree(cache, days=8)
        policy_path = self.write_policy(root)
        with mock.patch.object(clean_module, "open_file_paths", return_value=set()):
            plan_path, _ = clean_module.create_clean_plan(
                self.paths, policy_path=policy_path
            )
        calls = 0

        def change_marker(_paths, *, recursive=False):
            nonlocal calls
            calls += 1
            if calls == 2:
                marker.write_text("new")
            return set()

        self.open_files.side_effect = change_marker
        result = apply_clean_plan(self.paths, plan_path)

        self.assertTrue(cache.is_dir())
        self.assertEqual("marker or content drift", result["skipped"][0]["reason"])

    def test_cleanup_roots_come_from_platform_and_environment(self) -> None:
        temp_root = self.home / "process-temp"
        cache_root = self.home / "darwin-cache"
        self.assertEqual(
            temp_root.resolve(),
            clean_module._temporary_root({"TMPDIR": str(temp_root)}),
        )
        self.assertEqual(
            cache_root.resolve(),
            clean_module._darwin_cache_root({"DARWIN_USER_CACHE_DIR": str(cache_root)}),
        )
        with self.assertRaisesRegex(ValueError, "TMPDIR must be absolute"):
            clean_module._temporary_root({"TMPDIR": "relative"})
        with self.assertRaisesRegex(ValueError, "TMPDIR must be absolute"):
            clean_module._temporary_root({"TMPDIR": "~/relative"})

        completed = subprocess.CompletedProcess(
            ["getconf", "DARWIN_USER_CACHE_DIR"],
            0,
            stdout=f"{cache_root}\n",
            stderr="",
        )
        with (
            mock.patch.object(
                clean_module.tempfile, "gettempdir", return_value=temp_root
            ),
            mock.patch.object(clean_module.sys, "platform", "darwin"),
            mock.patch.object(clean_module.subprocess, "run", return_value=completed),
        ):
            self.assertEqual(temp_root.resolve(), clean_module._temporary_root({}))
            self.assertEqual(cache_root.resolve(), clean_module._darwin_cache_root({}))
            with mock.patch.object(
                clean_module.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(
                    ["getconf"], 0, stdout="/first\n/second\n", stderr=""
                ),
            ):
                self.assertIsNone(clean_module._darwin_cache_root({}))
            with mock.patch.object(
                clean_module.subprocess, "run", side_effect=FileNotFoundError("getconf")
            ):
                self.assertIsNone(clean_module._darwin_cache_root({}))

        generated = temp_root / "wr-implicit-preview"
        darwin = cache_root / "clang"
        generated.mkdir(parents=True)
        darwin.mkdir(parents=True)
        self.discovery_patcher.stop()
        with mock.patch.object(clean_module, "_walk_markers", return_value=iter(())):
            found = clean_module.discover_practical(
                self.paths,
                environ={
                    "TMPDIR": str(temp_root),
                    "DARWIN_USER_CACHE_DIR": str(cache_root),
                },
            )
        self.assertEqual(
            {generated.resolve(), darwin.resolve()},
            {Path(item["path"]).resolve() for item in found},
        )

    def test_apply_rejects_unsafe_state_anchor_before_cleanup(self) -> None:
        cache = self.home / "unsafe-state-cache"
        cache.mkdir()
        plan = self.write_plan([self.make_item(cache)])
        outside = self.home / "state-outside"
        shutil.move(self.paths.state, outside)
        self.paths.state.symlink_to(outside, target_is_directory=True)
        moved_plan = outside / plan.relative_to(self.paths.state)

        with self.assertRaisesRegex(ValueError, "symlinked ancestor"):
            apply_clean_plan(self.paths, moved_plan)

        self.assertTrue(cache.exists())
        self.open_files.assert_not_called()

    def test_identity_drift_fails_closed(self) -> None:
        cache = self.home / "cache"
        cache.mkdir()
        item = self.make_item(cache)
        plan = self.write_plan([item])
        (cache / "new").write_text("changed")

        with self.assertRaisesRegex(ValueError, "not currently allowed"):
            apply_clean_plan(self.paths, plan)

        self.assertTrue(cache.exists())
        self.open_files.assert_not_called()

    def test_git_tree_is_preserved(self) -> None:
        first = self.home / "first"
        protected = self.home / "protected"
        first.mkdir()
        protected.mkdir()
        (protected / ".git").mkdir()
        plan = self.write_plan([self.make_item(first), self.make_item(protected)])
        with self.assertRaisesRegex(ValueError, "not currently allowed"):
            apply_clean_plan(self.paths, plan)
        self.assertTrue(first.is_dir())
        self.assertTrue(protected.is_dir())
        self.open_files.assert_not_called()

    def test_git_metadata_at_any_depth_is_preserved(self) -> None:
        for action in ("delete-tree", "prune-mixed-cache"):
            for marker_case, name in enumerate((".git", ".GIT")):
                with self.subTest(action=action, name=name):
                    cache = self.home / f"deep-git-{action}-{marker_case}"
                    git = cache / f"a/b/c/d/e/{name}"
                    git.mkdir(parents=True)

                    self.assertIsNone(
                        clean_module._candidate(cache, "fixture", "fixture", action)
                    )

                    git.rmdir()
                    plan = self.write_plan([self.make_item(cache, action)])
                    calls = 0

                    def add_git_during_lsof(candidates, *, recursive=False, **kwargs):
                        nonlocal calls
                        calls += 1
                        if calls == 2:
                            git.mkdir()
                        return set()

                    self.open_files.side_effect = add_git_during_lsof
                    result = apply_clean_plan(self.paths, plan)

                    self.assertTrue(cache.is_dir())
                    self.assertEqual([], result["removed"])
                    self.assertEqual("Git metadata", result["skipped"][0]["reason"])
                    self.open_files.reset_mock(side_effect=True)

    def test_git_scan_does_not_follow_symlink_directories(self) -> None:
        outside = self.home / "outside-git"
        (outside / ".git").mkdir(parents=True)
        cache = self.home / "symlink-cache"
        cache.mkdir()
        (cache / "linked").symlink_to(outside, target_is_directory=True)
        plan = self.write_plan([self.make_item(cache)])

        result = apply_clean_plan(self.paths, plan)

        self.assertFalse(cache.exists())
        self.assertTrue((outside / ".git").is_dir())
        self.assertEqual([], result["skipped"])

    def test_mixed_cache_git_is_rejected_by_discovery_and_apply(self) -> None:
        cache = self.home / "wsms-cache-with-git"
        cache.mkdir()
        (cache / ".git").mkdir()
        self.assertIsNone(
            clean_module._candidate(
                cache, "go-cache", "allowlisted cache name", "prune-mixed-cache"
            )
        )

        item = self.make_item(cache, "prune-mixed-cache")
        plan = self.write_plan([item])
        with mock.patch.object(clean_module, "discover_practical", return_value=[item]):
            result = apply_clean_plan(self.paths, plan)

        self.assertTrue((cache / ".git").is_dir())
        self.assertEqual("Git metadata", result["skipped"][0]["reason"])

    def test_swift_and_rust_require_marker_pairs(self) -> None:
        cases = (
            ("swiftpm", ("workspace-state.json", "build.db")),
            ("rust-target", (".rustc_info.json", "CACHEDIR.TAG")),
        )
        for family, markers in cases:
            with self.subTest(family=family):
                cache = self.home / family
                cache.mkdir()
                first, second = (cache / name for name in markers)
                first.write_text("marker")
                self.assertIsNone(clean_module._candidate(cache, family, "forged"))
                second.write_text("marker")
                item = clean_module._candidate(cache, family, "forged")
                self.assertIsNotNone(item)
                self.assertEqual("+".join(markers), item["marker"])
                second.unlink()
                second.symlink_to(first)
                self.assertIsNone(clean_module._candidate(cache, family, "forged"))

    def test_required_marker_removed_during_lsof_is_preserved(self) -> None:
        cache = self.home / "swift-marker-drift"
        cache.mkdir()
        for name in ("workspace-state.json", "build.db"):
            (cache / name).write_text("marker")
        item = clean_module._candidate(cache, "swiftpm", "forged")
        self.assertIsNotNone(item)
        plan = self.write_plan([item])
        root_mtime_ns = cache.stat().st_mtime_ns
        calls = 0

        def remove_marker_during_lsof(candidates, *, recursive=False, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                (cache / "build.db").unlink()
                os.utime(cache, ns=(root_mtime_ns, root_mtime_ns))
            return set()

        self.open_files.side_effect = remove_marker_during_lsof
        result = apply_clean_plan(self.paths, plan)

        self.assertTrue(cache.is_dir())
        self.assertEqual([], result["removed"])
        self.assertEqual("marker or content drift", result["skipped"][0]["reason"])

    def test_mixed_cache_keeps_metadata(self) -> None:
        cache = self.home / "wsms-cache"
        cache.mkdir()
        (cache / "README.md").write_text("keep")
        (cache / "trim.txt").write_text("keep")
        (cache / "bucket").mkdir()
        (cache / "bucket/data").write_text("drop")
        plan = self.write_plan([self.make_item(cache, "prune-mixed-cache")])
        result = apply_clean_plan(self.paths, plan)
        self.assertEqual([], result["skipped"])
        self.assertTrue((cache / "README.md").exists())
        self.assertTrue((cache / "trim.txt").exists())
        self.assertFalse((cache / "bucket").exists())

    def test_permission_failure_is_isolated(self) -> None:
        denied = self.home / "denied"
        allowed = self.home / "allowed"
        denied.mkdir()
        allowed.mkdir()
        plan = self.write_plan([self.make_item(denied), self.make_item(allowed)])
        original = clean_module.os.replace

        def selective(source: Path, destination: Path) -> None:
            if Path(source) == denied:
                raise PermissionError("fixture denial")
            original(source, destination)

        with mock.patch.object(clean_module.os, "replace", side_effect=selective):
            result = apply_clean_plan(self.paths, plan)
        self.assertTrue(denied.exists())
        self.assertFalse(allowed.exists())
        self.assertEqual(1, len(result["skipped"]))
        self.assertIn("PermissionError", result["skipped"][0]["reason"])

    def test_altered_candidate_fields_are_rejected_before_lsof(self) -> None:
        forged_strings = {
            "family": "forged-family",
            "marker": "forged-marker",
            "action": "prune-mixed-cache",
            "type": "file",
        }
        for field in (
            *forged_strings,
            "allocated_bytes",
            "tree_fingerprint",
            "device",
            "inode",
            "mtime_ns",
        ):
            with self.subTest(field=field):
                cache = self.home / field
                cache.mkdir()
                allowed = self.make_item(cache)
                altered = dict(allowed)
                altered[field] = (
                    forged_strings[field]
                    if field in forged_strings
                    else (
                        "0" * 64
                        if field == "tree_fingerprint"
                        else int(allowed[field]) + 1
                    )
                )
                plan = self.write_plan([altered], allowed=[allowed])

                with self.assertRaisesRegex(ValueError, "not currently allowed"):
                    apply_clean_plan(self.paths, plan)

                self.assertTrue(cache.is_dir())
                self.open_files.assert_not_called()

    def test_profile_and_malformed_candidates_fail_before_lsof(self) -> None:
        cache = self.home / "cache"
        cache.mkdir()
        allowed = self.make_item(cache)
        malformed = dict(allowed)
        malformed.pop("family")
        cases = (
            ("profile", [allowed], "aggressive", "unsupported cleanup profile"),
            ("missing field", [malformed], "practical", "candidate shape"),
            ("non-object", ["forged"], "practical", "candidate shape"),
        )
        for name, candidates, profile, error in cases:
            with self.subTest(name=name):
                plan = self.write_plan(candidates, allowed=[allowed], profile=profile)

                with self.assertRaisesRegex(ValueError, error):
                    apply_clean_plan(self.paths, plan)

                self.assertTrue(cache.is_dir())
                self.open_files.assert_not_called()

        plan = self.write_plan([allowed])
        payload = common_module.load_json(plan)
        payload.pop("candidates")
        atomic_json(plan, payload)
        with self.assertRaisesRegex(ValueError, "plan shape"):
            apply_clean_plan(self.paths, plan)
        self.assertTrue(cache.is_dir())
        self.open_files.assert_not_called()

    def test_plan_contract_is_strict_before_lsof(self) -> None:
        cache = self.home / "strict-plan-cache"
        cache.mkdir()
        item = self.make_item(cache)
        for case in (
            "extra",
            "missing",
            "bool schema",
            "float schema",
            "schema one without policy",
            "time order",
            "run id traversal",
        ):
            with self.subTest(case=case):
                plan = self.write_plan([item])
                payload = common_module.load_json(plan)
                if case == "extra":
                    payload["extra"] = True
                elif case == "missing":
                    payload.pop("kind")
                elif case == "bool schema":
                    payload["schema_version"] = True
                elif case == "float schema":
                    payload["schema_version"] = 1.0
                elif case == "schema one without policy":
                    payload.pop("policy")
                elif case == "time order":
                    payload["created_at"], payload["expires_at"] = (
                        payload["expires_at"],
                        payload["created_at"],
                    )
                else:
                    payload["run_id"] = "../escaped"
                atomic_json(plan, payload)

                with self.assertRaises(ValueError):
                    apply_clean_plan(self.paths, plan)

                self.assertTrue(cache.is_dir())
                self.open_files.assert_not_called()

    def test_unknown_action_is_rejected_even_if_discovery_emits_it(self) -> None:
        cache = self.home / "unknown-action"
        cache.mkdir()
        item = self.make_item(cache)
        item["action"] = "erase-everything"
        plan = self.write_plan([item])

        with (
            mock.patch.object(clean_module, "discover_practical", return_value=[item]),
            self.assertRaisesRegex(ValueError, "unsupported cleanup action"),
        ):
            apply_clean_plan(self.paths, plan)

        self.assertTrue(cache.is_dir())
        self.open_files.assert_not_called()

    def test_invalid_candidate_causes_zero_mutation(self) -> None:
        for case in ("forged", "forged-only", "malformed", "altered"):
            with self.subTest(case=case):
                first = self.home / f"{case}-first"
                second = self.home / f"{case}-second"
                first.mkdir()
                second.mkdir()
                allowed = [self.make_item(first), self.make_item(second)]
                forged = None
                if case.startswith("forged"):
                    forged = self.home / f"{case}-path"
                    forged.mkdir(exist_ok=True)
                    invalid: object = self.make_item(forged)
                else:
                    invalid = dict(allowed[1])
                    if case == "malformed":
                        invalid.pop("marker")
                    else:
                        invalid["family"] = "forged"
                candidates = (
                    [invalid] if case == "forged-only" else [allowed[0], invalid]
                )
                plan = self.write_plan(candidates, allowed=allowed)

                with (
                    mock.patch.object(clean_module, "_delete_tree") as delete_tree,
                    self.assertRaisesRegex(ValueError, "candidate"),
                ):
                    apply_clean_plan(self.paths, plan)

                self.assertTrue(first.is_dir())
                self.assertTrue(second.is_dir())
                if forged is not None:
                    self.assertTrue(forged.is_dir())
                delete_tree.assert_not_called()
                self.open_files.assert_not_called()

    def test_lsof_unavailable_aborts_before_any_mutation(self) -> None:
        first = self.home / "first"
        second = self.home / "second"
        first.mkdir()
        second.mkdir()
        plan = self.write_plan([self.make_item(first), self.make_item(second)])
        self.open_files.side_effect = RuntimeError(
            "open-file enumeration unavailable: lsof was not found"
        )

        with self.assertRaisesRegex(RuntimeError, "lsof was not found"):
            apply_clean_plan(self.paths, plan)

        self.assertTrue(first.is_dir())
        self.assertTrue(second.is_dir())

    def test_lsof_failure_aborts_before_any_mutation(self) -> None:
        first = self.home / "first"
        second = self.home / "second"
        first.mkdir()
        second.mkdir()
        plan = self.write_plan([self.make_item(first), self.make_item(second)])
        self.open_files.side_effect = RuntimeError(
            "path-filtered open-file enumeration failed with status 2"
        )

        with self.assertRaisesRegex(RuntimeError, "status 2"):
            apply_clean_plan(self.paths, plan)

        self.assertTrue(first.is_dir())
        self.assertTrue(second.is_dir())

    def test_each_candidate_gets_fresh_recursive_check(self) -> None:
        opened = self.home / "opened"
        removable = self.home / "removable"
        for path in (opened, removable):
            path.mkdir()
            (path / "artifact").write_text("generated")
        plan = self.write_plan([self.make_item(opened), self.make_item(removable)])
        calls: list[tuple[Path, ...]] = []

        def enumerate_open(candidates, *, recursive=False, **kwargs):
            values = tuple(candidates)
            self.assertTrue(recursive)
            calls.append(values)
            if values == (opened,):
                return {opened / "artifact"}
            return set()

        self.open_files.side_effect = enumerate_open

        result = apply_clean_plan(self.paths, plan)

        self.assertEqual([(opened, removable), (opened,), (removable,)], calls)
        self.assertTrue(opened.is_dir())
        self.assertFalse(removable.exists())
        self.assertEqual("open", result["skipped"][0]["reason"])

    def test_lsof_time_swap_is_preserved_as_identity_drift(self) -> None:
        cache = self.home / "swap-target"
        original = self.home / "swap-original"
        cache.mkdir()
        plan = self.write_plan([self.make_item(cache)])
        calls = 0

        def swap_during_lsof(candidates, *, recursive=False, **kwargs):
            nonlocal calls
            self.assertEqual((cache,), tuple(candidates))
            self.assertTrue(recursive)
            calls += 1
            if calls == 2:
                cache.rename(original)
                cache.mkdir()
            return set()

        self.open_files.side_effect = swap_during_lsof

        result = apply_clean_plan(self.paths, plan)

        self.assertEqual(2, calls)
        self.assertTrue(cache.is_dir())
        self.assertTrue(original.is_dir())
        self.assertEqual([], result["removed"])
        self.assertEqual("identity drift", result["skipped"][0]["reason"])

    def test_descendant_change_during_lsof_is_preserved(self) -> None:
        cache = self.home / "descendant-drift"
        cache.mkdir()
        artifact = cache / "artifact"
        artifact.write_text("planned")
        plan = self.write_plan([self.make_item(cache)])
        calls = 0

        def change_during_lsof(candidates, *, recursive=False, **kwargs):
            nonlocal calls
            self.assertTrue(recursive)
            calls += 1
            if calls == 2:
                artifact.write_bytes(b"changed" * 4096)
            return set()

        self.open_files.side_effect = change_during_lsof

        result = apply_clean_plan(self.paths, plan)

        self.assertEqual(2, calls)
        self.assertTrue(cache.is_dir())
        self.assertEqual([], result["removed"])
        self.assertEqual("marker or content drift", result["skipped"][0]["reason"])

    def test_equal_allocation_change_during_lsof_is_preserved(self) -> None:
        for action in ("delete-tree", "prune-mixed-cache"):
            with self.subTest(action=action):
                cache = self.home / action
                cache.mkdir()
                artifact = cache / "artifact"
                artifact.write_bytes(b"a" * 4096)
                plan = self.write_plan([self.make_item(cache, action)])
                calls = 0

                def change_during_lsof(candidates, *, recursive=False, **kwargs):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        artifact.write_bytes(b"b" * 4096)
                    return set()

                self.open_files.side_effect = change_during_lsof
                result = apply_clean_plan(self.paths, plan)

                self.assertTrue(cache.is_dir())
                self.assertEqual([], result["removed"])
                self.assertEqual(
                    "marker or content drift", result["skipped"][0]["reason"]
                )
                self.open_files.reset_mock(side_effect=True)

    def test_same_name_marker_replacement_during_lsof_is_preserved(self) -> None:
        cache = self.home / "marker-replacement"
        cache.mkdir()
        marker = cache / "marker"
        marker.write_bytes(b"m" * 4096)
        plan = self.write_plan([self.make_item(cache)])
        root_mtime_ns = cache.stat().st_mtime_ns
        calls = 0

        def replace_during_lsof(candidates, *, recursive=False, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                replacement = cache / "replacement"
                replacement.write_bytes(marker.read_bytes())
                replacement.replace(marker)
                os.utime(cache, ns=(root_mtime_ns, root_mtime_ns))
            return set()

        self.open_files.side_effect = replace_during_lsof
        result = apply_clean_plan(self.paths, plan)

        self.assertTrue(cache.is_dir())
        self.assertEqual([], result["removed"])
        self.assertEqual("marker or content drift", result["skipped"][0]["reason"])

    def test_marker_removal_during_lsof_is_preserved(self) -> None:
        cache = self.home / "marker-drift"
        cache.mkdir()
        item = self.make_item(cache)
        plan = self.write_plan([item])

        with mock.patch.object(
            clean_module, "discover_practical", side_effect=([item], [])
        ):
            result = apply_clean_plan(self.paths, plan)

        self.assertTrue(cache.is_dir())
        self.assertEqual([], result["removed"])
        self.assertEqual("marker or content drift", result["skipped"][0]["reason"])

    def test_later_lsof_exec_failure_preserves_current_and_later_candidates(
        self,
    ) -> None:
        first = self.home / "first"
        second = self.home / "second"
        third = self.home / "third"
        for path in (first, second, third):
            path.mkdir()
        plan = self.write_plan(
            [self.make_item(first), self.make_item(second), self.make_item(third)]
        )
        no_match = subprocess.CompletedProcess(["lsof"], 1, stdout="", stderr="")
        self.open_files.side_effect = open_file_paths_for

        with (
            mock.patch.object(
                common_module, "_lsof_binary", return_value="/usr/bin/lsof"
            ),
            mock.patch.object(
                common_module.subprocess,
                "run",
                side_effect=[
                    no_match,
                    no_match,
                    no_match,
                    no_match,
                    FileNotFoundError("lsof disappeared"),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "could not execute"):
                apply_clean_plan(self.paths, plan)

        self.assertFalse(first.exists())
        self.assertTrue(second.is_dir())
        self.assertTrue(third.is_dir())

    def test_recursive_lsof_uses_plus_d_and_parses_status_one_output(self) -> None:
        candidate = self.home / "candidate"
        candidate.mkdir()
        descendant = candidate / "open-artifact"
        completed = subprocess.CompletedProcess(
            ["lsof"], 1, stdout=f"n{descendant}\0\n", stderr=""
        )
        with (
            mock.patch.object(
                common_module, "_lsof_binary", return_value="/usr/bin/lsof"
            ),
            mock.patch.object(
                common_module.subprocess, "run", return_value=completed
            ) as run,
        ):
            result = open_file_paths_for([candidate], recursive=True)

        self.assertEqual({descendant}, result)
        self.assertEqual(
            [
                "/usr/bin/lsof",
                "-nP",
                "-Fn0",
                "-x",
                "f",
                "+D",
                str(candidate),
            ],
            run.call_args.args[0],
        )

    def test_recursive_lsof_rejects_success_status_warning(self) -> None:
        candidate = self.home / "candidate"
        candidate.mkdir()
        completed = subprocess.CompletedProcess(
            ["lsof"], 0, stdout="", stderr="lsof: incomplete traversal"
        )
        with (
            mock.patch.object(
                common_module, "_lsof_binary", return_value="/usr/bin/lsof"
            ),
            mock.patch.object(common_module.subprocess, "run", return_value=completed),
        ):
            with self.assertRaisesRegex(RuntimeError, "incomplete traversal"):
                open_file_paths_for([candidate], recursive=True)

    def test_recursive_lsof_does_not_hide_search_errors(self) -> None:
        candidate = self.home / "candidate"
        candidate.mkdir()
        completed = subprocess.CompletedProcess(
            ["lsof"], 1, stdout="", stderr="lsof: permission denied"
        )
        with (
            mock.patch.object(
                common_module, "_lsof_binary", return_value="/usr/bin/lsof"
            ),
            mock.patch.object(common_module.subprocess, "run", return_value=completed),
        ):
            with self.assertRaisesRegex(RuntimeError, "permission denied"):
                open_file_paths_for([candidate], recursive=True)

    def test_any_open_normalizes_aliases_and_respects_path_components(self) -> None:
        real_parent = self.home / "real"
        candidate = real_parent / "cache"
        candidate.mkdir(parents=True)
        alias_parent = self.home / "alias"
        alias_parent.symlink_to(real_parent, target_is_directory=True)
        alias = alias_parent / "cache"

        self.assertTrue(any_open([alias], {candidate.resolve() / "artifact"}))
        self.assertTrue(
            any_open([alias / "artifact"], {candidate.resolve() / "artifact"})
        )
        self.assertFalse(
            any_open([alias], {real_parent.resolve() / "cache-other" / "artifact"})
        )

    def test_lsof_parser_preserves_newlines_and_normalizes_components(self) -> None:
        newline = self.home / "line-one\nline-two"
        backslash = self.home / r"line-one\nline-two"
        ordinary = self.home / "ordinary"
        self.assertEqual(
            {newline, backslash, ordinary},
            common_module._parse_lsof_paths(
                f"p123\0\nn{str(newline).replace(chr(10), r'\n')}\0"
                f"\nn{str(backslash).replace(chr(92), r'\\')}\0"
                f"\nn{ordinary}\0\n"
            ),
        )
        ambiguous = str(self.home / "control^Aname")
        self.assertEqual(
            {
                Path(ambiguous),
                Path(ambiguous.replace("^A", "\x01")),
            },
            common_module._parse_lsof_paths(f"n{ambiguous}\0"),
        )
        nul_literal = self.home / "literal^@name"
        self.assertEqual(
            {nul_literal}, common_module._parse_lsof_paths(f"n{nul_literal}\0")
        )
        high_byte = os.fsdecode(b"\xff")
        self.assertEqual(
            {self.home / "literal^?name", self.home / f"literal{high_byte}name"},
            common_module._parse_lsof_paths(f"n{self.home / 'literal^?name'}\0"),
        )
        self.assertFalse(any_open([self.home / "unrelated"], {nul_literal}))
        self.assertTrue(any_open([self.home / "CAFÉ"], {self.home / "Cafe\u0301/item"}))
        self.assertFalse(
            any_open([self.home / "cache"], {self.home / "cache-other/item"})
        )
        many_carets = "^A" * 13
        capped = common_module._parse_lsof_paths(
            f"n{self.home.resolve() / 'Café' / many_carets / 'item'}\0"
        )
        self.assertTrue(any_open([self.home / "CAFÉ" / ("\x01" * 13)], capped))
        self.assertFalse(any_open([self.home / "other"], capped))


if __name__ == "__main__":
    unittest.main()
