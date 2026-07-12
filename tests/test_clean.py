from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from storage_safeguard.clean import apply_clean_plan
from storage_safeguard.common import AppPaths, atomic_json, iso_utc, utc_now


class CleanupSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.paths = AppPaths.discover(self.home)
        self.paths.ensure_private()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_item(self, path: Path, action: str = "delete-tree") -> dict[str, object]:
        info = path.stat()
        return {
            "path": str(path),
            "family": "fixture",
            "marker": "fixture",
            "action": action,
            "allocated_bytes": 4096,
            "device": info.st_dev,
            "inode": info.st_ino,
            "mtime_ns": info.st_mtime_ns,
            "type": "directory",
        }

    def write_plan(self, items: list[dict[str, object]]) -> Path:
        now = utc_now()
        plan = self.paths.state / "plans/test-clean.json"
        atomic_json(
            plan,
            {
                "schema_version": 1,
                "kind": "clean-plan",
                "profile": "practical",
                "run_id": "test",
                "created_at": iso_utc(now),
                "expires_at": iso_utc(now + timedelta(hours=1)),
                "allocated_bytes": 4096 * len(items),
                "candidates": items,
                "skipped_open": [],
            },
        )
        return plan

    def test_delete_exact_planned_directory(self) -> None:
        cache = self.home / "cache"
        cache.mkdir()
        (cache / "artifact").write_text("generated")
        plan = self.write_plan([self.make_item(cache)])
        result = apply_clean_plan(self.paths, plan)
        self.assertFalse(cache.exists())
        self.assertEqual([], result["skipped"])

    def test_identity_drift_fails_closed(self) -> None:
        cache = self.home / "cache"
        cache.mkdir()
        item = self.make_item(cache)
        (cache / "new").write_text("changed")
        plan = self.write_plan([item])
        result = apply_clean_plan(self.paths, plan)
        self.assertTrue(cache.exists())
        self.assertEqual("identity drift", result["skipped"][0]["reason"])

    def test_git_tree_is_preserved(self) -> None:
        cache = self.home / "cache"
        cache.mkdir()
        (cache / ".git").mkdir()
        plan = self.write_plan([self.make_item(cache)])
        result = apply_clean_plan(self.paths, plan)
        self.assertTrue(cache.exists())
        self.assertEqual("Git metadata", result["skipped"][0]["reason"])

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


if __name__ == "__main__":
    unittest.main()

