from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from sesh_compresh.archive import (
    apply_archive_plan,
    create_archive_plan,
    iter_manifests,
    recover_quarantine,
    restore_manifest,
    verify_all,
)
from sesh_compresh.common import AppPaths, atomic_json, sha256_file, utc_now
from sesh_compresh.observer import ClaudeMemPaths


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
        path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
        os.chmod(path, 0o640)
        return path

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

    def test_recent_and_malformed_sessions_are_preserved(self) -> None:
        recent = self.write_session("recent", "2026-07-11T00:00:00Z")
        malformed = self.project / "bad.jsonl"
        malformed.write_text('{"timestamp":"2020-01-01T00:00:00Z"}\nnot-json\n', encoding="utf-8")
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

    def test_recover_restores_quarantined_source(self) -> None:
        original_root = self.home / "source"
        relative = Path("nested/session.jsonl")
        quarantined = self.paths.state / "quarantine/run/item/files" / relative
        quarantined.parent.mkdir(parents=True)
        quarantined.write_text("payload", encoding="utf-8")
        atomic_json(
            self.paths.state / "quarantine/run/item/_restore.json",
            {
                "schema_version": 1,
                "source_root": str(original_root),
                "manifest": "unused",
                "files": [str(relative)],
            },
        )
        result = recover_quarantine(self.paths)
        self.assertEqual({"restored": 1, "conflicts": 0}, result)
        self.assertEqual("payload", (original_root / relative).read_text())


if __name__ == "__main__":
    unittest.main()
