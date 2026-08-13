from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sesh_compresh.common import AppPaths
from sesh_compresh.history import (
    append_history_event,
    cas_id,
    history_summary,
    record_history_after_success,
    source_id,
)


class MaintenanceHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.paths = AppPaths.discover(Path(self.temp.name))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_events_are_immutable_private_and_do_not_store_raw_identities(self) -> None:
        raw_source = "/private/project/secret/session.jsonl"
        raw_object = "objects/sha256/ab/abcdef.zst"
        event = append_history_event(
            self.paths,
            operation="archive-direct",
            provider="claude",
            logical_archived_bytes=500,
            physical_allocated_bytes_delta=80,
            observed_free_bytes_delta=420,
            sources={raw_source: 500},
            cas_objects={raw_object: 80},
        )

        encoded = event.read_text(encoding="utf-8")
        self.assertNotIn(raw_source, encoded)
        self.assertNotIn(raw_object, encoded)
        self.assertIn(source_id(raw_source), encoded)
        self.assertIn(cas_id(raw_object), encoded)
        if os.name != "nt":
            self.assertEqual(0o600, event.stat().st_mode & 0o777)
            self.assertEqual(0o700, event.parent.stat().st_mode & 0o777)
        with mock.patch(
            "sesh_compresh.history.new_run_id",
            return_value=event.stem,
        ):
            with self.assertRaises(FileExistsError):
                append_history_event(
                    self.paths,
                    operation="archive-direct",
                )

    def test_summary_deduplicates_cas_and_reports_growth_and_separate_deltas(self) -> None:
        with mock.patch(
            "sesh_compresh.history.new_run_id",
            side_effect=[
                "20260101T000000.000000Z-00000000000000000000000000000001",
                "20260102T000000.000000Z-00000000000000000000000000000002",
                "20260102T010000.000000Z-00000000000000000000000000000003",
            ],
        ), mock.patch(
            "sesh_compresh.history.iso_utc",
            side_effect=[
                "2026-01-01T00:00:00Z",
                "2026-01-02T00:00:00Z",
                "2026-01-02T01:00:00Z",
            ],
        ):
            append_history_event(
                self.paths,
                operation="archive-direct",
                provider="claude",
                logical_archived_bytes=100,
                physical_allocated_bytes_delta=40,
                observed_free_bytes_delta=60,
                sources={"session-a": 100},
                cas_objects={"object-shared": 40},
            )
            append_history_event(
                self.paths,
                operation="archive-apply",
                provider="claude",
                logical_archived_bytes=150,
                physical_allocated_bytes_delta=10,
                observed_free_bytes_delta=50,
                sources={"session-a": 150},
                cas_objects={"object-shared": 40, "object-new": 10},
            )
            append_history_event(
                self.paths,
                operation="clean-expiry",
                logical_reclaimed_bytes_delta=25,
                physical_allocated_bytes_delta=-25,
                observed_free_bytes_delta=25,
                sources={"cache-a": 25},
            )

        summary = history_summary(self.paths)

        self.assertEqual(3, summary["events"])
        self.assertEqual(250, summary["logical_archived_bytes"])
        self.assertEqual(25, summary["logical_reclaimed_bytes_delta"])
        self.assertEqual(25, summary["physical_allocated_bytes_delta"])
        self.assertEqual(135, summary["observed_free_bytes_delta"])
        self.assertEqual(50, summary["unique_cas_bytes"])
        self.assertEqual(150, summary["unique_source_logical_bytes"])
        self.assertEqual(100, summary["unique_bytes_saved"])
        self.assertEqual(50, summary["top_growth_sources"][0]["growth_bytes"])
        self.assertEqual(3, len(summary["provider_utc_trends"]))

    def test_reader_rejects_unknown_symlink_and_conflicting_cas_entries(self) -> None:
        event = append_history_event(
            self.paths,
            operation="archive-direct",
            cas_objects={"same-object": 10},
        )
        unexpected = event.parent / "README"
        unexpected.write_text("not an event", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "history entry is unsafe"):
            history_summary(self.paths)
        unexpected.unlink()

        linked = event.parent / "linked.json"
        linked.symlink_to(event)
        with self.assertRaisesRegex(ValueError, "history entry is unsafe"):
            history_summary(self.paths)
        linked.unlink()

        second = append_history_event(
            self.paths,
            operation="archive-apply",
            cas_objects={"same-object": 10},
        )
        payload = json.loads(second.read_text(encoding="utf-8"))
        payload["cas_objects"][0]["bytes"] = 11
        second.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "conflicting sizes"):
            history_summary(self.paths)

    @unittest.skipIf(os.name == "nt", "POSIX permissions and hardlinks")
    def test_reader_rejects_public_or_hardlinked_event(self) -> None:
        event = append_history_event(
            self.paths,
            operation="archive-direct",
        )
        event.chmod(0o666)
        with self.assertRaisesRegex(ValueError, "history entry is unsafe"):
            history_summary(self.paths)
        event.chmod(0o600)

        external = self.paths.home / "external-event.json"
        os.link(event, external)
        with self.assertRaisesRegex(ValueError, "history entry is unsafe"):
            history_summary(self.paths)

    def test_reader_rejects_event_id_timestamp_mismatch(self) -> None:
        event = append_history_event(
            self.paths,
            operation="archive-direct",
        )
        payload = json.loads(event.read_text(encoding="utf-8"))
        payload["recorded_at"] = "2000-01-01T00:00:00Z"
        event.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "identity timestamp does not match"):
            history_summary(self.paths)

    def test_append_rejects_invalid_metrics_and_provider(self) -> None:
        cases = [
            {"logical_archived_bytes": -1},
            {"logical_archived_bytes": True},
            {"provider": "../../secret"},
            {"sources": {"source": -1}},
            {"cas_objects": {"object": True}},
        ]
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    append_history_event(
                        self.paths,
                        operation="archive-direct",
                        **values,
                    )

    def test_post_success_append_failure_is_explicit_without_raising(self) -> None:
        result = {"reclaimed_bytes": 42}
        with mock.patch(
            "sesh_compresh.history.append_history_event",
            side_effect=OSError("disk full"),
        ):
            recorded = record_history_after_success(
                self.paths,
                result,
                operation="clean-expiry",
            )

        self.assertEqual(42, recorded["reclaimed_bytes"])
        self.assertFalse(recorded["history_recorded"])
        self.assertEqual(
            "maintenance history append failed", recorded["history_warning"]
        )

    def test_cas_union_is_historical_and_deduplicated_by_identity(self) -> None:
        append_history_event(
            self.paths,
            operation="archive-direct",
            logical_archived_bytes=100,
            sources={"session": 100},
            cas_objects={"old": 25, "kept": 20},
        )
        append_history_event(
            self.paths,
            operation="archive-expiry",
            physical_allocated_bytes_delta=-25,
            cas_objects={"old": 25},
        )

        summary = history_summary(self.paths)

        self.assertEqual(45, summary["unique_cas_bytes"])
        self.assertEqual(55, summary["unique_bytes_saved"])


if __name__ == "__main__":
    unittest.main()
