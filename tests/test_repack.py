from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import sesh_compresh.repack as repack_module
from sesh_compresh.archive import (
    _zstd_binary,
    archive_planned_session,
    restore_manifest,
    validate_manifest,
    verify_all,
)
from sesh_compresh.common import (
    AppPaths,
    atomic_json,
    regular_file_stat,
    sha256_file,
)
from sesh_compresh.repack import (
    apply_repack_plan,
    create_repack_plan,
    recover_repack,
)


class RepackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.paths = AppPaths.discover(self.home)
        self.project = self.home / ".claude/projects/-repack"
        self.project.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def archive(self, name: str, *, content_name: str | None = None) -> Path:
        source = self.project / f"{name}.jsonl"
        source.write_text(
            json.dumps(
                {
                    "type": "user",
                    "timestamp": "2020-01-01T00:00:00Z",
                    "content": (
                        f"repack fixture {content_name or name} "
                    )
                    * 2000,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        session = {
            "provider": "claude",
            "session_id": f"-repack:{name}",
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
        self.paths.ensure_private()
        result = archive_planned_session(
            self.paths,
            session,
            zstd=_zstd_binary(),
            quarantine_run=self.paths.state / "quarantine" / name,
        )
        return Path(result["manifest"])

    def make_legacy(
        self, manifest_path: Path, *, level: int | None = None
    ) -> tuple[dict, Path]:
        manifest = validate_manifest(manifest_path)
        member = manifest["files"][0]
        current = self.paths.archive / member["object"]
        legacy_relative = (
            f"objects/sha256/{member['raw_sha256'][:2]}/"
            f"{member['raw_sha256']}.zst"
        )
        legacy = self.paths.archive / legacy_relative
        if level is None:
            os.replace(current, legacy)
        else:
            raw = self.home / f"legacy-{level}.raw"
            subprocess.run(
                [_zstd_binary(), "-q", "-d", "-f", str(current), "-o", str(raw)],
                check=True,
            )
            subprocess.run(
                [
                    _zstd_binary(),
                    "-q",
                    f"-{level}",
                    "--check",
                    "-f",
                    str(raw),
                    "-o",
                    str(legacy),
                ],
                check=True,
            )
            current.unlink()
            raw.unlink()
            member["compressed_sha256"] = sha256_file(legacy)
        member["object"] = legacy_relative
        atomic_json(manifest_path, manifest)
        return manifest, legacy

    def test_plan_selects_only_legacy_frames_and_binds_plan_filename(self) -> None:
        legacy_manifest = self.archive("legacy")
        legacy, legacy_object = self.make_legacy(legacy_manifest)
        modern_manifest = self.archive("modern")
        fixed = datetime(2026, 8, 29, 20, 0, tzinfo=UTC)

        plan_path, report = create_repack_plan(
            self.paths,
            minimum_compressed_bytes=0,
            now=fixed,
        )

        self.assertEqual(1, report["candidates"])
        self.assertEqual(1, report["manifests"])
        self.assertEqual(legacy["files"][0]["size"], report["raw_bytes"])
        self.assertEqual(legacy_object.stat().st_size, report["compressed_bytes"])
        self.assertRegex(
            plan_path.name,
            r"^archive-repack-20260829T200000\.000000Z-[0-9a-f]{32}-[0-9a-f]{64}\.json$",
        )
        payload = json.loads(plan_path.read_text(encoding="utf-8"))
        self.assertEqual("archive-repack-plan", payload["kind"])
        self.assertEqual(str(legacy_manifest), payload["items"][0]["manifest"])
        self.assertEqual(
            legacy["files"][0]["object"], payload["items"][0]["object"]
        )
        self.assertNotEqual(str(modern_manifest), payload["items"][0]["manifest"])

    def test_plan_rejects_negative_cutoff_without_creating_state(self) -> None:
        with self.assertRaisesRegex(ValueError, "minimum compressed bytes"):
            create_repack_plan(self.paths, minimum_compressed_bytes=-1)

        self.assertFalse(self.paths.state.exists())

    def test_repack_commands_reject_encrypted_archives(self) -> None:
        manifest_path = self.archive("encrypted-rejection")
        self.make_legacy(manifest_path, level=1)
        plan_path, _ = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )

        with mock.patch.object(
            repack_module, "encryption_config", return_value={"enabled": True}
        ):
            with self.assertRaisesRegex(RuntimeError, "encrypted archives"):
                create_repack_plan(self.paths, minimum_compressed_bytes=0)
            with self.assertRaisesRegex(RuntimeError, "encrypted archives"):
                apply_repack_plan(self.paths, plan_path)
            with self.assertRaisesRegex(RuntimeError, "encrypted archives"):
                recover_repack(self.paths)

    def test_apply_recompresses_losslessly_and_preserves_manifest_identity(self) -> None:
        manifest_path = self.archive("beneficial")
        original, old_object = self.make_legacy(manifest_path, level=1)
        plan_path, _ = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )

        result = apply_repack_plan(self.paths, plan_path)

        updated = validate_manifest(manifest_path)
        self.assertEqual(original["archive_id"], updated["archive_id"])
        self.assertEqual(original["archived_at"], updated["archived_at"])
        before_member = dict(original["files"][0])
        after_member = dict(updated["files"][0])
        for key in ("object", "compressed_sha256"):
            before_member.pop(key)
            after_member.pop(key)
        self.assertEqual(before_member, after_member)
        self.assertNotEqual(
            original["files"][0]["object"], updated["files"][0]["object"]
        )
        self.assertFalse(old_object.exists())
        self.assertEqual(1, result["selected"])
        self.assertEqual(1, result["repacked"])
        self.assertEqual(0, result["non_beneficial"])
        self.assertEqual(1, result["objects_removed"])
        self.assertGreater(result["bytes_reclaimed"], 0)
        self.assertTrue(result["history_recorded"])
        self.assertEqual({"manifests": 1, "files": 1}, verify_all(self.paths))
        destination = self.home / "restored"
        restore_manifest(self.paths, str(manifest_path), destination)
        restored = destination / original["files"][0]["relative"]
        self.assertEqual(original["files"][0]["raw_sha256"], sha256_file(restored))
        history = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in (self.paths.state / "history").glob("*.json")
        ]
        matches = [event for event in history if event["operation"] == "archive-repack"]
        self.assertEqual(1, len(matches))
        event = matches[0]
        self.assertEqual("archive-repack", event["operation"])
        self.assertEqual(0, event["logical_archived_bytes"])
        self.assertEqual(0, event["logical_reclaimed_bytes_delta"])

    def test_apply_rejects_wrong_plan_item_types(self) -> None:
        manifest_path = self.archive("wrong-plan-type")
        self.make_legacy(manifest_path, level=1)
        plan_path, plan = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )
        plan_path.unlink()
        plan["items"][0]["archive_id"] = 7
        forged = plan_path.parent / (
            f"archive-repack-{plan['run_id']}-{repack_module._plan_digest(plan)}.json"
        )
        atomic_json(forged, plan)

        with self.assertRaisesRegex(ValueError, "plan items"):
            apply_repack_plan(self.paths, forged)

    def test_apply_keeps_non_beneficial_legacy_frame_unchanged(self) -> None:
        manifest_path = self.archive("unchanged")
        original, old_object = self.make_legacy(manifest_path, level=19)
        plan_path, _ = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )

        with mock.patch.object(
            repack_module,
            "_stream_recompress",
            side_effect=lambda _zstd, source, target: shutil.copyfile(source, target),
        ):
            result = apply_repack_plan(self.paths, plan_path)

        self.assertEqual(original, validate_manifest(manifest_path))
        self.assertTrue(old_object.is_file())
        self.assertEqual(0, result["repacked"])
        self.assertEqual(1, result["non_beneficial"])
        self.assertEqual(0, result["objects_removed"])

    def test_apply_removes_shared_old_object_after_last_reference_moves(self) -> None:
        first_path = self.archive("shared-a", content_name="shared")
        _, old_object = self.make_legacy(first_path, level=1)
        second_path = self.archive("shared-b", content_name="shared")
        self.assertEqual(
            validate_manifest(first_path)["files"][0]["object"],
            validate_manifest(second_path)["files"][0]["object"],
        )
        plan_path, _ = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )

        result = apply_repack_plan(self.paths, plan_path)

        first = validate_manifest(first_path)["files"][0]["object"]
        second = validate_manifest(second_path)["files"][0]["object"]
        self.assertEqual(first, second)
        self.assertFalse(old_object.exists())
        self.assertEqual(2, result["repacked"])
        self.assertEqual(2, result["manifests_updated"])
        self.assertEqual(1, result["objects_removed"])

    def test_apply_rerun_recognizes_completed_member_but_rejects_logical_drift(
        self,
    ) -> None:
        manifest_path = self.archive("rerun")
        self.make_legacy(manifest_path, level=1)
        plan_path, _ = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )
        first = apply_repack_plan(self.paths, plan_path)

        second = apply_repack_plan(self.paths, plan_path)

        self.assertEqual(1, first["repacked"])
        self.assertEqual(0, second["repacked"])
        self.assertEqual(1, second["already_repacked"])
        manifest = validate_manifest(manifest_path)
        manifest["last_activity"] = "2020-01-02T00:00:00Z"
        atomic_json(manifest_path, manifest)
        with self.assertRaisesRegex(RuntimeError, "logical.*drift"):
            apply_repack_plan(self.paths, plan_path)

    def test_recover_rolls_back_interrupted_compression(self) -> None:
        manifest_path = self.archive("compress-crash")
        original, old_object = self.make_legacy(manifest_path, level=1)
        plan_path, _ = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )

        def crash(_zstd: str, _source: Path, target: Path) -> None:
            target.write_bytes(b"partial")
            raise SystemExit("compression crash")

        with mock.patch.object(repack_module, "_stream_recompress", side_effect=crash):
            with self.assertRaisesRegex(SystemExit, "compression crash"):
                apply_repack_plan(self.paths, plan_path)

        result = recover_repack(self.paths)

        self.assertEqual({"completed": 0, "rolled_back": 1}, result)
        self.assertEqual(original, validate_manifest(manifest_path))
        self.assertTrue(old_object.is_file())
        self.assertEqual([], list((self.paths.state / "repack").iterdir()))

    def test_apply_removes_temporary_when_initial_journal_write_fails(self) -> None:
        manifest_path = self.archive("journal-write-failure")
        original, old_object = self.make_legacy(manifest_path, level=1)
        plan_path, _ = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )

        with mock.patch.object(
            repack_module,
            "_write_journal",
            side_effect=OSError("journal write failed"),
        ):
            with self.assertRaisesRegex(OSError, "journal write failed"):
                apply_repack_plan(self.paths, plan_path)

        self.assertEqual(original, validate_manifest(manifest_path))
        self.assertTrue(old_object.is_file())
        self.assertEqual([], list(old_object.parent.glob("*.part")))
        self.assertEqual([], list((self.paths.state / "repack").iterdir()))

    def test_recover_rolls_back_published_candidate_before_manifest_swap(self) -> None:
        manifest_path = self.archive("publish-crash")
        original, old_object = self.make_legacy(manifest_path, level=1)
        plan_path, _ = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )
        real_atomic = repack_module.atomic_json

        def crash(path: Path, payload: dict, **kwargs) -> None:
            if Path(path) == manifest_path and payload.get("kind") == "session-archive":
                raise SystemExit("manifest crash")
            real_atomic(path, payload, **kwargs)

        with mock.patch.object(repack_module, "atomic_json", side_effect=crash):
            with self.assertRaisesRegex(SystemExit, "manifest crash"):
                apply_repack_plan(self.paths, plan_path)

        journal = json.loads(
            (self.paths.state / "repack/active.json").read_text(encoding="utf-8")
        )
        new_object = self.paths.archive / journal["new_object"]
        self.assertTrue(new_object.is_file())
        result = recover_repack(self.paths)

        self.assertEqual({"completed": 0, "rolled_back": 1}, result)
        self.assertEqual(original, validate_manifest(manifest_path))
        self.assertTrue(old_object.is_file())
        self.assertFalse(new_object.exists())

    def test_recover_completes_committed_manifest_and_old_object_cleanup(self) -> None:
        manifest_path = self.archive("commit-crash")
        original, old_object = self.make_legacy(manifest_path, level=1)
        plan_path, _ = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )

        with mock.patch.object(
            repack_module,
            "_verify_validated_manifest",
            side_effect=SystemExit("verification crash"),
        ):
            with self.assertRaisesRegex(SystemExit, "verification crash"):
                apply_repack_plan(self.paths, plan_path)

        self.assertNotEqual(original, validate_manifest(manifest_path))
        self.assertTrue(old_object.is_file())
        result = recover_repack(self.paths)

        self.assertEqual({"completed": 1, "rolled_back": 0}, result)
        self.assertFalse(old_object.exists())
        self.assertEqual({"manifests": 1, "files": 1}, verify_all(self.paths))

    def test_recover_rejects_forged_journal_without_deleting_objects(self) -> None:
        manifest_path = self.archive("forged-journal")
        _, old_object = self.make_legacy(manifest_path, level=1)
        plan_path, _ = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )
        real_atomic = repack_module.atomic_json

        def crash(path: Path, payload: dict, **kwargs) -> None:
            if Path(path) == manifest_path and payload.get("kind") == "session-archive":
                raise SystemExit("manifest crash")
            real_atomic(path, payload, **kwargs)

        with mock.patch.object(repack_module, "atomic_json", side_effect=crash):
            with self.assertRaises(SystemExit):
                apply_repack_plan(self.paths, plan_path)
        journal_path = self.paths.state / "repack/active.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        new_object = self.paths.archive / journal["new_object"]
        journal["new_object"] = "../escape.zst"
        atomic_json(journal_path, journal)

        with self.assertRaisesRegex(ValueError, "journal"):
            recover_repack(self.paths)

        self.assertTrue(old_object.is_file())
        self.assertTrue(new_object.is_file())
        self.assertTrue(journal_path.is_file())

    def test_apply_validates_unrelated_manifest_before_first_mutation(self) -> None:
        manifest_path = self.archive("preflight")
        original, old_object = self.make_legacy(manifest_path, level=1)
        plan_path, _ = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )
        unrelated = self.paths.archive / "manifests/claude/unrelated.json"
        atomic_json(unrelated, {"kind": "invalid"})

        with self.assertRaisesRegex(ValueError, "manifest"):
            apply_repack_plan(self.paths, plan_path)

        self.assertEqual(original, validate_manifest(manifest_path))
        self.assertTrue(old_object.is_file())
        self.assertEqual([], list((self.paths.state / "repack").iterdir()))

    def test_apply_rejects_any_pending_repack_journal_entry(self) -> None:
        manifest_path = self.archive("pending-journal")
        original, old_object = self.make_legacy(manifest_path, level=1)
        plan_path, _ = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )
        atomic_json(self.paths.state / "repack/unexpected.json", {"forged": True})

        with self.assertRaisesRegex(RuntimeError, "recovery is pending"):
            apply_repack_plan(self.paths, plan_path)

        self.assertEqual(original, validate_manifest(manifest_path))
        self.assertTrue(old_object.is_file())

    def test_apply_rescans_complete_graph_before_old_object_unlink(self) -> None:
        manifest_path = self.archive("rescan-target")
        _, old_object = self.make_legacy(manifest_path, level=1)
        unrelated_manifest = self.archive("rescan-unrelated")
        unrelated = validate_manifest(unrelated_manifest)
        unrelated_object = self.paths.archive / unrelated["files"][0]["object"]
        plan_path, _ = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )
        real_atomic = repack_module.atomic_json

        def remove_unrelated_after_swap(path: Path, payload: dict, **kwargs) -> None:
            real_atomic(path, payload, **kwargs)
            if Path(path) == manifest_path and payload.get("kind") == "session-archive":
                unrelated_object.unlink()

        with mock.patch.object(
            repack_module, "atomic_json", side_effect=remove_unrelated_after_swap
        ):
            with self.assertRaisesRegex(ValueError, "object is unavailable"):
                apply_repack_plan(self.paths, plan_path)

        self.assertTrue(old_object.is_file())

    def test_recover_accepts_crash_after_old_object_unlink(self) -> None:
        manifest_path = self.archive("post-unlink-crash")
        self.make_legacy(manifest_path, level=1)
        plan_path, _ = create_repack_plan(
            self.paths, minimum_compressed_bytes=0
        )

        with mock.patch.object(
            repack_module,
            "_remove_journal",
            side_effect=SystemExit("journal cleanup crash"),
        ):
            with self.assertRaisesRegex(SystemExit, "journal cleanup crash"):
                apply_repack_plan(self.paths, plan_path)

        result = recover_repack(self.paths)

        self.assertEqual({"completed": 1, "rolled_back": 0}, result)
        self.assertEqual({"manifests": 1, "files": 1}, verify_all(self.paths))


if __name__ == "__main__":
    unittest.main()
