from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sesh_compresh.archive as archive_module
import sesh_compresh.common as common_module
import sesh_compresh.schema as schema_module
from sesh_compresh.common import AppPaths
from sesh_compresh.schema import (
    _inventory_archive_schemas,
    check_archive_schema,
    rebuild_latest_indexes,
)


class SchemaInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name).resolve()
        self.paths = AppPaths.discover(self.home)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_json(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    def manifest(self, name: str, schema: int, *, version: int = 0) -> Path:
        raw = "a" * 64
        compressed = "b" * 64
        source_root = self.home / "source"
        payload = {
            "schema_version": schema,
            "kind": "session-archive",
            "archive_id": "pending",
            "provider": "claude",
            "session_id": name,
            "source_root": str(source_root),
            "last_activity": "2020-01-01T00:00:00Z",
            "archived_at": f"2020-01-{version + 2:02d}T00:00:00Z",
            "zstd_version": "fixture",
            "files": [
                {
                    "path": str(source_root / f"{name}.jsonl"),
                    "relative": f"{name}.jsonl",
                    "device": 1,
                    "inode": 2,
                    "size": 3,
                    "mtime_ns": 4,
                    "mode": 0o600,
                    "raw_sha256": raw,
                    "compressed_sha256": compressed,
                    "object": f"objects/sha256/aa/{raw}.{compressed}.zst",
                }
            ],
            "directories": [],
        }
        key = archive_module._manifest_key(payload)
        payload["archive_id"] = (
            key if version == 0 else f"{key}-v{version:016d}-{'c' * 32}"
        )
        path = self.paths.archive / "manifests/claude" / f"{payload['archive_id']}.json"
        self.write_json(path, payload)
        return path

    def latest_index(self, manifest_path: Path, *, schema: int = 2) -> Path:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        key = archive_module._manifest_session_key(manifest)
        path = self.paths.state / "latest" / f"claude-{key}.json"
        self.write_json(
            path,
            {
                "schema_version": schema,
                "kind": "archive-latest",
                "provider": "claude",
                "session_key": key,
                "version": archive_module._manifest_version(manifest),
                "archive_id": manifest["archive_id"],
                "archived_at": manifest["archived_at"],
                "manifest": str(manifest_path.relative_to(self.paths.archive)),
            },
        )
        return path

    def snapshot(self, paths: list[Path]) -> dict[Path, tuple[int, int, bytes]]:
        return {
            path: (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
            for path in paths
        }

    def test_empty_inventory_does_not_create_roots(self) -> None:
        report = _inventory_archive_schemas(self.paths)

        self.assertEqual(
            {
                "current_schema": 2,
                "supported_schemas": [1, 2],
                "compatible": True,
                "latest_indexes_current": True,
                "manifests": 0,
                "latest_indexes": 0,
                "expected_latest_indexes": 0,
                "manifest_schemas": {},
                "latest_index_schemas": {},
                "missing_latest_indexes": [],
                "stale_latest_indexes": [],
                "unexpected_latest_indexes": [],
                "invalid": [],
                "unsupported": [],
            },
            report,
        )
        self.assertFalse((self.home / ".local").exists())

    def test_supported_inventory_is_exact_and_read_only(self) -> None:
        files = [self.manifest("one", 1), self.manifest("two", 2)]
        files.extend(self.latest_index(path) for path in files.copy())
        before = self.snapshot(files)

        report = _inventory_archive_schemas(self.paths)

        self.assertEqual(before, self.snapshot(files))
        self.assertEqual(
            {
                "current_schema",
                "supported_schemas",
                "compatible",
                "latest_indexes_current",
                "manifests",
                "latest_indexes",
                "expected_latest_indexes",
                "manifest_schemas",
                "latest_index_schemas",
                "missing_latest_indexes",
                "stale_latest_indexes",
                "unexpected_latest_indexes",
                "invalid",
                "unsupported",
            },
            set(report),
        )
        self.assertTrue(report["compatible"])
        self.assertTrue(report["latest_indexes_current"])
        self.assertEqual(2, report["manifests"])
        self.assertEqual(2, report["latest_indexes"])
        self.assertEqual({"1": 1, "2": 1}, report["manifest_schemas"])
        self.assertEqual({"2": 2}, report["latest_index_schemas"])

    def test_invalid_and_unsupported_schemas_are_distinct(self) -> None:
        invalid_manifest = self.manifest("invalid", 2)
        self.write_json(invalid_manifest, {"schema_version": 2})
        future_manifest = self.manifest("future", 3)
        bool_index = self.paths.state / "latest/bool.json"
        future_index = self.paths.state / "latest/future.json"
        self.write_json(bool_index, {"schema_version": True})
        self.write_json(future_index, {"schema_version": 999})
        files = [invalid_manifest, future_manifest, bool_index, future_index]
        before = self.snapshot(files)

        report = _inventory_archive_schemas(self.paths)

        self.assertEqual(before, self.snapshot(files))
        self.assertFalse(report["compatible"])
        self.assertFalse(report["latest_indexes_current"])
        self.assertEqual({"2": 1, "3": 1}, report["manifest_schemas"])
        self.assertEqual({"999": 1}, report["latest_index_schemas"])
        self.assertEqual(2, len(report["invalid"]))
        self.assertEqual(
            {("manifest", 3), ("latest-index", 999)},
            {(item["kind"], item["schema_version"]) for item in report["unsupported"]},
        )

    def test_currentness_reports_highest_missing_stale_and_unexpected(self) -> None:
        first = self.manifest("versioned", 1, version=1)
        second = self.manifest("versioned", 2, version=2)
        stale = self.latest_index(first, schema=1)
        unexpected = self.paths.state / f"latest/claude-{'d' * 20}.json"
        self.write_json(
            unexpected,
            {
                "schema_version": 2,
                "kind": "archive-latest",
                "provider": "claude",
                "session_key": "d" * 20,
                "version": 0,
                "archive_id": "d" * 20,
                "archived_at": "2020-01-01T00:00:00Z",
                "manifest": f"manifests/claude/{'d' * 20}.json",
            },
        )

        report = _inventory_archive_schemas(self.paths)

        self.assertTrue(report["compatible"])
        self.assertFalse(report["latest_indexes_current"])
        self.assertEqual([], report["missing_latest_indexes"])
        self.assertEqual([str(unexpected)], report["unexpected_latest_indexes"])
        self.assertEqual(
            [
                {
                    "path": str(stale),
                    "expected_manifest": str(second.relative_to(self.paths.archive)),
                    "actual_manifest": str(first.relative_to(self.paths.archive)),
                }
            ],
            report["stale_latest_indexes"],
        )

        stale.unlink()
        report = _inventory_archive_schemas(self.paths)
        self.assertEqual([str(stale)], report["missing_latest_indexes"])

    def test_unsafe_entry_fails_without_following_it(self) -> None:
        outside = self.home / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_text("unchanged", encoding="utf-8")
        provider = self.paths.archive / "manifests/linked"
        provider.parent.mkdir(parents=True)
        provider.symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "unsafe entry"):
            _inventory_archive_schemas(self.paths)

        self.assertEqual("unchanged", sentinel.read_text(encoding="utf-8"))

    def test_public_check_is_read_only_and_reports_currentness(self) -> None:
        manifest = self.manifest("check", 2, version=1)
        before = self.snapshot([manifest])

        report = check_archive_schema(self.paths)

        self.assertEqual(before, self.snapshot([manifest]))
        self.assertTrue(report["compatible"])
        self.assertFalse(report["latest_indexes_current"])

    def test_rebuild_writes_highest_indexes_and_preserves_manifests_and_cas(
        self,
    ) -> None:
        first = self.manifest("rebuild", 1, version=1)
        second = self.manifest("rebuild", 2, version=2)
        stale = self.latest_index(first, schema=1)
        orphan = self.paths.state / f"latest/claude-{'d' * 20}.json"
        self.write_json(
            orphan,
            {
                "schema_version": 2,
                "kind": "archive-latest",
                "provider": "claude",
                "session_key": "d" * 20,
                "version": 0,
                "archive_id": "d" * 20,
                "archived_at": "2020-01-01T00:00:00Z",
                "manifest": f"manifests/claude/{'d' * 20}.json",
            },
        )
        cas = self.paths.archive / "objects/sha256/aa/sentinel"
        cas.parent.mkdir(parents=True)
        cas.write_bytes(b"cas unchanged")
        before = self.snapshot([first, second, cas])

        result = rebuild_latest_indexes(self.paths)

        self.assertEqual(before, self.snapshot([first, second, cas]))
        self.assertTrue(result["latest_indexes_current"])
        self.assertEqual(1, result["indexes_written"])
        self.assertEqual(1, result["indexes_removed"])
        self.assertEqual(0, result["manifests_rewritten"])
        self.assertEqual(0, result["cas_objects_rewritten"])
        self.assertFalse(orphan.exists())
        payload = json.loads(stale.read_text(encoding="utf-8"))
        self.assertEqual(
            str(second.relative_to(self.paths.archive)), payload["manifest"]
        )
        self.assertEqual(2, payload["schema_version"])
        retry = rebuild_latest_indexes(self.paths)
        self.assertEqual(0, retry["indexes_written"])
        self.assertEqual(0, retry["indexes_removed"])

    def test_interrupted_rebuild_retries_without_manifest_or_cas_changes(self) -> None:
        first = self.manifest("retry-one", 1, version=1)
        second = self.manifest("retry-two", 2, version=1)
        cas = self.paths.archive / "objects/sha256/aa/retry-sentinel"
        cas.parent.mkdir(parents=True)
        cas.write_bytes(b"cas unchanged")
        before = self.snapshot([first, second, cas])
        real_atomic_json = schema_module.atomic_json
        publications = 0

        def interrupt_second(path, payload):
            nonlocal publications
            publications += 1
            if publications == 2:
                raise OSError("simulated index publication interruption")
            return real_atomic_json(path, payload)

        with mock.patch.object(
            schema_module, "atomic_json", side_effect=interrupt_second
        ):
            with self.assertRaisesRegex(OSError, "publication interruption"):
                rebuild_latest_indexes(self.paths)

        result = rebuild_latest_indexes(self.paths)

        self.assertTrue(result["latest_indexes_current"])
        self.assertEqual(before, self.snapshot([first, second, cas]))

    def test_retry_resyncs_latest_root_after_post_replace_sync_failure(self) -> None:
        self.manifest("replace-sync", 2, version=1)
        latest_root = self.paths.state / "latest"
        real_common_sync = common_module.fsync_dir
        failed = False

        def fail_after_replace(path):
            nonlocal failed
            if path == latest_root and not failed:
                failed = True
                raise OSError("post-replace parent sync failed")
            return real_common_sync(path)

        with mock.patch.object(
            common_module, "fsync_dir", side_effect=fail_after_replace
        ):
            with self.assertRaisesRegex(OSError, "post-replace parent sync failed"):
                rebuild_latest_indexes(self.paths)

        syncs = []
        real_sync = schema_module.fsync_dir

        def track_sync(path):
            syncs.append(path)
            return real_sync(path)

        with mock.patch.object(schema_module, "fsync_dir", side_effect=track_sync):
            retry = rebuild_latest_indexes(self.paths)

        self.assertEqual(0, retry["indexes_written"])
        self.assertIn(latest_root, syncs)
        self.assertTrue(retry["latest_indexes_current"])

    def test_retry_resyncs_latest_root_after_post_unlink_sync_failure(self) -> None:
        manifest = self.manifest("unlink-sync", 2, version=1)
        self.latest_index(manifest)
        orphan = self.paths.state / f"latest/claude-{'d' * 20}.json"
        self.write_json(
            orphan,
            {
                "schema_version": 2,
                "kind": "archive-latest",
                "provider": "claude",
                "session_key": "d" * 20,
                "version": 0,
                "archive_id": "d" * 20,
                "archived_at": "2020-01-01T00:00:00Z",
                "manifest": f"manifests/claude/{'d' * 20}.json",
            },
        )
        latest_root = orphan.parent
        real_sync = schema_module.fsync_dir
        failed = False

        def fail_after_unlink(path):
            nonlocal failed
            if not orphan.exists() and not failed:
                failed = True
                raise OSError("post-unlink parent sync failed")
            return real_sync(path)

        with mock.patch.object(
            schema_module, "fsync_dir", side_effect=fail_after_unlink
        ):
            with self.assertRaisesRegex(OSError, "post-unlink parent sync failed"):
                rebuild_latest_indexes(self.paths)

        syncs = []

        def track_sync(path):
            syncs.append(path)
            return real_sync(path)

        with mock.patch.object(schema_module, "fsync_dir", side_effect=track_sync):
            retry = rebuild_latest_indexes(self.paths)

        self.assertEqual(0, retry["indexes_removed"])
        self.assertIn(latest_root, syncs)
        self.assertTrue(retry["latest_indexes_current"])

    def test_unknown_latest_entry_blocks_rebuild_before_publication(self) -> None:
        manifest = self.manifest("unknown", 2, version=1)
        unknown = self.paths.state / "latest/foreign.tmp"
        unknown.parent.mkdir(parents=True)
        unknown.write_bytes(b"foreign")
        before = self.snapshot([manifest, unknown])

        with mock.patch.object(schema_module, "atomic_json") as publish:
            with self.assertRaisesRegex(ValueError, "unknown entry"):
                rebuild_latest_indexes(self.paths)

        publish.assert_not_called()
        self.assertEqual(before, self.snapshot([manifest, unknown]))

    def test_incompatible_or_unsafe_state_causes_zero_rebuild_mutation(self) -> None:
        manifest = self.manifest("blocked", 2, version=1)
        index = self.latest_index(manifest)
        cases = (
            (manifest, {"schema_version": 999}),
            (index, {"schema_version": 999}),
            (index, {"schema_version": 2}),
        )
        for target, payload in cases:
            with self.subTest(target=target.name, payload=payload):
                original_manifest = self.manifest("blocked", 2, version=1)
                original_index = self.latest_index(original_manifest)
                self.write_json(target, payload)
                files = [original_manifest, original_index]
                before = self.snapshot(files)
                with mock.patch.object(schema_module, "atomic_json") as publish:
                    with self.assertRaisesRegex(ValueError, "incompatible"):
                        rebuild_latest_indexes(self.paths)
                publish.assert_not_called()
                self.assertEqual(before, self.snapshot(files))

        outside = self.home / "unsafe-index"
        outside.write_text("sentinel", encoding="utf-8")
        index.unlink(missing_ok=True)
        index.symlink_to(outside)
        before_manifest = self.snapshot([manifest])
        with self.assertRaisesRegex(ValueError, "unsafe entry"):
            rebuild_latest_indexes(self.paths)
        self.assertEqual(before_manifest, self.snapshot([manifest]))
        self.assertEqual("sentinel", outside.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
