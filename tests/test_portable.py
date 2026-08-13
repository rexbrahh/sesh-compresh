from __future__ import annotations

import hashlib
import json
import stat
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

import sesh_compresh.portable as portable_module
from sesh_compresh.archive import (
    _zstd_binary,
    archive_planned_session,
    iter_manifests,
    list_archives,
    resolve_manifest,
    restore_manifest,
    validate_manifest,
    verify_all,
)
from sesh_compresh.common import (
    AppPaths,
    ensure_safe_cas_shard,
    regular_directory_stat,
    regular_file_stat,
)
from sesh_compresh.portable import (
    apply_portable_import_plan,
    create_portable_import_plan,
    export_portable_archive,
    recover_portable_imports,
)


class PortableArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_paths = AppPaths.discover(self.root / "source-home")
        self.project = self.source_paths.home / ".claude/projects/-portable"
        self.project.mkdir(parents=True)
        self.destination = self.root / "portable.scp.zip"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _session(
        self,
        name: str,
        files: list[Path],
        directories: list[Path] | None = None,
    ) -> dict:
        return {
            "provider": "claude",
            "session_id": f"portable:{name}",
            "source_root": str(self.project),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {
                    "path": str(path),
                    "relative": str(path.relative_to(self.project)),
                    **regular_file_stat(path),
                }
                for path in files
            ],
            "directories": [
                {
                    "path": str(path),
                    "relative": str(path.relative_to(self.project)),
                    **regular_directory_stat(path),
                }
                for path in (directories or [])
            ],
        }

    def _archive(
        self, name: str, session: dict, *, dictionary: Path | None = None
    ) -> Path:
        result = archive_planned_session(
            self.source_paths,
            session,
            zstd=_zstd_binary(),
            quarantine_run=self.source_paths.state / "quarantine" / f"run-{name}",
            dictionary=dictionary,
        )
        return Path(result["manifest"])

    def _fixture_graph(self) -> tuple[list[Path], bytes]:
        self.source_paths.ensure_private()
        dictionary_bytes = (
            b'{"type":"user","timestamp":"2020-01-01T00:00:00Z",'
            b'"content":"common portable vocabulary"}\n' * 32
        )
        dictionary_digest = hashlib.sha256(dictionary_bytes).hexdigest()
        dictionary = (
            ensure_safe_cas_shard(
                self.source_paths.archive, dictionary_digest[:2]
            )
            / f"{dictionary_digest}.dict"
        )
        dictionary.write_bytes(dictionary_bytes)
        dictionary.chmod(0o600)

        primary = self.project / "bundle.jsonl"
        primary_bytes = (
            b'{"type":"user","content":"common portable vocabulary one"}\n'
            * 256
        )
        primary.write_bytes(primary_bytes)
        companion_root = self.project / "bundle"
        companion_root.mkdir()
        companion = companion_root / "copy.jsonl"
        companion.write_bytes(primary_bytes + b'{"copy":true}\n')
        bundle_manifest = self._archive(
            "bundle",
            self._session(
                "bundle", [primary, companion], directories=[companion_root]
            ),
            dictionary=dictionary,
        )

        large = self.project / "large.jsonl"
        line = b'{"type":"user","content":"chunked portable data"}\n'
        large_bytes = line * (1_200_000 // len(line) + 1)
        large.write_bytes(large_bytes)
        large_manifest = self._archive(
            "large", self._session("large", [large])
        )
        return [bundle_manifest, large_manifest], primary_bytes

    def _export_fixture(self) -> tuple[list[Path], dict]:
        manifests, primary_bytes = self._fixture_graph()
        result = export_portable_archive(
            self.source_paths,
            [str(path) for path in [*manifests, manifests[0]]],
            self.destination,
        )
        return manifests, {"result": result, "primary": primary_bytes}

    def _new_paths(self, name: str = "import-home") -> AppPaths:
        return AppPaths.discover(self.root / name)

    def _zip_info(
        self, name: str, *, compression: int = zipfile.ZIP_STORED
    ) -> zipfile.ZipInfo:
        info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
        info.compress_type = compression
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o600) << 16
        return info

    def _rewrite_zip(
        self,
        destination: Path,
        *,
        extra: tuple[str, bytes] | None = None,
        duplicate: str | None = None,
        compress: str | None = None,
        noncanonical_index: bool = False,
        reverse: bool = False,
    ) -> None:
        with zipfile.ZipFile(self.destination, "r") as source:
            entries = [(info.filename, source.read(info)) for info in source.infolist()]
        if noncanonical_index:
            entries = [
                (
                    name,
                    json.dumps(json.loads(data), indent=2).encode("utf-8") + b"\n",
                )
                if name == portable_module.INDEX_NAME
                else (name, data)
                for name, data in entries
            ]
        if reverse:
            entries.reverse()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(destination, "w") as target:
                for name, data in entries:
                    target.writestr(
                        self._zip_info(
                            name,
                            compression=(
                                zipfile.ZIP_DEFLATED
                                if name == compress
                                else zipfile.ZIP_STORED
                            ),
                        ),
                        data,
                    )
                if extra is not None:
                    target.writestr(self._zip_info(extra[0]), extra[1])
                if duplicate is not None:
                    data = next(data for name, data in entries if name == duplicate)
                    target.writestr(self._zip_info(duplicate), data)

    def test_export_import_round_trip_contains_exact_reachable_graph(self) -> None:
        manifests, fixture = self._export_fixture()

        with zipfile.ZipFile(self.destination, "r") as archive:
            index = json.loads(archive.read(portable_module.INDEX_NAME))
            names = [item.filename for item in archive.infolist()]
        expected_objects = {}
        for path in manifests:
            expected_objects.update(
                portable_module._manifest_objects(validate_manifest(path))
            )
        self.assertEqual(sorted(expected_objects), [item["path"] for item in index["objects"]])
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(2, len(index["manifests"]))
        self.assertEqual(fixture["result"]["bundle_id"], index["bundle_id"])

        imported = self._new_paths()
        plan_path, plan = create_portable_import_plan(imported, self.destination)
        self.assertEqual(2, plan["manifests"])
        result = apply_portable_import_plan(imported, plan_path)

        self.assertEqual(2, result["manifests"])
        self.assertEqual(
            {"manifests": 2, "files": 3},
            verify_all(imported),
        )
        imported_manifests = list(iter_manifests(imported))
        bundle = next(
            path
            for path in imported_manifests
            if validate_manifest(path)["session_id"] == "portable:bundle"
        )
        restore_root = self.root / "restored"
        restore_manifest(imported, str(bundle), restore_root)
        self.assertEqual(
            fixture["primary"], (restore_root / "bundle.jsonl").read_bytes()
        )
        self.assertFalse(
            (imported.archive / "dictionaries" / "claude.json").exists()
        )

    def test_strict_zip_validation_rejects_unsafe_or_unindexed_members(self) -> None:
        self._export_fixture()
        index_name = portable_module.INDEX_NAME
        cases = {
            "traversal": {"extra": ("../escape", b"escape")},
            "duplicate": {"duplicate": index_name},
            "compressed": {"compress": index_name},
            "unindexed": {"extra": ("extra.bin", b"extra")},
            "noncanonical-index": {"noncanonical_index": True},
            "reordered": {"reverse": True},
        }
        for name, options in cases.items():
            with self.subTest(case=name):
                malformed = self.root / f"{name}.zip"
                self._rewrite_zip(malformed, **options)
                imported = self._new_paths(f"import-{name}")
                with self.assertRaises(ValueError):
                    create_portable_import_plan(imported, malformed)
                self.assertEqual([], list(iter_manifests(imported)))
                self.assertEqual(
                    [],
                    list((imported.archive / "objects/sha256").glob("*/*")),
                )

    def test_import_plan_rejects_artifact_identity_drift(self) -> None:
        self._export_fixture()
        imported = self._new_paths()
        plan_path, _ = create_portable_import_plan(imported, self.destination)
        with self.destination.open("ab") as artifact:
            artifact.write(b"drift")

        with self.assertRaisesRegex(RuntimeError, "identity changed"):
            apply_portable_import_plan(imported, plan_path)
        self.assertEqual([], list(iter_manifests(imported)))

    def test_import_rejects_run_id_collision_with_a_different_plan(self) -> None:
        self._export_fixture()
        imported = self._new_paths()
        plan_a_path, plan_a = create_portable_import_plan(
            imported, self.destination
        )
        real_publish = portable_module._publish_file

        with mock.patch.object(
            portable_module,
            "_publish_file",
            side_effect=RuntimeError("leave staged plan A"),
        ):
            with self.assertRaisesRegex(RuntimeError, "leave staged plan A"):
                apply_portable_import_plan(imported, plan_a_path)

        different_artifact = self.root / "different.scp.zip"
        with zipfile.ZipFile(self.destination, "r") as source, zipfile.ZipFile(
            different_artifact, "w"
        ) as target:
            for info in source.infolist():
                target.writestr(info, source.read(info))
        different_artifact.touch()
        with mock.patch.object(
            portable_module,
            "new_run_id",
            return_value=plan_a["run_id"],
        ):
            plan_b_path, _ = create_portable_import_plan(
                imported, different_artifact
            )

        with mock.patch.object(portable_module, "_publish_file", real_publish):
            with self.assertRaisesRegex(RuntimeError, "different plan"):
                apply_portable_import_plan(imported, plan_b_path)
        self.assertEqual([], list(iter_manifests(imported)))

    def test_import_reuses_exact_object_and_rejects_conflicting_object(self) -> None:
        self._export_fixture()
        index, _ = portable_module._inspect_zip(self.destination)
        object_entry = index["objects"][0]
        with zipfile.ZipFile(self.destination, "r") as archive:
            object_bytes = archive.read(object_entry["path"])

        exact_paths = self._new_paths("import-exact")
        exact_paths.ensure_private()
        exact_target = exact_paths.archive / object_entry["path"]
        ensure_safe_cas_shard(exact_paths.archive, exact_target.parent.name)
        exact_target.write_bytes(object_bytes)
        exact_target.chmod(0o600)
        exact_plan, _ = create_portable_import_plan(exact_paths, self.destination)
        exact_result = apply_portable_import_plan(exact_paths, exact_plan)
        self.assertGreaterEqual(exact_result["reused"], 1)
        self.assertEqual(
            {"manifests": 2, "files": 3}, verify_all(exact_paths)
        )

        conflict_paths = self._new_paths("import-conflict")
        conflict_paths.ensure_private()
        conflict_target = conflict_paths.archive / object_entry["path"]
        ensure_safe_cas_shard(conflict_paths.archive, conflict_target.parent.name)
        conflict_target.write_bytes(b"conflict")
        conflict_target.chmod(0o600)
        conflict_plan, _ = create_portable_import_plan(
            conflict_paths, self.destination
        )
        with self.assertRaisesRegex(RuntimeError, "target conflicts"):
            apply_portable_import_plan(conflict_paths, conflict_plan)
        self.assertEqual(b"conflict", conflict_target.read_bytes())
        self.assertEqual([], list(iter_manifests(conflict_paths)))

    def test_import_publication_binds_retained_temp_for_objects_and_manifests(
        self,
    ) -> None:
        self._export_fixture()
        real_link = portable_module._link_portable_temp
        foreign = b"foreign portable publication"
        for target_kind in ("objects", "manifests"):
            for race in ("temp-replacement", "same-inode-mutation", "target-replacement"):
                with self.subTest(target_kind=target_kind, race=race):
                    imported = self._new_paths(f"race-{target_kind}-{race}")
                    plan_path, _ = create_portable_import_plan(
                        imported, self.destination
                    )
                    raced: dict[str, Path] = {}

                    def race_link(source: Path, target: Path) -> None:
                        if target_kind not in target.parts or raced:
                            real_link(source, target)
                            return
                        raced["source"] = source
                        raced["target"] = target
                        if race == "temp-replacement":
                            displaced = source.with_name(source.name + ".displaced")
                            source.rename(displaced)
                            source.write_bytes(foreign)
                            real_link(source, target)
                        elif race == "same-inode-mutation":
                            real_link(source, target)
                            with source.open("wb") as handle:
                                handle.write(foreign)
                        else:
                            real_link(source, target)
                            target.unlink()
                            target.write_bytes(foreign)

                    with mock.patch.object(
                        portable_module,
                        "_link_portable_temp",
                        side_effect=race_link,
                    ):
                        with self.assertRaisesRegex(
                            RuntimeError,
                            "(identity|retained content) changed",
                        ):
                            apply_portable_import_plan(imported, plan_path)

                    self.assertTrue(raced)
                    self.assertEqual(foreign, raced["target"].read_bytes())
                    if race != "target-replacement":
                        self.assertEqual(foreign, raced["source"].read_bytes())
                    if target_kind == "objects":
                        self.assertEqual([], list(iter_manifests(imported)))

    def test_export_rejects_replaced_temp_and_preserves_foreign_paths(self) -> None:
        manifests, _ = self._fixture_graph()
        real_link = portable_module._link_portable_temp
        foreign = b"foreign portable export"
        raced: dict[str, Path] = {}

        def replace_temp(source: Path, target: Path) -> None:
            displaced = source.with_name(source.name + ".displaced")
            source.rename(displaced)
            source.write_bytes(foreign)
            raced.update(source=source, target=target, displaced=displaced)
            real_link(source, target)

        with mock.patch.object(
            portable_module,
            "_link_portable_temp",
            side_effect=replace_temp,
        ):
            with self.assertRaisesRegex(RuntimeError, "published identity changed"):
                export_portable_archive(
                    self.source_paths,
                    [str(path) for path in manifests],
                    self.destination,
                )

        self.assertEqual(foreign, raced["source"].read_bytes())
        self.assertEqual(foreign, raced["target"].read_bytes())
        with zipfile.ZipFile(raced["displaced"], "r") as archive:
            self.assertIn(portable_module.INDEX_NAME, archive.namelist())

    def test_recovery_finishes_objects_before_manifests_after_interruption(self) -> None:
        self._export_fixture()
        imported = self._new_paths()
        plan_path, _ = create_portable_import_plan(imported, self.destination)
        events: list[tuple[bool, str]] = []
        real_publish = portable_module._publish_file

        def interrupt_before_manifest(
            source: Path,
            target: Path,
            expected_size: int,
            expected_sha256: str,
            *,
            cas_object: bool,
        ) -> bool:
            events.append((cas_object, str(target)))
            if not cas_object:
                raise RuntimeError("injected import interruption")
            return real_publish(
                source,
                target,
                expected_size,
                expected_sha256,
                cas_object=cas_object,
            )

        with mock.patch.object(
            portable_module,
            "_publish_file",
            side_effect=interrupt_before_manifest,
        ):
            with self.assertRaisesRegex(RuntimeError, "injected import interruption"):
                apply_portable_import_plan(imported, plan_path)

        first_manifest = next(index for index, item in enumerate(events) if not item[0])
        self.assertTrue(all(item[0] for item in events[:first_manifest]))
        self.assertEqual([], list(iter_manifests(imported)))
        intents = list(
            (imported.state / "portable-imports").glob("*/intent.json")
        )
        self.assertEqual(1, len(intents))
        generation, hidden = portable_module.portable_manifest_visibility(imported)
        intent = json.loads(intents[0].read_text())
        self.assertGreaterEqual(generation, 1)
        self.assertEqual(
            {item["path"] for item in intent["manifests"]},
            set(hidden),
        )

        recovered = recover_portable_imports(imported)

        self.assertEqual(1, recovered["completed"])
        self.assertEqual([], recovered["incomplete"])
        committed_generation, hidden = portable_module.portable_manifest_visibility(
            imported
        )
        self.assertGreater(committed_generation, generation)
        self.assertEqual(frozenset(), hidden)
        self.assertEqual(
            {"manifests": 2, "files": 3}, verify_all(imported)
        )
        self.assertEqual(
            [], list((imported.state / "portable-imports").iterdir())
        )

    def test_second_manifest_interruption_hides_the_partial_import(self) -> None:
        self._export_fixture()
        imported = self._new_paths()
        plan_path, _ = create_portable_import_plan(imported, self.destination)
        real_publish = portable_module._publish_file
        manifest_calls = 0

        def interrupt_second_manifest(
            source: Path,
            target: Path,
            expected_size: int,
            expected_sha256: str,
            *,
            cas_object: bool,
        ) -> bool:
            nonlocal manifest_calls
            if not cas_object:
                manifest_calls += 1
                if manifest_calls == 2:
                    raise RuntimeError("injected second-manifest interruption")
            return real_publish(
                source,
                target,
                expected_size,
                expected_sha256,
                cas_object=cas_object,
            )

        with mock.patch.object(
            portable_module,
            "_publish_file",
            side_effect=interrupt_second_manifest,
        ):
            with self.assertRaisesRegex(RuntimeError, "second-manifest"):
                apply_portable_import_plan(imported, plan_path)

        physical = list((imported.archive / "manifests").glob("*/*.json"))
        self.assertEqual(1, len(physical))
        self.assertEqual([], list(iter_manifests(imported)))
        self.assertEqual([], list_archives(imported))
        self.assertEqual({"manifests": 0, "files": 0}, verify_all(imported))
        with self.assertRaisesRegex(ValueError, "matched 0"):
            resolve_manifest(imported, physical[0].stem)
        with self.assertRaisesRegex(ValueError, "not committed"):
            resolve_manifest(imported, str(physical[0]))
        with self.assertRaisesRegex(ValueError, "not committed"):
            restore_manifest(imported, str(physical[0]), self.root / "hidden")

        self.assertEqual(1, recover_portable_imports(imported)["completed"])
        self.assertEqual(2, len(list(iter_manifests(imported))))

    def test_recovery_resyncs_exact_reused_target_before_commit(self) -> None:
        self._export_fixture()
        imported = self._new_paths()
        plan_path, _ = create_portable_import_plan(imported, self.destination)
        real_fsync = portable_module.fsync_dir
        failed_parent: Path | None = None
        injected = False

        def fail_first_manifest_sync(path: Path) -> None:
            nonlocal failed_parent, injected
            real_fsync(path)
            if not injected and path.parent == imported.archive / "manifests":
                injected = True
                failed_parent = path
                raise OSError("injected manifest parent fsync failure")

        with mock.patch.object(
            portable_module,
            "fsync_dir",
            side_effect=fail_first_manifest_sync,
        ):
            with self.assertRaisesRegex(OSError, "manifest parent fsync"):
                apply_portable_import_plan(imported, plan_path)

        intent_path = next(
            (imported.state / "portable-imports").glob("*/intent.json")
        )
        self.assertEqual("publishing", json.loads(intent_path.read_text())["phase"])
        self.assertIsNotNone(failed_parent)
        self.assertEqual(1, len(list(failed_parent.glob("*.json"))))
        synced: list[Path] = []

        def record_sync(path: Path) -> None:
            synced.append(path)
            real_fsync(path)

        with mock.patch.object(
            portable_module, "fsync_dir", side_effect=record_sync
        ):
            recovered = recover_portable_imports(imported)

        self.assertEqual(1, recovered["completed"])
        self.assertIn(failed_parent, synced)
        self.assertEqual(2, len(list(iter_manifests(imported))))

    def test_manifest_enumeration_retries_a_visibility_generation_change(self) -> None:
        manifests = self._fixture_graph()[0]
        hidden = frozenset(
            manifest.relative_to(self.source_paths.archive).as_posix()
            for manifest in manifests
        )
        snapshots = [
            (0, frozenset()),
            (1, hidden),
            (1, hidden),
            (1, hidden),
        ]
        with mock.patch.object(
            portable_module,
            "portable_manifest_visibility",
            side_effect=snapshots,
        ) as visibility:
            self.assertEqual([], list(iter_manifests(self.source_paths)))
        self.assertEqual(4, visibility.call_count)

    def test_latest_index_failure_keeps_committed_intent_for_retry(self) -> None:
        self._export_fixture()
        imported = self._new_paths()
        plan_path, _ = create_portable_import_plan(imported, self.destination)

        with mock.patch.object(
            portable_module,
            "_refresh_latest_indexes",
            side_effect=RuntimeError("injected latest-index failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "latest-index failure"):
                apply_portable_import_plan(imported, plan_path)

        self.assertEqual(2, len(list(iter_manifests(imported))))
        intent_path = next(
            (imported.state / "portable-imports").glob("*/intent.json")
        )
        self.assertEqual(
            "committed", json.loads(intent_path.read_text())["phase"]
        )
        _, hidden = portable_module.portable_manifest_visibility(imported)
        self.assertEqual(frozenset(), hidden)

        recovered = recover_portable_imports(imported)

        self.assertEqual(1, recovered["completed"])
        self.assertEqual(2, len(list((imported.state / "latest").glob("*.json"))))
        self.assertEqual(
            [], list((imported.state / "portable-imports").iterdir())
        )

    def test_cleanup_failure_preserves_intent_and_resumes_without_stage(self) -> None:
        self._export_fixture()
        imported = self._new_paths()
        plan_path, _ = create_portable_import_plan(imported, self.destination)
        real_rmtree = portable_module.shutil.rmtree
        failed = False

        def remove_stage_then_fail(path: Path, *args, **kwargs) -> None:
            nonlocal failed
            real_rmtree(path, *args, **kwargs)
            target = Path(path)
            if (
                not failed
                and target.name == "archive"
                and target.parent.parent == imported.state / "portable-imports"
            ):
                failed = True
                raise RuntimeError("injected cleanup failure")

        with mock.patch.object(
            portable_module.shutil,
            "rmtree",
            side_effect=remove_stage_then_fail,
        ):
            with self.assertRaisesRegex(RuntimeError, "cleanup failure"):
                apply_portable_import_plan(imported, plan_path)

        intent_path = next(
            (imported.state / "portable-imports").glob("*/intent.json")
        )
        self.assertEqual("cleanup", json.loads(intent_path.read_text())["phase"])
        self.assertFalse((intent_path.parent / "archive").exists())
        self.assertEqual(
            {"manifests": 2, "files": 3}, verify_all(imported)
        )

        recovered = recover_portable_imports(imported)

        self.assertEqual(1, recovered["completed"])
        self.assertEqual(
            [], list((imported.state / "portable-imports").iterdir())
        )


if __name__ == "__main__":
    unittest.main()
