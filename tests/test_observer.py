from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

import sesh_compresh.observer as observer_module
import sesh_compresh.archive as archive_module
import sesh_compresh.common as common_module
from sesh_compresh.common import (
    AppPaths,
    app_lock,
    atomic_json,
    iso_utc,
    open_file_paths,
    open_file_paths_for,
    prune_expired_plans,
)
from sesh_compresh.observer import (
    OBSERVER_PROVIDER,
    ClaudeMemPaths,
    apply_observer_expiry_plan,
    apply_observer_gc_plan,
    create_observer_expiry_plan,
    create_observer_gc_plan,
    sanitize_claude_project_path,
)


DATABASE_ID = "11111111-1111-1111-1111-111111111111"
CORPUS_ID = "22222222-2222-2222-2222-222222222222"
ORPHAN_ID = "33333333-3333-3333-3333-333333333333"
RECENT_ID = "44444444-4444-4444-4444-444444444444"
OPEN_ID = "55555555-5555-5555-5555-555555555555"
NEW_REFERENCE_ID = "66666666-6666-6666-6666-666666666666"
CHANGED_ID = "77777777-7777-7777-7777-777777777777"
ARCHIVED_ID = "88888888-8888-8888-8888-888888888888"


class ObserverFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.paths = AppPaths.discover(self.home)
        self.runtime = ClaudeMemPaths.discover(self.paths, environ={})
        self.runtime.data.mkdir(parents=True)
        self._create_database()
        self.runtime.observer_project.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _create_database(self) -> None:
        connection = sqlite3.connect(self.runtime.database)
        try:
            connection.execute(
                "CREATE TABLE sdk_sessions (id INTEGER PRIMARY KEY, memory_session_id TEXT)"
            )
            connection.commit()
        finally:
            connection.close()

    def add_database_reference(self, session_id: str) -> None:
        connection = sqlite3.connect(self.runtime.database)
        try:
            connection.execute(
                "INSERT INTO sdk_sessions(memory_session_id) VALUES (?)",
                (session_id,),
            )
            connection.commit()
        finally:
            connection.close()

    def write_session(self, session_id: str, *, age_hours: int = 3) -> Path:
        path = self.runtime.observer_project / f"{session_id}.jsonl"
        path.write_text(
            json.dumps(
                {
                    "type": "user",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "content": "fixture transcript content",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        modified = datetime.now(UTC) - timedelta(hours=age_hours)
        os.utime(path, (modified.timestamp(), modified.timestamp()))
        return path

    def write_companion(self, session_id: str, *, age_hours: int = 3) -> tuple[Path, Path]:
        root = self.runtime.observer_project / session_id
        nested = root / "attachments"
        nested.mkdir(parents=True)
        member = nested / "payload.bin"
        member.write_bytes(b"companion payload")
        modified = datetime.now(UTC) - timedelta(hours=age_hours)
        for path in (member, nested, root):
            os.utime(path, (modified.timestamp(), modified.timestamp()))
        return root, member

    def plan(self, *, grace_seconds: int = 3600):
        with mock.patch.object(observer_module, "open_file_paths_for", return_value=set()):
            return create_observer_gc_plan(
                self.paths,
                self.runtime,
                grace_seconds=grace_seconds,
            )


class ObserverPathTests(unittest.TestCase):
    def test_sdk_path_sanitization_and_non_default_home(self) -> None:
        value = "/Users/alice/.claude-mem/observer-sessions"
        self.assertEqual(
            "-Users-alice--claude-mem-observer-sessions",
            sanitize_claude_project_path(value),
        )
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            paths = AppPaths.discover(home)
            runtime = ClaudeMemPaths.discover(paths, environ={})
            self.assertEqual((home / ".claude").resolve(), runtime.claude_config)
            self.assertEqual((home / ".claude-mem").resolve(), runtime.data)
            self.assertEqual(
                runtime.claude_config
                / "projects"
                / sanitize_claude_project_path(str(runtime.data / "observer-sessions")),
                runtime.observer_project,
            )

    def test_sdk_sanitization_uses_utf16_units_at_long_path_threshold(self) -> None:
        self.assertEqual("--", sanitize_claude_project_path("😀"))
        value = "x" * 199 + "😀"
        self.assertEqual("x" * 199 + "--strnl1", sanitize_claude_project_path(value))

    def test_strict_lsof_rejects_no_match_exit(self) -> None:
        completed = subprocess.CompletedProcess(["lsof"], 1, stdout="", stderr="")
        with (
            mock.patch.object(common_module.shutil, "which", return_value="/usr/bin/lsof"),
            mock.patch.object(common_module.subprocess, "run", return_value=completed),
        ):
            with self.assertRaisesRegex(RuntimeError, "status 1"):
                open_file_paths(strict=True)

    def test_path_filtered_lsof_is_bounded_and_accepts_empty_no_match(self) -> None:
        candidates = [Path(f"/tmp/candidate-{index}") for index in range(3)]
        completed = [
            subprocess.CompletedProcess(["lsof"], 1, stdout="", stderr=""),
            subprocess.CompletedProcess(
                ["lsof"], 0, stdout=f"n{candidates[2]}\n", stderr=""
            ),
        ]
        with (
            mock.patch.object(common_module, "_lsof_binary", return_value="/usr/bin/lsof"),
            mock.patch.object(common_module.subprocess, "run", side_effect=completed) as run,
        ):
            opened = open_file_paths_for(candidates, batch_size=2)

        self.assertEqual({candidates[2]}, opened)
        self.assertEqual(2, run.call_count)
        self.assertEqual(candidates[:2], [Path(value) for value in run.call_args_list[0].args[0][3:]])

    def test_expired_plan_history_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = AppPaths.discover(Path(temp))
            paths.ensure_private()
            expired_at = datetime.now(UTC) - timedelta(days=1)
            for index in range(6):
                atomic_json(
                    paths.state / "plans" / f"old-{index}.json",
                    {"kind": "fixture", "expires_at": iso_utc(expired_at)},
                )
            self.assertEqual(4, prune_expired_plans(paths, keep=2))
            self.assertEqual(2, len(list((paths.state / "plans").glob("*.json"))))

    def test_app_lock_accepts_injected_portable_backend(self) -> None:
        class FakeBackend:
            def __init__(self) -> None:
                self.events: list[str] = []

            def acquire(self, fd: int) -> None:
                os.fstat(fd)
                self.events.append("acquire")

            def release(self, fd: int) -> None:
                os.fstat(fd)
                self.events.append("release")

        with tempfile.TemporaryDirectory() as temp:
            paths = AppPaths.discover(Path(temp))
            backend = FakeBackend()
            with app_lock(paths, backend=backend):
                backend.events.append("body")
            self.assertEqual(["acquire", "body", "release"], backend.events)

    def test_resolution_matches_claude_mem_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            paths = AppPaths.discover(home)
            default_data = home / ".claude-mem"
            default_data.mkdir()
            atomic_json(
                default_data / "settings.json",
                {
                    "env": {
                        "CLAUDE_MEM_DATA_DIR": "settings-data",
                        "CLAUDE_CONFIG_DIR": "settings-claude",
                    }
                },
            )
            from_settings = ClaudeMemPaths.discover(paths, environ={})
            self.assertEqual((home / "settings-data").resolve(), from_settings.data)
            self.assertEqual((home / ".claude").resolve(), from_settings.claude_config)

            from_env = ClaudeMemPaths.discover(
                paths,
                environ={
                    "CLAUDE_MEM_DATA_DIR": str(home / "env-data"),
                    "CLAUDE_CONFIG_DIR": str(home / "env-claude"),
                },
            )
            self.assertEqual((home / "env-data").resolve(), from_env.data)
            self.assertEqual((home / "env-claude").resolve(), from_env.claude_config)

            from_cli = ClaudeMemPaths.discover(
                paths,
                data=home / "cli-data",
                claude_config=home / "cli-claude",
                environ={
                    "CLAUDE_MEM_DATA_DIR": str(home / "env-data"),
                    "CLAUDE_CONFIG_DIR": str(home / "env-claude"),
                },
            )
            self.assertEqual((home / "cli-data").resolve(), from_cli.data)
            self.assertEqual((home / "cli-claude").resolve(), from_cli.claude_config)

            (default_data / "settings.json").write_text("malformed", encoding="utf-8")
            recovered = ClaudeMemPaths.discover(
                paths,
                data=home / "recovery-data",
                claude_config=home / "recovery-claude",
                environ={},
            )
            self.assertEqual((home / "recovery-data").resolve(), recovered.data)
            self.assertEqual((home / "recovery-claude").resolve(), recovered.claude_config)


class ObserverGcTests(ObserverFixture):
    def test_keep_set_unions_database_and_corpus_roots(self) -> None:
        database = self.write_session(DATABASE_ID)
        corpus = self.write_session(CORPUS_ID)
        orphan = self.write_session(ORPHAN_ID)
        self.add_database_reference(database.stem.upper())
        self.runtime.corpora.mkdir()
        atomic_json(
            self.runtime.corpora / "fixture.corpus.json",
            {"version": 1, "session_id": corpus.stem},
        )

        _, plan = self.plan()

        self.assertEqual([orphan.stem], [item["session_id"] for item in plan["candidates"]])
        self.assertEqual({"database": 1, "corpora": 1, "union": 2}, plan["reference_counts"])
        self.assertEqual(2, plan["protected"]["referenced"])

    def test_non_uuid_jsonl_name_is_preserved_and_counted(self) -> None:
        arbitrary = self.write_session("notes")

        _, plan = self.plan()

        self.assertEqual([], plan["candidates"])
        self.assertEqual(1, plan["protected"]["non_uuid_name"])
        self.assertTrue(arbitrary.exists())

    def test_recent_and_open_sessions_are_protected(self) -> None:
        recent = self.write_session(RECENT_ID, age_hours=0)
        opened = self.write_session(OPEN_ID)
        with mock.patch.object(observer_module, "open_file_paths_for", return_value={opened}):
            _, plan = create_observer_gc_plan(self.paths, self.runtime)
        self.assertEqual([], plan["candidates"])
        self.assertEqual(1, plan["protected"]["recent"])
        self.assertEqual(1, plan["protected"]["open"])
        self.assertTrue(recent.exists())
        self.assertTrue(opened.exists())

    def test_companion_bundle_is_archived_and_removed_together(self) -> None:
        source = self.write_session(ORPHAN_ID)
        companion, member = self.write_companion(ORPHAN_ID)
        plan_path, plan = self.plan()

        self.assertEqual(2, len(plan["candidates"][0]["files"]))
        self.assertEqual(2, len(plan["candidates"][0]["directories"]))
        with mock.patch.object(observer_module, "open_file_paths_for", return_value=set()):
            result = apply_observer_gc_plan(self.paths, self.runtime, plan_path)

        self.assertEqual(1, result["archived"])
        self.assertFalse(source.exists())
        self.assertFalse(member.exists())
        self.assertFalse(companion.exists())
        manifest = json.loads(Path(result["manifests"][0]).read_text(encoding="utf-8"))
        self.assertEqual(
            {source.name, f"{ORPHAN_ID}/attachments/payload.bin"},
            {item["relative"] for item in manifest["files"]},
        )

    def test_reference_protects_primary_and_companion(self) -> None:
        source = self.write_session(DATABASE_ID)
        companion, member = self.write_companion(DATABASE_ID)
        self.add_database_reference(DATABASE_ID)

        _, plan = self.plan()

        self.assertEqual([], plan["candidates"])
        self.assertTrue(source.exists())
        self.assertTrue(companion.exists())
        self.assertTrue(member.exists())

    def test_unsafe_companion_protects_whole_candidate(self) -> None:
        source = self.write_session(ORPHAN_ID)
        companion = self.runtime.observer_project / ORPHAN_ID
        companion.mkdir()
        outside = self.home / "outside"
        outside.write_bytes(b"outside")
        (companion / "escape").symlink_to(outside)

        _, plan = self.plan()

        self.assertEqual([], plan["candidates"])
        self.assertEqual(1, plan["protected"]["unsafe_bundle"])
        self.assertTrue(source.exists())
        self.assertEqual(b"outside", outside.read_bytes())

    def test_open_companion_protects_whole_candidate(self) -> None:
        source = self.write_session(ORPHAN_ID)
        companion, member = self.write_companion(ORPHAN_ID)

        with mock.patch.object(observer_module, "open_file_paths_for", return_value={member}):
            _, plan = create_observer_gc_plan(self.paths, self.runtime)

        self.assertEqual([], plan["candidates"])
        self.assertEqual(1, plan["protected"]["open"])
        self.assertTrue(source.exists())
        self.assertTrue(companion.exists())

    def test_enumerator_database_and_corpus_errors_fail_closed(self) -> None:
        self.write_session(ORPHAN_ID)
        with mock.patch.object(
            observer_module,
            "open_file_paths_for",
            side_effect=RuntimeError("lsof failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "lsof failed"):
                create_observer_gc_plan(self.paths, self.runtime)

        self.runtime.corpora.mkdir()
        (self.runtime.corpora / "bad.corpus.json").write_text("not json", encoding="utf-8")
        with mock.patch.object(observer_module, "open_file_paths_for", return_value=set()):
            with self.assertRaisesRegex(RuntimeError, "malformed claude-mem corpus"):
                create_observer_gc_plan(self.paths, self.runtime)

        self.runtime.database.unlink()
        with mock.patch.object(observer_module, "open_file_paths_for", return_value=set()):
            with self.assertRaisesRegex(RuntimeError, "database is missing"):
                create_observer_gc_plan(self.paths, self.runtime)

    def test_apply_rechecks_references_and_isolates_identity_races(self) -> None:
        newly_referenced = self.write_session(NEW_REFERENCE_ID)
        changed = self.write_session(CHANGED_ID)
        archived = self.write_session(ARCHIVED_ID)
        plan_path, _ = self.plan()
        self.add_database_reference(newly_referenced.stem)
        changed.write_text(changed.read_text() + "{}\n", encoding="utf-8")

        with mock.patch.object(observer_module, "open_file_paths_for", return_value=set()):
            result = apply_observer_gc_plan(self.paths, self.runtime, plan_path)

        self.assertEqual(1, result["archived"])
        self.assertFalse(archived.exists())
        self.assertTrue(newly_referenced.exists())
        self.assertTrue(changed.exists())
        reasons = {item["session_id"]: item["reason"] for item in result["skipped"]}
        self.assertEqual("newly referenced", reasons[newly_referenced.stem])
        self.assertEqual("identity drift", reasons[changed.stem])

    def test_pre_move_callback_catches_new_reference(self) -> None:
        source = self.write_session(ORPHAN_ID)
        plan_path, _ = self.plan()
        empty_counts = {"database": 0, "corpora": 0, "union": 0}

        with (
            mock.patch.object(observer_module, "open_file_paths_for", return_value=set()),
            mock.patch.object(
                observer_module,
                "read_keep_set",
                return_value=(set(), empty_counts),
            ),
            mock.patch.object(observer_module, "session_is_referenced", return_value=True),
        ):
            result = apply_observer_gc_plan(self.paths, self.runtime, plan_path)

        self.assertEqual(0, result["archived"])
        self.assertEqual("newly referenced", result["skipped"][0]["reason"])
        self.assertTrue(source.exists())

    def test_pre_move_liveness_failure_aborts_without_mutation(self) -> None:
        source = self.write_session(ORPHAN_ID)
        plan_path, _ = self.plan()
        counts = {"database": 0, "corpora": 0, "union": 0}

        with (
            mock.patch.object(observer_module, "open_file_paths_for", return_value=set()),
            mock.patch.object(
                observer_module,
                "read_keep_set",
                return_value=(set(), counts),
            ),
            mock.patch.object(
                observer_module,
                "session_is_referenced",
                side_effect=RuntimeError("database snapshot failed"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "database snapshot failed"):
                apply_observer_gc_plan(self.paths, self.runtime, plan_path)
        self.assertTrue(source.exists())

    def test_apply_uses_cached_reads_then_open_reference_move_order(self) -> None:
        source = self.write_session(ORPHAN_ID)
        plan_path, _ = self.plan()
        counts = {"database": 0, "corpora": 0, "union": 0}
        events: list[str] = []
        real_replace = os.replace

        def enumerate_open(_paths) -> set[Path]:
            events.append("open-cached" if "open-cached" not in events else "open-final")
            return set()

        def referenced(_runtime, _session_id: str) -> bool:
            events.append("reference-final")
            return False

        def replace(source_path, destination_path) -> None:
            if Path(source_path) == source:
                events.append("move-source")
            real_replace(source_path, destination_path)

        with (
            mock.patch.object(observer_module, "open_file_paths_for", side_effect=enumerate_open) as opened,
            mock.patch.object(
                observer_module, "read_keep_set", return_value=(set(), counts)
            ) as keep,
            mock.patch.object(observer_module, "session_is_referenced", side_effect=referenced),
            mock.patch.object(archive_module.os, "replace", side_effect=replace),
        ):
            result = apply_observer_gc_plan(self.paths, self.runtime, plan_path)

        self.assertEqual(1, result["archived"])
        self.assertEqual(1, keep.call_count)
        self.assertEqual(2, opened.call_count)
        self.assertEqual(
            ["open-cached", "open-final", "reference-final", "move-source"],
            events,
        )

    def test_malformed_later_gc_entry_causes_zero_mutation(self) -> None:
        first = self.write_session(ORPHAN_ID)
        second = self.write_session(ARCHIVED_ID)
        plan_path, plan = self.plan()
        plan["candidates"][1]["files"][0]["size"] = "invalid"
        atomic_json(plan_path, plan)

        with self.assertRaisesRegex(ValueError, "identity is invalid"):
            apply_observer_gc_plan(self.paths, self.runtime, plan_path)

        self.assertTrue(first.exists())
        self.assertTrue(second.exists())
        self.assertEqual([], list((self.paths.archive / "manifests").rglob("*.json")))

    def test_observer_directory_identity_swap_aborts(self) -> None:
        source = self.write_session(ORPHAN_ID)
        plan_path, _ = self.plan()
        moved = self.runtime.observer_project.with_name("observer-project-original")
        self.runtime.observer_project.rename(moved)
        self.runtime.observer_project.mkdir()

        with mock.patch.object(observer_module, "open_file_paths_for", return_value=set()):
            with self.assertRaisesRegex(RuntimeError, "directory identity drift"):
                apply_observer_gc_plan(self.paths, self.runtime, plan_path)
        self.assertTrue((moved / source.name).exists())

    def test_observer_symlinked_ancestor_aborts(self) -> None:
        source = self.write_session(ORPHAN_ID)
        plan_path, _ = self.plan()
        projects = self.runtime.observer_project.parent
        real_projects = projects.with_name("projects-real")
        projects.rename(real_projects)
        projects.symlink_to(real_projects, target_is_directory=True)

        with mock.patch.object(observer_module, "open_file_paths_for", return_value=set()):
            with self.assertRaisesRegex(RuntimeError, "ancestor is unsafe"):
                apply_observer_gc_plan(self.paths, self.runtime, plan_path)
        self.assertTrue((real_projects / self.runtime.observer_project.name / source.name).exists())


class ObserverExpiryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.paths = AppPaths.discover(self.home)
        self.paths.ensure_private()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_object(self, name: str, size: int = 10) -> str:
        relative = f"objects/sha256/{name[:2]}/{name}.zst"
        path = self.paths.archive / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(name.encode()[:1] * size)
        return relative

    def make_manifest(
        self,
        provider: str,
        name: str,
        archived_at: datetime,
        objects: list[str],
    ) -> Path:
        path = self.paths.archive / "manifests" / provider / f"{name}.json"
        atomic_json(
            path,
            {
                "schema_version": 1,
                "kind": "session-archive",
                "archive_id": name,
                "provider": provider,
                "session_id": name,
                "source_root": "/fixture",
                "last_activity": archived_at.isoformat(),
                "archived_at": archived_at.isoformat(),
                "files": [{"object": value} for value in objects],
            },
        )
        return path

    def test_expiry_is_provider_isolated_and_preserves_shared_cas(self) -> None:
        now = datetime.now(UTC)
        shared = self.make_object("aa-shared")
        observer = self.make_manifest(
            OBSERVER_PROVIDER,
            "observer-old",
            now - timedelta(days=10),
            [shared],
        )
        ordinary = self.make_manifest("claude", "ordinary-old", now - timedelta(days=20), [shared])

        plan_path, plan = create_observer_expiry_plan(
            self.paths,
            ttl_days=7,
            cap_bytes=1024,
            now=now,
        )
        self.assertEqual([str(observer)], [item["path"] for item in plan["manifests"]])
        self.assertEqual([], plan["cas_candidates"])

        result = apply_observer_expiry_plan(self.paths, plan_path)
        self.assertEqual(1, result["manifests_removed"])
        self.assertFalse(observer.exists())
        self.assertTrue(ordinary.exists())
        self.assertTrue((self.paths.archive / shared).exists())

    def test_cap_expires_oldest_and_collects_only_unreachable_objects(self) -> None:
        now = datetime.now(UTC)
        objects = [self.make_object(f"{index:02d}-object", size=10) for index in range(3)]
        manifests = [
            self.make_manifest(
                OBSERVER_PROVIDER,
                f"observer-{index}",
                now - timedelta(hours=3 - index),
                [objects[index]],
            )
            for index in range(3)
        ]

        plan_path, plan = create_observer_expiry_plan(
            self.paths,
            ttl_days=365,
            cap_bytes=15,
            now=now,
        )
        self.assertEqual(
            [str(manifests[0]), str(manifests[1])],
            [item["path"] for item in plan["manifests"]],
        )
        self.assertEqual(2, len(plan["cas_candidates"]))
        self.assertLessEqual(plan["observer_bytes_after"], 15)

        result = apply_observer_expiry_plan(self.paths, plan_path)
        self.assertEqual(2, result["manifests_removed"])
        self.assertEqual(2, result["objects_removed"])
        self.assertTrue(manifests[2].exists())
        self.assertTrue((self.paths.archive / objects[2]).exists())

    def test_manifest_published_after_plan_keeps_cas_reachable(self) -> None:
        now = datetime.now(UTC)
        shared = self.make_object("bb-late-shared")
        observer = self.make_manifest(
            OBSERVER_PROVIDER,
            "observer-old",
            now - timedelta(days=10),
            [shared],
        )
        plan_path, plan = create_observer_expiry_plan(
            self.paths,
            ttl_days=7,
            cap_bytes=1024,
            now=now,
        )
        self.assertEqual(1, len(plan["cas_candidates"]))
        ordinary = self.make_manifest("claude", "published-late", now, [shared])

        result = apply_observer_expiry_plan(self.paths, plan_path)

        self.assertFalse(observer.exists())
        self.assertTrue(ordinary.exists())
        self.assertTrue((self.paths.archive / shared).exists())
        self.assertEqual(0, result["objects_removed"])
        self.assertIn("still reachable", {item["reason"] for item in result["skipped"]})

    def test_identity_pinned_orphan_cas_is_collected(self) -> None:
        digest = "c" * 64
        relative = f"objects/sha256/{digest[:2]}/{digest}.zst"
        orphan = self.paths.archive / relative
        orphan.parent.mkdir(parents=True)
        orphan.write_bytes(b"orphan")

        plan_path, plan = create_observer_expiry_plan(
            self.paths,
            ttl_days=7,
            cap_bytes=1024,
        )
        self.assertEqual([str(orphan)], [item["path"] for item in plan["cas_candidates"]])

        result = apply_observer_expiry_plan(self.paths, plan_path)
        self.assertEqual(1, result["objects_removed"])
        self.assertFalse(orphan.exists())

    def test_symlink_shard_escape_fails_closed(self) -> None:
        now = datetime.now(UTC)
        root = self.paths.archive / "objects" / "sha256"
        root.mkdir(parents=True)
        outside = self.home / "outside-cas"
        outside.mkdir()
        digest = "a" * 64
        outside_object = outside / f"{digest}.zst"
        outside_object.write_bytes(b"outside")
        (root / "aa").symlink_to(outside, target_is_directory=True)
        relative = f"objects/sha256/aa/{digest}.zst"
        self.make_manifest(
            OBSERVER_PROVIDER,
            "observer-symlink-escape",
            now - timedelta(days=10),
            [relative],
        )

        with self.assertRaisesRegex(RuntimeError, "cannot evaluate archive reachability"):
            create_observer_expiry_plan(
                self.paths,
                ttl_days=7,
                cap_bytes=1024,
                now=now,
            )
        self.assertEqual(b"outside", outside_object.read_bytes())

    def test_symlinked_objects_anchor_fails_closed(self) -> None:
        now = datetime.now(UTC)
        outside = self.home / "outside-objects"
        object_path = outside / "sha256" / "aa" / f"{'a' * 64}.zst"
        object_path.parent.mkdir(parents=True)
        object_path.write_bytes(b"outside")
        (self.paths.archive / "objects").symlink_to(outside, target_is_directory=True)
        relative = f"objects/sha256/aa/{'a' * 64}.zst"
        self.make_manifest(
            OBSERVER_PROVIDER,
            "observer-objects-escape",
            now - timedelta(days=10),
            [relative],
        )

        with self.assertRaisesRegex(RuntimeError, "cannot evaluate archive reachability"):
            create_observer_expiry_plan(
                self.paths,
                ttl_days=7,
                cap_bytes=1024,
                now=now,
            )

        self.assertEqual(b"outside", object_path.read_bytes())

    def test_malformed_later_expiry_entry_causes_zero_mutation(self) -> None:
        now = datetime.now(UTC)
        first_object = self.make_object("dd-first")
        second_object = self.make_object("ee-second")
        first = self.make_manifest(
            OBSERVER_PROVIDER,
            "observer-first",
            now - timedelta(days=10),
            [first_object],
        )
        second = self.make_manifest(
            OBSERVER_PROVIDER,
            "observer-second",
            now - timedelta(days=9),
            [second_object],
        )
        plan_path, plan = create_observer_expiry_plan(
            self.paths,
            ttl_days=7,
            cap_bytes=1024,
            now=now,
        )
        plan["manifests"][1]["inode"] = "invalid"
        atomic_json(plan_path, plan)

        with self.assertRaisesRegex(ValueError, "manifest identity is invalid"):
            apply_observer_expiry_plan(self.paths, plan_path)

        self.assertTrue(first.exists())
        self.assertTrue(second.exists())
        self.assertTrue((self.paths.archive / first_object).exists())
        self.assertTrue((self.paths.archive / second_object).exists())


if __name__ == "__main__":
    unittest.main()
