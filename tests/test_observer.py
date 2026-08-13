from __future__ import annotations

import errno
import hashlib
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
import sesh_compresh.history as history_module
from sesh_compresh.common import (
    AppPaths,
    app_lock,
    atomic_json,
    ensure_safe_cas_shard,
    fsync_dir,
    iso_utc,
    open_file_paths,
    open_file_paths_for,
    prune_expired_plans,
)
from sesh_compresh.observer import (
    OBSERVER_PROVIDER,
    ClaudeMemPaths,
    apply_archive_expiry_plan,
    apply_observer_expiry_plan,
    apply_observer_gc_plan,
    create_archive_expiry_plan,
    create_observer_expiry_plan,
    create_observer_gc_plan,
    list_holds,
    pin_archive_version,
    pin_live_session,
    remove_hold,
    sanitize_claude_project_path,
)
from sesh_compresh.history import history_summary


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

    def write_companion(
        self, session_id: str, *, age_hours: int = 3
    ) -> tuple[Path, Path]:
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
        with mock.patch.object(
            observer_module, "open_file_paths_for", return_value=set()
        ):
            return create_observer_gc_plan(
                self.paths,
                self.runtime,
                grace_seconds=grace_seconds,
            )


class ObserverPathTests(unittest.TestCase):
    def test_directory_fsync_propagates_real_failures(self) -> None:
        path = Path("/fixture/directory")
        for stage, failure in (
            ("open", PermissionError(errno.EACCES, "denied")),
            ("fsync", OSError(errno.EIO, "I/O failure")),
            ("fsync", PermissionError(errno.EPERM, "not permitted")),
        ):
            with self.subTest(stage=stage, errno=failure.errno):
                with (
                    mock.patch.object(
                        common_module.os,
                        "open",
                        side_effect=failure if stage == "open" else None,
                        return_value=41,
                    ),
                    mock.patch.object(
                        common_module.os,
                        "fsync",
                        side_effect=failure if stage == "fsync" else None,
                    ) as sync,
                    mock.patch.object(common_module.os, "close") as close,
                ):
                    with self.assertRaises(OSError) as raised:
                        fsync_dir(path)
                self.assertEqual(failure.errno, raised.exception.errno)
                if stage == "open":
                    sync.assert_not_called()
                    close.assert_not_called()
                else:
                    close.assert_called_once_with(41)

    def test_directory_fsync_suppresses_only_unsupported_errors(self) -> None:
        unsupported = {
            errno.EINVAL,
            *(
                value
                for value in (
                    getattr(errno, "ENOTSUP", None),
                    getattr(errno, "EOPNOTSUPP", None),
                )
                if value is not None
            ),
        }
        for error_number in unsupported:
            with self.subTest(errno=error_number):
                with (
                    mock.patch.object(common_module.os, "open", return_value=42),
                    mock.patch.object(
                        common_module.os,
                        "fsync",
                        side_effect=OSError(error_number, "unsupported"),
                    ),
                    mock.patch.object(common_module.os, "close") as close,
                ):
                    fsync_dir(Path("/fixture/directory"))
                close.assert_called_once_with(42)

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
            mock.patch.object(
                common_module.shutil, "which", return_value="/usr/bin/lsof"
            ),
            mock.patch.object(common_module.subprocess, "run", return_value=completed),
        ):
            with self.assertRaisesRegex(RuntimeError, "status 1"):
                open_file_paths(strict=True)

    def test_path_filtered_lsof_is_bounded_and_accepts_empty_no_match(self) -> None:
        candidates = [Path(f"/tmp/candidate-{index}") for index in range(3)]
        completed = [
            subprocess.CompletedProcess(["lsof"], 1, stdout="", stderr=""),
            subprocess.CompletedProcess(
                ["lsof"], 0, stdout=f"n{candidates[2]}\0\n", stderr=""
            ),
        ]
        with (
            mock.patch.object(
                common_module, "_lsof_binary", return_value="/usr/bin/lsof"
            ),
            mock.patch.object(
                common_module.subprocess, "run", side_effect=completed
            ) as run,
        ):
            opened = open_file_paths_for(candidates, batch_size=2)

        self.assertEqual({candidates[2]}, opened)
        self.assertEqual(2, run.call_count)
        self.assertEqual(
            candidates[:2], [Path(value) for value in run.call_args_list[0].args[0][3:]]
        )
        self.assertEqual("-Fn0", run.call_args_list[0].args[0][2])

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
            self.assertEqual(
                (home / "recovery-claude").resolve(), recovered.claude_config
            )


class ObserverGcTests(ObserverFixture):
    def test_live_session_hold_lifecycle_protects_planning(self) -> None:
        source = self.write_session(ORPHAN_ID)

        hold = pin_live_session(
            self.paths, self.runtime, ORPHAN_ID.upper(), "Keep for local review"
        )

        self.assertEqual("live-session", hold["kind"])
        self.assertEqual(ORPHAN_ID, hold["session_id"])
        self.assertEqual("Keep for local review", hold["reason"])
        self.assertEqual([hold], list_holds(self.paths))
        state = self.paths.state / "holds.json"
        self.assertEqual(0o600, state.stat().st_mode & 0o777)
        _, held_plan = self.plan()
        self.assertEqual([], held_plan["candidates"])
        self.assertEqual(1, held_plan["protected"]["held"])
        self.assertTrue(source.exists())

        self.assertEqual(hold, remove_hold(self.paths, hold["hold_id"]))
        self.assertEqual([], list_holds(self.paths))
        _, unheld_plan = self.plan()
        self.assertEqual(
            [ORPHAN_ID], [item["session_id"] for item in unheld_plan["candidates"]]
        )

    def test_hold_created_after_plan_protects_apply(self) -> None:
        source = self.write_session(ORPHAN_ID)
        plan_path, _ = self.plan()
        hold = pin_live_session(self.paths, self.runtime, ORPHAN_ID, "Do not archive")

        with mock.patch.object(
            observer_module, "open_file_paths_for", return_value=set()
        ):
            result = apply_observer_gc_plan(self.paths, self.runtime, plan_path)

        self.assertEqual(0, result["archived"])
        self.assertEqual("held", result["skipped"][0]["reason"])
        self.assertTrue(source.exists())
        self.assertEqual(hold, list_holds(self.paths)[0])

    def test_pre_move_callback_rechecks_live_hold(self) -> None:
        source = self.write_session(ORPHAN_ID)
        plan_path, _ = self.plan()
        hold = pin_live_session(self.paths, self.runtime, ORPHAN_ID, "Late hold")
        remove_hold(self.paths, hold["hold_id"])

        with (
            mock.patch.object(
                observer_module, "open_file_paths_for", return_value=set()
            ),
            mock.patch.object(
                observer_module, "_load_holds_locked", side_effect=([], [hold])
            ) as load_holds,
        ):
            result = apply_observer_gc_plan(self.paths, self.runtime, plan_path)

        self.assertEqual(2, load_holds.call_count)
        self.assertEqual(0, result["archived"])
        self.assertEqual("held", result["skipped"][0]["reason"])
        self.assertTrue(source.exists())
        self.assertEqual([], list_holds(self.paths))

    def test_live_hold_rejects_missing_session_and_invalid_reason(self) -> None:
        for session_id, reason in (
            ("not-a-uuid", "reason"),
            (ORPHAN_ID, ""),
            (ORPHAN_ID, " padded "),
        ):
            with self.subTest(session_id=session_id, reason=reason):
                with self.assertRaises(ValueError):
                    pin_live_session(self.paths, self.runtime, session_id, reason)
        with self.assertRaises((FileNotFoundError, ValueError)):
            pin_live_session(self.paths, self.runtime, ORPHAN_ID, "missing")
        self.assertEqual([], list_holds(self.paths))

    def test_hold_state_schema_fails_closed(self) -> None:
        self.write_session(ORPHAN_ID)
        hold = pin_live_session(self.paths, self.runtime, ORPHAN_ID, "Keep")
        state_path = self.paths.state / "holds.json"
        original = common_module.load_json(state_path)
        changes = (
            lambda state: state.update(extra=True),
            lambda state: state["holds"][0].update(provider="claude"),
            lambda state: state["holds"][0].update(reason=""),
            lambda state: state["holds"][0].update(hold_id="0" * 32),
        )
        for change in changes:
            with self.subTest(change=change):
                state = json.loads(json.dumps(original))
                change(state)
                atomic_json(state_path, state)
                with self.assertRaises(ValueError):
                    list_holds(self.paths)
        atomic_json(state_path, original)
        self.assertEqual([hold], list_holds(self.paths))

    def test_dangling_observer_root_is_rejected_without_plan(self) -> None:
        self.runtime.observer_project.rmdir()
        self.runtime.observer_project.symlink_to(self.home / "missing-observer")

        with self.assertRaisesRegex(ValueError, "symlink|safe"):
            create_observer_gc_plan(self.paths, self.runtime, grace_seconds=0)

        self.assertEqual([], list((self.paths.state / "plans").glob("*.json")))

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

        self.assertEqual(
            [orphan.stem], [item["session_id"] for item in plan["candidates"]]
        )
        self.assertEqual(
            {"database": 1, "corpora": 1, "union": 2}, plan["reference_counts"]
        )
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
        with mock.patch.object(
            observer_module, "open_file_paths_for", return_value={opened}
        ):
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
        with mock.patch.object(
            observer_module, "open_file_paths_for", return_value=set()
        ):
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
        history = history_summary(self.paths)
        self.assertEqual(1, history["events"])
        self.assertEqual(result["logical_raw_bytes"], history["logical_archived_bytes"])
        self.assertEqual(result["unique_cas_bytes"], history["unique_cas_bytes"])
        self.assertEqual(1, len(history["top_growth_sources"]))

    def test_observer_history_failure_does_not_hide_completed_archive(self) -> None:
        source = self.write_session(ORPHAN_ID)
        plan_path, _ = self.plan()

        with (
            mock.patch.object(
                observer_module, "open_file_paths_for", return_value=set()
            ),
            mock.patch.object(
                history_module,
                "append_history_event",
                side_effect=OSError("history unavailable"),
            ),
        ):
            result = apply_observer_gc_plan(self.paths, self.runtime, plan_path)

        self.assertFalse(source.exists())
        self.assertEqual(1, result["archived"])
        self.assertFalse(result["history_recorded"])

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

        with mock.patch.object(
            observer_module, "open_file_paths_for", return_value={member}
        ):
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
        (self.runtime.corpora / "bad.corpus.json").write_text(
            "not json", encoding="utf-8"
        )
        with mock.patch.object(
            observer_module, "open_file_paths_for", return_value=set()
        ):
            with self.assertRaisesRegex(RuntimeError, "malformed claude-mem corpus"):
                create_observer_gc_plan(self.paths, self.runtime)

        self.runtime.database.unlink()
        with mock.patch.object(
            observer_module, "open_file_paths_for", return_value=set()
        ):
            with self.assertRaisesRegex(RuntimeError, "database is missing"):
                create_observer_gc_plan(self.paths, self.runtime)

    def test_apply_rechecks_references_and_isolates_identity_races(self) -> None:
        newly_referenced = self.write_session(NEW_REFERENCE_ID)
        changed = self.write_session(CHANGED_ID)
        archived = self.write_session(ARCHIVED_ID)
        plan_path, _ = self.plan()
        self.add_database_reference(newly_referenced.stem)
        changed.write_text(changed.read_text() + "{}\n", encoding="utf-8")

        with mock.patch.object(
            observer_module, "open_file_paths_for", return_value=set()
        ):
            result = apply_observer_gc_plan(self.paths, self.runtime, plan_path)

        self.assertEqual(1, result["archived"])
        self.assertFalse(archived.exists())
        self.assertTrue(newly_referenced.exists())
        self.assertTrue(changed.exists())
        reasons = {item["session_id"]: item["reason"] for item in result["skipped"]}
        self.assertEqual("newly referenced", reasons[newly_referenced.stem])
        self.assertEqual("identity drift", reasons[changed.stem])

    def test_pre_move_callback_catches_new_reference(self) -> None:
        self.paths.ensure_private()
        archive_module._ensure_archive_canary(self.paths, archive_module._zstd_binary())
        cas_before = archive_module._cas_inventory(self.paths)
        source = self.write_session(ORPHAN_ID)
        plan_path, _ = self.plan()
        empty_counts = {"database": 0, "corpora": 0, "union": 0}

        with (
            mock.patch.object(
                observer_module, "open_file_paths_for", return_value=set()
            ),
            mock.patch.object(
                observer_module,
                "read_keep_set",
                return_value=(set(), empty_counts),
            ),
            mock.patch.object(
                observer_module, "session_is_referenced", return_value=True
            ),
        ):
            result = apply_observer_gc_plan(self.paths, self.runtime, plan_path)

        self.assertEqual(0, result["archived"])
        self.assertEqual("newly referenced", result["skipped"][0]["reason"])
        self.assertTrue(source.exists())
        cas_after = archive_module._cas_inventory(self.paths)
        created = cas_after.keys() - cas_before.keys()
        self.assertEqual(1, result["new_objects"])
        self.assertEqual(
            sum(cas_after[relative][0] for relative in created),
            result["unique_new_cas_bytes"],
        )
        self.assertEqual(
            sum(value[1] for value in cas_after.values())
            - sum(value[1] for value in cas_before.values()),
            result["cas_allocated_bytes_change"],
        )

    def test_mixed_case_reference_protects_at_final_check(self) -> None:
        mixed_id = "abcdef01-2345-6789-abcd-ef0123456789"
        source = self.write_session(mixed_id)
        plan_path, _ = self.plan()
        mixed_case = "".join(
            character.upper() if index % 2 else character
            for index, character in enumerate(mixed_id)
        )
        self.add_database_reference(mixed_case)

        with mock.patch.object(
            observer_module, "open_file_paths_for", return_value=set()
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
            mock.patch.object(
                observer_module, "open_file_paths_for", return_value=set()
            ),
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
            events.append(
                "open-cached" if "open-cached" not in events else "open-final"
            )
            return set()

        def referenced(_runtime, _session_id: str) -> bool:
            events.append("reference-final")
            return False

        def replace(source_path, destination_path) -> None:
            if Path(source_path) == source:
                events.append("move-source")
            real_replace(source_path, destination_path)

        with (
            mock.patch.object(
                observer_module, "open_file_paths_for", side_effect=enumerate_open
            ) as opened,
            mock.patch.object(
                observer_module, "read_keep_set", return_value=(set(), counts)
            ) as keep,
            mock.patch.object(
                observer_module, "session_is_referenced", side_effect=referenced
            ),
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

        with mock.patch.object(
            observer_module, "open_file_paths_for", return_value=set()
        ):
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

        with mock.patch.object(
            observer_module, "open_file_paths_for", return_value=set()
        ):
            with self.assertRaisesRegex(RuntimeError, "ancestor is unsafe"):
                apply_observer_gc_plan(self.paths, self.runtime, plan_path)
        self.assertTrue(
            (real_projects / self.runtime.observer_project.name / source.name).exists()
        )


class ObserverExpiryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.paths = AppPaths.discover(self.home)
        self.paths.ensure_private()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_object(self, name: str, size: int = 10) -> str:
        digest = hashlib.sha256(name.encode()).hexdigest()
        relative = f"objects/sha256/{digest[:2]}/{digest}.zst"
        path = ensure_safe_cas_shard(self.paths.archive, digest[:2]) / f"{digest}.zst"
        path.write_bytes(name.encode()[:1] * size)
        return relative

    def make_manifest(
        self,
        provider: str,
        name: str,
        archived_at: datetime,
        objects: list[str],
        dictionary: str | None = None,
    ) -> Path:
        path = self.paths.archive / "manifests" / provider / f"{name}.json"
        files = []
        for index, value in enumerate(objects):
            object_path = self.paths.archive / value
            relative = f"member-{index}.jsonl"
            files.append(
                {
                    "path": f"/fixture/{relative}",
                    "relative": relative,
                    "device": 0,
                    "inode": index,
                    "size": object_path.stat().st_size,
                    "mtime_ns": 0,
                    "mode": 0o600,
                    "raw_sha256": Path(value).name.split(".", 1)[0],
                    "compressed_sha256": hashlib.sha256(
                        object_path.read_bytes()
                    ).hexdigest(),
                    "object": value,
                    **({"dictionary": dictionary} if dictionary is not None else {}),
                }
            )
        atomic_json(
            path,
            {
                "schema_version": 2 if dictionary is not None else 1,
                "kind": "session-archive",
                "archive_id": name,
                "provider": provider,
                "session_id": name,
                "source_root": "/fixture",
                "last_activity": archived_at.isoformat(),
                "archived_at": archived_at.isoformat(),
                "zstd_version": "fixture",
                "files": files,
                "directories": [],
            },
        )
        return path

    def make_versioned_manifest(
        self,
        provider: str,
        name: str,
        archived_at: datetime,
        objects: list[str],
        *,
        version: int = 1,
    ) -> Path:
        path = self.make_manifest(provider, name, archived_at, objects)
        manifest = common_module.load_json(path)
        key = archive_module._manifest_key(manifest)
        token = hashlib.sha256(name.encode()).hexdigest()[:32]
        manifest["archive_id"] = f"{key}-v{version:016d}-{token}"
        versioned = path.with_name(f"{manifest['archive_id']}.json")
        atomic_json(versioned, manifest)
        path.unlink()
        return versioned

    def test_archive_version_hold_lifecycle_preserves_manifest_and_cas(self) -> None:
        now = datetime.now(UTC)
        held_object = self.make_object("held-version")
        expired_object = self.make_object("unheld-version")
        held_manifest = self.make_versioned_manifest(
            "claude", "held-version", now - timedelta(days=20), [held_object]
        )
        expired_manifest = self.make_versioned_manifest(
            "claude", "unheld-version", now - timedelta(days=20), [expired_object]
        )

        with self.assertRaisesRegex(ValueError, "manifest path"):
            pin_archive_version(  # type: ignore[arg-type]
                self.paths, str(held_manifest), "Invalid path type"
            )
        hold = pin_archive_version(self.paths, held_manifest, "Keep this checkpoint")
        self.assertEqual("archive-version", hold["kind"])
        self.assertEqual("claude", hold["provider"])
        self.assertEqual("Keep this checkpoint", hold["reason"])
        self.assertEqual(
            str(held_manifest.relative_to(self.paths.archive)), hold["manifest"]
        )
        self.assertEqual([hold], list_holds(self.paths))
        state_path = self.paths.state / "holds.json"
        valid_state = common_module.load_json(state_path)
        invalid_state = json.loads(json.dumps(valid_state))
        invalid_state["holds"][0]["version"] += 1
        atomic_json(state_path, invalid_state)
        with self.assertRaisesRegex(ValueError, "identity"):
            list_holds(self.paths)
        atomic_json(state_path, valid_state)

        plan_path, plan = create_archive_expiry_plan(
            self.paths, "claude", ttl_days=7, cap_bytes=0, now=now
        )
        self.assertEqual(
            [str(expired_manifest)], [item["path"] for item in plan["manifests"]]
        )
        self.assertNotIn(
            held_object, [item["relative"] for item in plan["cas_candidates"]]
        )
        result = apply_archive_expiry_plan(self.paths, plan_path)
        self.assertEqual(1, result["manifests_removed"])
        self.assertTrue(held_manifest.exists())
        self.assertTrue((self.paths.archive / held_object).exists())
        self.assertFalse(expired_manifest.exists())

        remove_hold(self.paths, hold["hold_id"])
        final_path, final_plan = create_archive_expiry_plan(
            self.paths, "claude", ttl_days=7, cap_bytes=0, now=now
        )
        self.assertEqual(
            [str(held_manifest)], [item["path"] for item in final_plan["manifests"]]
        )
        apply_archive_expiry_plan(self.paths, final_path)
        self.assertFalse(held_manifest.exists())
        self.assertFalse((self.paths.archive / held_object).exists())

    def test_observer_archive_version_hold_is_provider_bound(self) -> None:
        now = datetime.now(UTC)
        relative = self.make_object("held-observer-version")
        manifest = self.make_versioned_manifest(
            OBSERVER_PROVIDER,
            "held-observer-version",
            now - timedelta(days=20),
            [relative],
        )
        pin_archive_version(self.paths, manifest, "Keep observer checkpoint")

        _, plan = create_observer_expiry_plan(
            self.paths, ttl_days=0, cap_bytes=0, now=now
        )

        self.assertEqual([], plan["manifests"])
        self.assertEqual([], plan["cas_candidates"])
        self.assertTrue(manifest.exists())
        self.assertTrue((self.paths.archive / relative).exists())

    def test_hold_created_after_expiry_plan_blocks_stale_apply(self) -> None:
        now = datetime.now(UTC)
        relative = self.make_object("late-held-version")
        manifest = self.make_versioned_manifest(
            "claude", "late-held-version", now - timedelta(days=20), [relative]
        )
        plan_path, plan = create_archive_expiry_plan(
            self.paths, "claude", ttl_days=7, cap_bytes=0, now=now
        )
        self.assertEqual([str(manifest)], [item["path"] for item in plan["manifests"]])
        pin_archive_version(self.paths, manifest, "Hold after review")

        with self.assertRaisesRegex(RuntimeError, "eligibility changed"):
            apply_archive_expiry_plan(self.paths, plan_path)

        self.assertTrue(manifest.exists())
        self.assertTrue((self.paths.archive / relative).exists())

    def test_archive_hold_target_binding_fails_closed(self) -> None:
        now = datetime.now(UTC)
        relative = self.make_object("forged-held-version")
        manifest_path = self.make_versioned_manifest(
            "claude", "forged-held-version", now - timedelta(days=20), [relative]
        )
        pin_archive_version(self.paths, manifest_path, "Keep exact version")
        manifest = common_module.load_json(manifest_path)
        manifest["session_id"] = "forged-session"
        atomic_json(manifest_path, manifest)

        with self.assertRaisesRegex(ValueError, "target identity"):
            create_archive_expiry_plan(
                self.paths, "claude", ttl_days=7, cap_bytes=0, now=now
            )

        self.assertTrue(manifest_path.exists())
        self.assertTrue((self.paths.archive / relative).exists())

    def make_dictionary(self, digest: str) -> str:
        relative = f"objects/sha256/{digest[:2]}/{digest}.dict"
        path = ensure_safe_cas_shard(self.paths.archive, digest[:2]) / f"{digest}.dict"
        path.write_bytes(b"dictionary-bytes")
        return relative

    def make_chunk_manifest(
        self,
        provider: str,
        name: str,
        archived_at: datetime,
        digests: list[str],
    ) -> Path:
        for digest in digests:
            chunk = (
                ensure_safe_cas_shard(self.paths.archive, digest[:2]) / f"{digest}.zst"
            )
            chunk.write_bytes(b"chunk")
        path = self.paths.archive / "manifests" / provider / f"{name}.json"
        atomic_json(
            path,
            {
                "schema_version": 2,
                "kind": "session-archive",
                "archive_id": name,
                "provider": provider,
                "session_id": name,
                "source_root": "/fixture",
                "last_activity": archived_at.isoformat(),
                "archived_at": archived_at.isoformat(),
                "zstd_version": "fixture",
                "files": [
                    {
                        "path": "/fixture/chunked.jsonl",
                        "relative": "chunked.jsonl",
                        "device": 0,
                        "inode": 0,
                        "chunks": [{"sha256": digest, "size": 5} for digest in digests],
                        "raw_sha256": "0" * 64,
                        "size": 5 * len(digests),
                        "mtime_ns": 0,
                        "mode": 0o600,
                    }
                ],
                "directories": [],
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
        ordinary = self.make_manifest(
            "claude", "ordinary-old", now - timedelta(days=20), [shared]
        )

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

    def test_ordinary_expiry_is_dry_run_and_preserves_reachable_cas(self) -> None:
        now = datetime.now(UTC)
        unique = self.make_object("ordinary-unique")
        shared = self.make_object("ordinary-shared")
        claude = self.make_manifest(
            "claude", "claude-old", now - timedelta(days=20), [unique, shared]
        )
        codex = self.make_manifest(
            "codex", "codex-old", now - timedelta(days=20), [shared]
        )
        dictionary_digest = hashlib.sha256(b"dictionary-bytes").hexdigest()
        dictionary = self.make_dictionary(dictionary_digest)
        atomic_json(
            self.paths.archive / "dictionaries/claude.json",
            {
                "schema_version": 2,
                "kind": "compression-dictionary",
                "provider": "claude",
                "object": dictionary,
                "raw_sha256": dictionary_digest,
            },
        )

        plan_path, plan = create_archive_expiry_plan(
            self.paths, "claude", ttl_days=7, cap_bytes=1024, now=now
        )

        self.assertTrue(claude.exists())
        self.assertTrue((self.paths.archive / unique).exists())
        self.assertEqual([str(claude)], [item["path"] for item in plan["manifests"]])
        self.assertEqual(
            [unique], [item["relative"] for item in plan["cas_candidates"]]
        )
        self.assertNotIn(
            dictionary, [item["relative"] for item in plan["cas_candidates"]]
        )

        result = apply_archive_expiry_plan(self.paths, plan_path)

        self.assertEqual(1, result["manifests_removed"])
        self.assertFalse(claude.exists())
        self.assertFalse((self.paths.archive / unique).exists())
        self.assertTrue(codex.exists())
        self.assertTrue((self.paths.archive / shared).exists())
        self.assertTrue((self.paths.archive / dictionary).exists())
        history = history_summary(self.paths)
        self.assertEqual(result["logical_reclaimed_bytes"], history["logical_reclaimed_bytes_delta"])
        self.assertEqual(result["physical_allocated_bytes_change"], history["physical_allocated_bytes_delta"])
        self.assertEqual(result["filesystem_free_bytes_change"], history["observed_free_bytes_delta"])
        self.assertEqual(0, history["unique_cas_bytes"])

        _, codex_plan = create_archive_expiry_plan(
            self.paths, "codex", ttl_days=7, cap_bytes=1024, now=now
        )
        self.assertEqual(
            [str(codex)], [item["path"] for item in codex_plan["manifests"]]
        )
        self.assertEqual(
            [shared], [item["relative"] for item in codex_plan["cas_candidates"]]
        )

    def test_expiry_keeps_or_removes_latest_index_with_versions(self) -> None:
        now = datetime.now(UTC)
        old_object = self.make_object("indexed-old")
        new_object = self.make_object("indexed-new")
        old_path = self.make_manifest(
            "claude", "indexed-old", now - timedelta(days=20), [old_object]
        )
        new_path = self.make_manifest("claude", "indexed-new", now, [new_object])
        manifests = []
        for number, path in enumerate((old_path, new_path), start=1):
            payload = common_module.load_json(path)
            payload["session_id"] = "indexed-session"
            key = archive_module._manifest_key(payload)
            payload["archive_id"] = f"{key}-v{number:016d}-{number:032x}"
            version_path = path.with_name(f"{payload['archive_id']}.json")
            atomic_json(version_path, payload)
            path.unlink()
            manifests.append((version_path, payload))
        key = archive_module._manifest_key(manifests[0][1])
        archive_module._publish_latest_index(
            self.paths, manifests[1][0], manifests[1][1]
        )

        first_plan, _ = create_archive_expiry_plan(
            self.paths, "claude", ttl_days=7, cap_bytes=1024, now=now
        )
        apply_archive_expiry_plan(self.paths, first_plan)
        self.assertFalse(manifests[0][0].exists())
        self.assertEqual(
            manifests[1][0],
            archive_module.resolve_latest_manifest(self.paths, "claude", key),
        )

        final_plan, _ = create_archive_expiry_plan(
            self.paths, "claude", ttl_days=0, cap_bytes=1024, now=now
        )
        apply_archive_expiry_plan(self.paths, final_plan)
        self.assertFalse(manifests[1][0].exists())
        with self.assertRaises(ValueError):
            archive_module.resolve_latest_manifest(self.paths, "claude", key)

    def test_ordinary_expiry_rejects_forged_recent_manifest(self) -> None:
        now = datetime.now(UTC)
        old_object = self.make_object("expiry-old")
        recent_object = self.make_object("expiry-recent")
        old = self.make_manifest(
            "claude", "expiry-old", now - timedelta(days=20), [old_object]
        )
        recent = self.make_manifest("claude", "expiry-recent", now, [recent_object])
        plan_path, plan = create_archive_expiry_plan(
            self.paths, "claude", ttl_days=7, cap_bytes=1024, now=now
        )
        record = observer_module._manifest_record(self.paths, recent)
        plan["manifests"].append(
            {
                key: value
                for key, value in record.items()
                if key not in {"archived_at_value", "provider"}
            }
            | {"reasons": ["ttl"]}
        )
        atomic_json(plan_path, plan)

        with self.assertRaisesRegex(ValueError, "identity"):
            apply_archive_expiry_plan(self.paths, plan_path)

        self.assertTrue(old.exists())
        self.assertTrue(recent.exists())
        self.assertTrue((self.paths.archive / old_object).exists())
        self.assertTrue((self.paths.archive / recent_object).exists())

    def test_ordinary_expiry_rejects_boolean_and_negative_policy(self) -> None:
        for ttl_days, cap_bytes in ((True, 1), (1, True), (-1, 1), (1, -1)):
            with self.subTest(ttl_days=ttl_days, cap_bytes=cap_bytes):
                with self.assertRaisesRegex(ValueError, "non-negative"):
                    create_archive_expiry_plan(
                        self.paths,
                        "claude",
                        ttl_days=ttl_days,
                        cap_bytes=cap_bytes,
                    )
                with self.assertRaisesRegex(ValueError, "non-negative"):
                    create_observer_expiry_plan(
                        self.paths,
                        ttl_days=ttl_days,
                        cap_bytes=cap_bytes,
                    )

        now = datetime.now(UTC)
        relative = self.make_object("invalid-policy")
        manifest = self.make_manifest(
            "claude", "invalid-policy", now - timedelta(days=20), [relative]
        )
        plan_path, plan = create_archive_expiry_plan(
            self.paths, "claude", ttl_days=7, cap_bytes=1024, now=now
        )
        for field, value in (
            ("schema_version", True),
            ("ttl_days", True),
            ("cap_bytes", -1),
        ):
            with self.subTest(field=field, value=value):
                invalid = json.loads(json.dumps(plan))
                invalid[field] = value
                atomic_json(plan_path, invalid)
                with self.assertRaises(ValueError):
                    apply_archive_expiry_plan(self.paths, plan_path)
                self.assertTrue(manifest.exists())
                self.assertTrue((self.paths.archive / relative).exists())

        for change in (
            lambda value: value.pop("created_at"),
            lambda value: value["manifests"][0].pop("reasons"),
            lambda value: value["manifests"][0].update(reasons="ttl"),
            lambda value: value.update(created_at="2999-01-01T00:00:00Z"),
        ):
            invalid = json.loads(json.dumps(plan))
            change(invalid)
            atomic_json(plan_path, invalid)
            with self.assertRaises(ValueError):
                apply_archive_expiry_plan(self.paths, plan_path)
            self.assertTrue(manifest.exists())
            self.assertTrue((self.paths.archive / relative).exists())

    def test_ordinary_expiry_plan_path_binds_reviewed_policy(self) -> None:
        now = datetime.now(UTC)
        relative = self.make_object("bound-policy")
        manifest = self.make_manifest(
            "claude", "bound-policy", now - timedelta(days=1), [relative]
        )
        plan_path, benign = create_archive_expiry_plan(
            self.paths, "claude", ttl_days=365, cap_bytes=1024**3, now=now
        )
        _, aggressive = create_archive_expiry_plan(
            self.paths, "claude", ttl_days=0, cap_bytes=1024**3, now=now
        )
        aggressive["run_id"] = benign["run_id"]
        aggressive["created_at"] = benign["created_at"]
        aggressive["expires_at"] = benign["expires_at"]
        atomic_json(plan_path, aggressive)

        with self.assertRaisesRegex(ValueError, "identity"):
            apply_archive_expiry_plan(self.paths, plan_path)

        self.assertTrue(manifest.exists())
        self.assertTrue((self.paths.archive / relative).exists())

    def test_expiry_propagates_post_unlink_directory_sync_failure(self) -> None:
        now = datetime.now(UTC)
        relative = self.make_object("expiry-sync-failure")
        manifest = self.make_manifest(
            "claude", "expiry-sync-failure", now - timedelta(days=20), [relative]
        )
        plan_path, _ = create_archive_expiry_plan(
            self.paths, "claude", ttl_days=7, cap_bytes=1024, now=now
        )
        failure = OSError(errno.EIO, "directory sync failed")

        with mock.patch.object(
            observer_module, "fsync_dir", side_effect=(None, failure)
        ):
            with self.assertRaises(OSError) as raised:
                apply_archive_expiry_plan(self.paths, plan_path)

        self.assertEqual(errno.EIO, raised.exception.errno)
        self.assertFalse(manifest.exists())
        self.assertTrue((self.paths.archive / relative).exists())

    def test_manifest_change_during_expiry_planning_causes_zero_mutation(self) -> None:
        now = datetime.now(UTC)
        relative = self.make_object("expiry-manifest-race")
        manifest_path = self.make_manifest(
            OBSERVER_PROVIDER,
            "expiry-manifest-race",
            now - timedelta(days=10),
            [relative],
        )
        for index in range(33):
            atomic_json(
                self.paths.state / "plans" / f"race-expired-{index}.json",
                {"expires_at": "2000-01-01T00:00:00Z"},
            )
        plans_before = set((self.paths.state / "plans").glob("*.json"))
        real_records = observer_module._all_manifest_records
        calls = 0

        def change_after_first_scan(paths):
            nonlocal calls
            calls += 1
            records = real_records(paths)
            if calls == 1:
                payload = common_module.load_json(manifest_path)
                payload["files"][0].pop("size")
                atomic_json(manifest_path, payload)
            return records

        with (
            mock.patch.object(
                observer_module,
                "_all_manifest_records",
                side_effect=change_after_first_scan,
            ),
            self.assertRaisesRegex(
                RuntimeError, "cannot evaluate archive reachability"
            ),
        ):
            create_observer_expiry_plan(self.paths, now=now)

        self.assertEqual(2, calls)
        self.assertEqual(plans_before, set((self.paths.state / "plans").glob("*.json")))
        self.assertTrue((self.paths.archive / relative).is_file())

    def test_cap_expires_oldest_and_collects_only_unreachable_objects(self) -> None:
        now = datetime.now(UTC)
        objects = [
            self.make_object(f"{index:02d}-object", size=10) for index in range(3)
        ]
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

    def test_expiry_collects_unreachable_recipe_variant(self) -> None:
        payload = b"variant"
        raw_hash = "a" * 64
        compressed_hash = hashlib.sha256(payload).hexdigest()
        relative = f"objects/sha256/{raw_hash[:2]}/{raw_hash}.{compressed_hash}.zst"
        variant = self.paths.archive / relative
        ensure_safe_cas_shard(self.paths.archive, raw_hash[:2])
        variant.write_bytes(payload)

        plan_path, plan = create_observer_expiry_plan(
            self.paths,
            ttl_days=7,
            cap_bytes=1024,
        )
        self.assertEqual(
            [str(variant)], [item["path"] for item in plan["cas_candidates"]]
        )

        result = apply_observer_expiry_plan(self.paths, plan_path)
        self.assertEqual(1, result["objects_removed"])
        self.assertFalse(variant.exists())

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
        ensure_safe_cas_shard(self.paths.archive, digest[:2])
        orphan.write_bytes(b"orphan")

        plan_path, plan = create_observer_expiry_plan(
            self.paths,
            ttl_days=7,
            cap_bytes=1024,
        )
        self.assertEqual(
            [str(orphan)], [item["path"] for item in plan["cas_candidates"]]
        )

        result = apply_observer_expiry_plan(self.paths, plan_path)
        self.assertEqual(1, result["objects_removed"])
        self.assertFalse(orphan.exists())

    def test_orphan_sweep_collects_crash_remnant_temps(self) -> None:
        digest = "d" * 64
        relative = f"objects/sha256/{digest[:2]}/.{digest}.abc12345.part"
        remnant = self.paths.archive / relative
        ensure_safe_cas_shard(self.paths.archive, digest[:2])
        remnant.write_bytes(b"partial")

        plan_path, plan = create_observer_expiry_plan(
            self.paths,
            ttl_days=7,
            cap_bytes=1024,
        )
        self.assertEqual(
            [str(remnant)], [item["path"] for item in plan["cas_candidates"]]
        )

        result = apply_observer_expiry_plan(self.paths, plan_path)
        self.assertEqual(1, result["objects_removed"])
        self.assertFalse(remnant.exists())

    def test_manifest_dictionary_rejects_zstd_object(self) -> None:
        now = datetime.now(UTC)
        member = self.make_object("member")
        wrong_dictionary = self.make_object("wrong-dictionary")
        self.make_manifest(
            OBSERVER_PROVIDER,
            "wrong-dictionary-kind",
            now - timedelta(days=10),
            [member],
            dictionary=wrong_dictionary,
        )

        with self.assertRaisesRegex(RuntimeError, "invalid CAS name for dictionary"):
            create_observer_expiry_plan(self.paths, ttl_days=7, cap_bytes=1024, now=now)

    def test_symlink_shard_escape_fails_closed(self) -> None:
        now = datetime.now(UTC)
        root = self.paths.archive / "objects" / "sha256"
        root.mkdir(parents=True, exist_ok=True)
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

        with self.assertRaisesRegex(ValueError, "symlinked ancestor"):
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
        (self.paths.archive / "objects/sha256").rmdir()
        (self.paths.archive / "objects").rmdir()
        (self.paths.archive / "objects").symlink_to(outside, target_is_directory=True)
        relative = f"objects/sha256/aa/{'a' * 64}.zst"
        self.make_manifest(
            OBSERVER_PROVIDER,
            "observer-objects-escape",
            now - timedelta(days=10),
            [relative],
        )

        with self.assertRaisesRegex(ValueError, "symlinked ancestor"):
            create_observer_expiry_plan(
                self.paths,
                ttl_days=7,
                cap_bytes=1024,
                now=now,
            )

        self.assertEqual(b"outside", object_path.read_bytes())

    def test_expiry_preserves_dictionary_referenced_elsewhere(self) -> None:
        now = datetime.now(UTC)
        dictionary = self.make_dictionary("e" * 64)
        observer_object = self.make_object("ff-expired")
        observer = self.make_manifest(
            OBSERVER_PROVIDER,
            "observer-dict",
            now - timedelta(days=10),
            [observer_object],
            dictionary=dictionary,
        )
        ordinary_object = self.make_object("a0-ordinary")
        ordinary = self.make_manifest(
            "claude",
            "ordinary-dict",
            now - timedelta(days=20),
            [ordinary_object],
            dictionary=dictionary,
        )

        plan_path, _ = create_observer_expiry_plan(
            self.paths, ttl_days=7, cap_bytes=1024**4, now=now
        )
        result = apply_observer_expiry_plan(self.paths, plan_path)

        self.assertEqual(1, result["manifests_removed"])
        self.assertFalse(observer.exists())
        self.assertTrue(ordinary.exists())
        self.assertTrue((self.paths.archive / dictionary).exists())
        self.assertFalse((self.paths.archive / observer_object).exists())

    def test_expiry_collects_unreferenced_dictionary(self) -> None:
        now = datetime.now(UTC)
        dictionary = self.make_dictionary("e" * 64)
        observer_object = self.make_object("f1-only")
        self.make_manifest(
            OBSERVER_PROVIDER,
            "observer-dict-only",
            now - timedelta(days=10),
            [observer_object],
            dictionary=dictionary,
        )

        plan_path, _ = create_observer_expiry_plan(
            self.paths, ttl_days=7, cap_bytes=1024**4, now=now
        )
        result = apply_observer_expiry_plan(self.paths, plan_path)

        self.assertEqual(1, result["manifests_removed"])
        self.assertEqual(2, result["objects_removed"])
        self.assertFalse((self.paths.archive / dictionary).exists())

    def test_expiry_preserves_dictionary_referenced_by_active_pointer(self) -> None:
        content = b"active-dictionary"
        digest = hashlib.sha256(content).hexdigest()
        dictionary = f"objects/sha256/{digest[:2]}/{digest}.dict"
        dictionary_path = (
            ensure_safe_cas_shard(self.paths.archive, digest[:2]) / f"{digest}.dict"
        )
        dictionary_path.write_bytes(content)
        plan_path, plan = create_observer_expiry_plan(
            self.paths, ttl_days=7, cap_bytes=1024
        )
        self.assertIn(dictionary, {item["relative"] for item in plan["cas_candidates"]})

        atomic_json(
            self.paths.archive / "dictionaries" / f"{OBSERVER_PROVIDER}.json",
            {
                "schema_version": 1,
                "kind": "compression-dictionary",
                "provider": OBSERVER_PROVIDER,
                "object": dictionary,
                "raw_sha256": digest,
            },
        )
        result = apply_observer_expiry_plan(self.paths, plan_path)

        self.assertEqual(0, result["objects_removed"])
        self.assertIn("still reachable", {item["reason"] for item in result["skipped"]})
        self.assertTrue(dictionary_path.exists())

    def test_invalid_dictionary_pointer_schema_does_not_protect_object(self) -> None:
        content = b"invalid-schema-dictionary"
        digest = hashlib.sha256(content).hexdigest()
        relative = f"objects/sha256/{digest[:2]}/{digest}.dict"
        pointer = self.paths.archive / "dictionaries" / f"{OBSERVER_PROVIDER}.json"
        for schema in (None, True, 999):
            with self.subTest(schema=schema):
                target = (
                    ensure_safe_cas_shard(self.paths.archive, digest[:2])
                    / f"{digest}.dict"
                )
                target.write_bytes(content)
                payload = {
                    "kind": "compression-dictionary",
                    "provider": OBSERVER_PROVIDER,
                    "object": relative,
                    "raw_sha256": digest,
                }
                if schema is not None:
                    payload["schema_version"] = schema
                atomic_json(pointer, payload)

                plan_path, plan = create_observer_expiry_plan(
                    self.paths, ttl_days=7, cap_bytes=1024
                )
                self.assertIn(
                    relative,
                    {item["relative"] for item in plan["cas_candidates"]},
                )
                apply_observer_expiry_plan(self.paths, plan_path)
                self.assertFalse(target.exists())

    def test_expiry_chunk_reachability(self) -> None:
        now = datetime.now(UTC)
        digest_one = "01" + "0" * 62
        digest_two = "02" + "0" * 62
        observer = self.make_chunk_manifest(
            OBSERVER_PROVIDER,
            "observer-chunked",
            now - timedelta(days=10),
            [digest_one, digest_two],
        )
        ordinary = self.make_chunk_manifest(
            "claude",
            "ordinary-chunked",
            now - timedelta(days=20),
            [digest_two],
        )

        plan_path, _ = create_observer_expiry_plan(
            self.paths, ttl_days=7, cap_bytes=1024**4, now=now
        )
        result = apply_observer_expiry_plan(self.paths, plan_path)

        self.assertEqual(1, result["manifests_removed"])
        self.assertEqual(1, result["objects_removed"])
        self.assertFalse(observer.exists())
        self.assertTrue(ordinary.exists())
        self.assertFalse(
            (self.paths.archive / f"objects/sha256/01/{digest_one}.zst").exists()
        )
        self.assertTrue(
            (self.paths.archive / f"objects/sha256/02/{digest_two}.zst").exists()
        )

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
