from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import sesh_compresh.cli as cli_module
from sesh_compresh.common import AppPaths, atomic_json


class CliTests(unittest.TestCase):
    def test_archive_repack_commands_dispatch_and_require_confirmation(self) -> None:
        parser = cli_module.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["archive", "repack", "apply", "/plan.json"])

        with tempfile.TemporaryDirectory() as home:
            plan_path = Path(home) / "repack-plan.json"
            plan_report = {
                "plan": str(plan_path),
                "candidates": 2,
                "manifests": 2,
                "raw_bytes": 30,
                "compressed_bytes": 20,
            }
            with (
                mock.patch.object(
                    cli_module,
                    "create_repack_plan",
                    create=True,
                    return_value=(plan_path, plan_report),
                ) as create,
                mock.patch.object(
                    cli_module,
                    "apply_repack_plan",
                    create=True,
                    return_value={"repacked": 2},
                ) as apply,
                mock.patch.object(
                    cli_module,
                    "recover_repack",
                    create=True,
                    return_value={"completed": 1, "rolled_back": 0},
                ) as recover,
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    0,
                    cli_module.main(
                        [
                            "--home",
                            home,
                            "archive",
                            "repack",
                            "plan",
                            "--minimum-compressed-mib",
                            "3",
                        ]
                    ),
                )
                self.assertEqual(
                    0,
                    cli_module.main(
                        [
                            "--home",
                            home,
                            "archive",
                            "repack",
                            "apply",
                            str(plan_path),
                            "--yes",
                        ]
                    ),
                )
                self.assertEqual(
                    0,
                    cli_module.main(
                        ["--home", home, "archive", "repack", "recover"]
                    ),
                )

        create.assert_called_once_with(
            mock.ANY, minimum_compressed_bytes=3 * 1024**2
        )
        apply.assert_called_once_with(mock.ANY, plan_path)
        recover.assert_called_once_with(mock.ANY)

    def test_history_command_emits_read_only_summary(self) -> None:
        report = {
            "events": 2,
            "unique_bytes_saved": 42,
            "provider_utc_trends": [],
            "top_growth_sources": [],
        }
        stdout = io.StringIO()
        with (
            mock.patch.object(
                cli_module, "history_summary", return_value=report
            ) as summary,
            redirect_stdout(stdout),
        ):
            status = cli_module.main(
                ["--home", "/fixture", "--json", "history", "--top", "5"]
            )

        self.assertEqual(0, status)
        self.assertEqual(report, json.loads(stdout.getvalue()))
        summary.assert_called_once_with(mock.ANY, top=5)

    def test_archive_encryption_commands_dispatch_and_require_confirmation(
        self,
    ) -> None:
        parser = cli_module.build_parser()
        for command in (
            ["archive", "encryption", "enable", "--recovery-file", "/key.age"],
            ["archive", "encryption", "restore-key", "--recovery-file", "/key.age"],
        ):
            with self.subTest(command=command), self.assertRaises(SystemExit):
                parser.parse_args(command)

        with tempfile.TemporaryDirectory() as home:
            recovery = Path(home) / "recovery.age"
            with (
                mock.patch.object(
                    cli_module,
                    "enable_archive_encryption",
                    return_value={"enabled": True},
                ) as enable,
                mock.patch.object(
                    cli_module,
                    "encryption_status",
                    return_value={"enabled": True, "key_available": True},
                ) as status,
                mock.patch.object(
                    cli_module,
                    "restore_archive_key",
                    return_value={"restored": True},
                ) as restore,
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    0,
                    cli_module.main(
                        [
                            "--home",
                            home,
                            "archive",
                            "encryption",
                            "enable",
                            "--recovery-file",
                            str(recovery),
                            "--yes",
                        ]
                    ),
                )
                self.assertEqual(
                    0,
                    cli_module.main(
                        ["--home", home, "archive", "encryption", "status"]
                    ),
                )
                self.assertEqual(
                    0,
                    cli_module.main(
                        [
                            "--home",
                            home,
                            "archive",
                            "encryption",
                            "restore-key",
                            "--recovery-file",
                            str(recovery),
                            "--yes",
                        ]
                    ),
                )
        enable.assert_called_once_with(mock.ANY, recovery)
        status.assert_called_once_with(mock.ANY)
        restore.assert_called_once_with(mock.ANY, recovery)

    def test_portable_commands_dispatch_and_require_confirmation(self) -> None:
        parser = cli_module.build_parser()
        for command in (
            ["portable", "import", "apply", "/plan.json"],
            ["portable", "import", "recover"],
        ):
            with self.subTest(command=command), self.assertRaises(SystemExit):
                parser.parse_args(command)

        with tempfile.TemporaryDirectory() as home:
            destination = Path(home) / "export.zip"
            artifact = Path(home) / "artifact.zip"
            plan_path = Path(home) / "portable-plan.json"
            plan = {
                "bundle_id": "a" * 64,
                "manifests": 2,
                "objects": 3,
                "artifact": {"sha256": "b" * 64},
            }
            with (
                mock.patch.object(
                    cli_module,
                    "export_portable_archive",
                    return_value={"bundle_id": "a" * 64},
                ) as export,
                mock.patch.object(
                    cli_module,
                    "create_portable_import_plan",
                    return_value=(plan_path, plan),
                ) as create,
                mock.patch.object(
                    cli_module,
                    "apply_portable_import_plan",
                    return_value={"published": 5},
                ) as apply,
                mock.patch.object(
                    cli_module,
                    "recover_portable_imports",
                    return_value={"completed": 1},
                ) as recover,
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    0,
                    cli_module.main(
                        [
                            "--home",
                            home,
                            "portable",
                            "export",
                            str(destination),
                            "one",
                            "two",
                        ]
                    ),
                )
                self.assertEqual(
                    0,
                    cli_module.main(
                        [
                            "--home",
                            home,
                            "portable",
                            "import",
                            "plan",
                            str(artifact),
                        ]
                    ),
                )
                self.assertEqual(
                    0,
                    cli_module.main(
                        [
                            "--home",
                            home,
                            "portable",
                            "import",
                            "apply",
                            str(plan_path),
                            "--yes",
                        ]
                    ),
                )
                self.assertEqual(
                    0,
                    cli_module.main(
                        [
                            "--home",
                            home,
                            "portable",
                            "import",
                            "recover",
                            "--yes",
                        ]
                    ),
                )

        export.assert_called_once_with(mock.ANY, ["one", "two"], destination)
        create.assert_called_once_with(mock.ANY, artifact)
        apply.assert_called_once_with(mock.ANY, plan_path)
        recover.assert_called_once_with(mock.ANY)

    def test_pressure_plan_dispatches_strict_thresholds_and_policy(self) -> None:
        payload = {
            "triggered": True,
            "archive_plan": "/archive-plan.json",
            "clean_plan": "/clean-plan.json",
        }
        with tempfile.TemporaryDirectory() as home:
            policy = Path(home) / "policy.json"
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module, "plan_disk_pressure", return_value=payload
                ) as plan,
                redirect_stdout(output),
            ):
                result = cli_module.main(
                    [
                        "--home",
                        home,
                        "--json",
                        "pressure",
                        "plan",
                        "--trigger-free-gib",
                        "2",
                        "--target-free-gib",
                        "3.5",
                        "--policy",
                        str(policy),
                    ]
                )

        self.assertEqual(0, result)
        self.assertEqual(payload, json.loads(output.getvalue()))
        plan.assert_called_once_with(
            mock.ANY,
            trigger_free_bytes=2 * 1024**3,
            target_free_bytes=7 * 1024**3 // 2,
            policy_path=policy,
        )

    def test_pressure_has_no_apply_and_rejects_inexact_gib_values(self) -> None:
        parser = cli_module.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["pressure", "apply"])

        with tempfile.TemporaryDirectory() as home:
            for value in ("nan", "sNaN", "inf", "-1", "0.1"):
                with self.subTest(value=value):
                    error = io.StringIO()
                    with (
                        mock.patch.object(cli_module, "plan_disk_pressure") as plan,
                        redirect_stderr(error),
                    ):
                        result = cli_module.main(
                            [
                                "--home",
                                home,
                                "pressure",
                                "plan",
                                "--trigger-free-gib",
                                value,
                                "--target-free-gib",
                                "1",
                            ]
                        )
                    self.assertEqual(1, result)
                    self.assertIn("disk pressure trigger", error.getvalue())
                    plan.assert_not_called()

    def test_pressure_partial_failure_emits_child_path_and_returns_one(self) -> None:
        payload = {
            "triggered": True,
            "partial": True,
            "failed_stage": "archive",
            "error_type": "RuntimeError",
            "error": "archive planning failed",
            "clean_plan": "/clean-plan.json",
        }
        with tempfile.TemporaryDirectory() as home:
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "plan_disk_pressure",
                    side_effect=cli_module.PressurePlanError(payload),
                ),
                redirect_stdout(output),
            ):
                result = cli_module.main(
                    [
                        "--home",
                        home,
                        "--json",
                        "pressure",
                        "plan",
                        "--trigger-free-gib",
                        "1",
                        "--target-free-gib",
                        "2",
                    ]
                )

        self.assertEqual(1, result)
        self.assertEqual(payload, json.loads(output.getvalue()))

    def test_archive_verify_continue_reports_once_and_sets_failure_status(self) -> None:
        cases = (
            (
                {
                    "selected": 2,
                    "verified": 1,
                    "failed_manifests": 1,
                    "files": 3,
                    "failures": [
                        {
                            "manifest": "/archive/bad.json",
                            "error_type": "RuntimeError",
                            "error": "chunk mismatch",
                        }
                    ],
                },
                1,
            ),
            (
                {
                    "selected": 2,
                    "verified": 2,
                    "failed_manifests": 0,
                    "files": 4,
                    "failures": [],
                },
                0,
            ),
        )
        with tempfile.TemporaryDirectory() as home:
            for payload, expected_status in cases:
                with self.subTest(failed=payload["failed_manifests"]):
                    output = io.StringIO()
                    with (
                        mock.patch.object(
                            cli_module, "verify_all", return_value=payload
                        ) as verify,
                        redirect_stdout(output),
                    ):
                        result = cli_module.main(
                            [
                                "--home",
                                home,
                                "--json",
                                "archive",
                                "verify",
                                "--continue",
                            ]
                        )
                    self.assertEqual(expected_status, result)
                    self.assertEqual(payload, json.loads(output.getvalue()))
                    verify.assert_called_once_with(mock.ANY, continue_on_error=True)

    def test_archive_verify_default_keeps_legacy_dispatch_and_result(self) -> None:
        payload = {"manifests": 2, "files": 3}
        with tempfile.TemporaryDirectory() as home:
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module, "verify_all", return_value=payload
                ) as verify,
                redirect_stdout(output),
            ):
                result = cli_module.main(
                    ["--home", home, "--json", "archive", "verify"]
                )

        self.assertEqual(0, result)
        self.assertEqual(payload, json.loads(output.getvalue()))
        verify.assert_called_once_with(mock.ANY)

    def test_schedule_commands_dispatch_and_report_contract(self) -> None:
        payload = {
            "backend": "systemd",
            "installed": True,
            "active": True,
            "enabled": True,
            "command": [
                "/bin/sesh-compresh",
                "--json",
                "scheduled-maintain",
                "--notify",
            ],
            "command_available": True,
            "interval_seconds": 90,
            "notify": True,
            "event_mode": True,
            "definitions": ["/service", "/timer"],
        }
        with tempfile.TemporaryDirectory() as home:
            output = io.StringIO()
            executable = Path(home) / "sesh-compresh"
            with (
                mock.patch.object(
                    cli_module, "schedule_install", return_value=payload
                ) as install,
                mock.patch.object(
                    cli_module, "schedule_status", return_value=payload
                ) as status,
                mock.patch.object(
                    cli_module,
                    "schedule_uninstall",
                    return_value=payload | {"installed": False},
                ) as uninstall,
                redirect_stdout(output),
            ):
                self.assertEqual(
                    0,
                    cli_module.main(
                        [
                            "--home",
                            home,
                            "--json",
                            "schedule",
                            "install",
                            "--interval-seconds",
                            "90",
                            "--executable",
                            str(executable),
                            "--notify",
                        ]
                    ),
                )
                self.assertEqual(
                    0, cli_module.main(["--home", home, "schedule", "status"])
                )
                self.assertEqual(
                    0, cli_module.main(["--home", home, "schedule", "uninstall"])
                )

        install.assert_called_once_with(
            mock.ANY, interval_seconds=90, executable=executable, notify=True
        )
        status.assert_called_once_with(mock.ANY)
        uninstall.assert_called_once_with(mock.ANY)
        self.assertIn('"interval_seconds": 90', output.getvalue())
        self.assertIn('command: ["/bin/sesh-compresh"', output.getvalue())

    def test_scheduled_maintenance_emits_typed_sanitized_event(self) -> None:
        counts = {
            "archived": 2,
            "protected": 3,
            "manifests_removed": 4,
            "objects_removed": 5,
        }
        event = {
            "schema_version": 1,
            "kind": "scheduled-maintenance-event",
            "event_id": "opaque",
            "occurred_at": "2026-08-13T00:00:00Z",
            "status": "success",
            "reason_codes": ["success", "protected", "low_space"],
            "counts": counts,
            "notification": "pending",
        }
        result = {
            "event": event,
            "notification_result": {
                "schema_version": 1,
                "kind": "scheduled-maintenance-notification",
                "event_id": "opaque",
                "notification": "sent",
            },
        }
        with tempfile.TemporaryDirectory() as home:
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "_maintenance_cycle",
                    return_value=({"private": "/secret/session"}, counts),
                ) as cycle,
                mock.patch.object(
                    cli_module,
                    "verify_all",
                    return_value={"failed_manifests": 0},
                ),
                mock.patch.object(
                    cli_module.shutil,
                    "disk_usage",
                    return_value=mock.Mock(free=1),
                ),
                mock.patch.object(
                    cli_module, "record_maintenance_event", return_value=result
                ) as record,
                redirect_stdout(output),
            ):
                status = cli_module.main(
                    [
                        "--home",
                        home,
                        "--json",
                        "scheduled-maintain",
                        "--notify",
                    ]
                )

        self.assertEqual(0, status)
        self.assertEqual(result, json.loads(output.getvalue()))
        cycle.assert_called_once_with(
            mock.ANY,
            mock.ANY,
            grace_seconds=cli_module.DEFAULT_GRACE_SECONDS,
            ttl_days=cli_module.DEFAULT_ARCHIVE_TTL_DAYS,
            cap_bytes=cli_module.DEFAULT_ARCHIVE_CAP_BYTES,
            apply=True,
        )
        record.assert_called_once_with(
            mock.ANY,
            counts=counts,
            reason_codes=["success", "protected", "low_space"],
            notify=True,
        )
        self.assertNotIn("/secret/session", output.getvalue())

    def test_scheduled_maintenance_failure_records_once_without_error_text(self) -> None:
        failure_event = {
            "schema_version": 1,
            "kind": "scheduled-maintenance-event",
            "event_id": "opaque",
            "occurred_at": "2026-08-13T00:00:00Z",
            "status": "failure",
            "reason_codes": ["failure"],
            "counts": {
                "archived": 0,
                "protected": 0,
                "manifests_removed": 0,
                "objects_removed": 0,
            },
            "notification": "pending",
        }
        failure = {
            "event": failure_event,
            "notification_result": {
                "schema_version": 1,
                "kind": "scheduled-maintenance-notification",
                "event_id": "opaque",
                "notification": "failed",
            },
        }
        with tempfile.TemporaryDirectory() as home:
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "_maintenance_cycle",
                    side_effect=OSError("failed at /secret/session-id"),
                ) as cycle,
                mock.patch.object(
                    cli_module, "record_maintenance_event", return_value=failure
                ) as record,
                redirect_stdout(output),
            ):
                status = cli_module.main(
                    ["--home", home, "--json", "scheduled-maintain", "--notify"]
                )

        self.assertEqual(1, status)
        self.assertEqual(failure, json.loads(output.getvalue()))
        self.assertEqual(1, cycle.call_count)
        record.assert_called_once_with(
            mock.ANY,
            counts=failure_event["counts"],
            reason_codes=["failure"],
            notify=True,
        )
        self.assertNotIn("secret", output.getvalue())

    def test_scheduled_maintenance_corruption_is_a_failure_signal(self) -> None:
        counts = {
            "archived": 0,
            "protected": 0,
            "manifests_removed": 0,
            "objects_removed": 0,
        }
        result = {
            "event": {
                "status": "failure",
                "reason_codes": ["corruption"],
                "counts": counts,
            },
            "notification_result": None,
        }
        with tempfile.TemporaryDirectory() as home:
            with (
                mock.patch.object(
                    cli_module,
                    "_maintenance_cycle",
                    return_value=({}, counts),
                ),
                mock.patch.object(
                    cli_module,
                    "verify_all",
                    return_value={"failed_manifests": 2},
                ),
                mock.patch.object(
                    cli_module.shutil,
                    "disk_usage",
                    return_value=mock.Mock(free=cli_module.DEFAULT_LOW_SPACE_BYTES),
                ),
                mock.patch.object(
                    cli_module, "record_maintenance_event", return_value=result
                ) as record,
                redirect_stdout(io.StringIO()),
            ):
                status = cli_module.main(
                    ["--home", home, "--json", "scheduled-maintain"]
                )

        self.assertEqual(1, status)
        record.assert_called_once_with(
            mock.ANY,
            counts=counts,
            reason_codes=["corruption"],
            notify=False,
        )

    def test_doctor_reports_all_green_checks_and_optional_scheduler(self) -> None:
        lock_entries = 0

        @contextmanager
        def tracking_lock(paths):
            nonlocal lock_entries
            lock_entries += 1
            yield

        with tempfile.TemporaryDirectory() as home:
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "_required_tool",
                    side_effect=lambda name: f"/bin/{name}",
                ),
                mock.patch.object(cli_module, "_check_anchors", return_value="safe"),
                mock.patch.object(cli_module, "app_lock", tracking_lock),
                mock.patch.object(
                    cli_module,
                    "verify_all",
                    return_value={"manifests": 2, "files": 3},
                ),
                mock.patch.object(
                    cli_module, "_check_archive_quarantine", return_value="safe"
                ),
                mock.patch.object(
                    cli_module, "_check_clean_quarantine", return_value="safe"
                ),
                mock.patch.object(cli_module, "_scheduler_artifacts", return_value=()),
                redirect_stdout(output),
            ):
                result = cli_module.main(["--home", home, "--json", "doctor"])

        payload = json.loads(output.getvalue())
        self.assertEqual(0, result)
        self.assertTrue(payload["ok"])
        self.assertEqual([], payload["required_failures"])
        self.assertEqual(
            [
                "tool:zstd",
                "tool:lsof",
                "directories",
                "lock",
                "manifests",
                "archive-quarantine",
                "clean-quarantine",
                "scheduler",
            ],
            [check["name"] for check in payload["checks"]],
        )
        self.assertFalse(payload["checks"][-1]["required"])
        self.assertEqual(2, lock_entries)

    def test_doctor_aggregates_required_failures_and_returns_one(self) -> None:
        def tool(name: str) -> str:
            if name == "zstd":
                raise RuntimeError("missing zstd")
            return "/bin/lsof"

        with tempfile.TemporaryDirectory() as home:
            scheduler = Path(home) / "scheduler"
            scheduler.touch()
            output = io.StringIO()
            with (
                mock.patch.object(cli_module, "_required_tool", side_effect=tool),
                mock.patch.object(
                    cli_module, "_check_anchors", side_effect=ValueError("unsafe mode")
                ),
                mock.patch.object(
                    cli_module, "_check_lock", side_effect=RuntimeError("busy")
                ),
                mock.patch.object(
                    cli_module,
                    "_check_manifests",
                    side_effect=ValueError("bad manifest"),
                ),
                mock.patch.object(
                    cli_module,
                    "_check_archive_quarantine",
                    side_effect=ValueError("bad archive journal"),
                ),
                mock.patch.object(
                    cli_module,
                    "_check_clean_quarantine",
                    side_effect=ValueError("bad clean journal"),
                ),
                mock.patch.object(
                    cli_module, "_scheduler_artifacts", return_value=(scheduler,)
                ),
                mock.patch.object(
                    cli_module,
                    "_check_scheduler",
                    side_effect=RuntimeError("inactive"),
                ),
                redirect_stdout(output),
            ):
                result = cli_module.main(["--home", home, "--json", "doctor"])

        payload = json.loads(output.getvalue())
        self.assertEqual(1, result)
        self.assertFalse(payload["ok"])
        self.assertEqual(
            {
                "tool:zstd",
                "directories",
                "lock",
                "manifests",
                "archive-quarantine",
                "clean-quarantine",
                "scheduler",
            },
            set(payload["required_failures"]),
        )
        self.assertTrue(all("detail" in check for check in payload["checks"]))

    @unittest.skipIf(os.name == "nt", "POSIX permission contract")
    def test_doctor_anchor_check_rejects_public_mode_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            paths = AppPaths.discover(Path(home))
            paths.ensure_private()
            paths.archive.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "permissions are not private"):
                cli_module._check_anchors(paths)
            paths.archive.chmod(0o700)
            outside = Path(home) / "outside"
            outside.mkdir()
            (paths.archive / "manifests/unsafe").symlink_to(
                outside, target_is_directory=True
            )
            with self.assertRaisesRegex(ValueError, "not canonical"):
                cli_module._check_anchors(paths)

    def test_doctor_clean_quarantine_uses_strict_journal_validator(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            paths = AppPaths.discover(Path(home))
            paths.ensure_private()
            (paths.state / "clean-quarantine/bad.json").write_text(
                '{"kind":"clean-quarantine"}\n', encoding="utf-8"
            )

            with self.assertRaisesRegex(ValueError, "journal is invalid"):
                cli_module._check_clean_quarantine(paths)

    def test_doctor_reuses_strict_schedule_status(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            paths = AppPaths.discover(Path(home))
            valid = {
                "installed": True,
                "enabled": True,
                "active": True,
                "command_available": True,
            }
            with mock.patch.object(
                cli_module, "schedule_status", return_value=valid
            ) as status:
                self.assertEqual(
                    "installed scheduler is enabled and active",
                    cli_module._check_scheduler(paths),
                )
            status.assert_called_once_with(paths)
            with (
                mock.patch.object(
                    cli_module,
                    "schedule_status",
                    side_effect=ValueError("systemd service command is invalid"),
                ),
                self.assertRaisesRegex(ValueError, "service command is invalid"),
            ):
                cli_module._check_scheduler(paths)
            with (
                mock.patch.object(
                    cli_module,
                    "schedule_status",
                    return_value=valid | {"command_available": False},
                ),
                self.assertRaisesRegex(RuntimeError, "executable is unavailable"),
            ):
                cli_module._check_scheduler(paths)

    def test_plan_show_reports_candidates_and_skips_in_json_and_text(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            plan_path = Path(home) / "clean.json"
            atomic_json(
                plan_path,
                {
                    "kind": "clean-plan",
                    "candidates": [
                        {
                            "path": "/cache/build",
                            "family": "swiftpm",
                            "marker": "workspace-state.json+build.db",
                            "action": "delete-tree",
                            "allocated_bytes": 4096,
                        }
                    ],
                    "skipped_open": ["/cache/open"],
                },
            )
            json_output = io.StringIO()
            text_output = io.StringIO()
            with redirect_stdout(json_output):
                json_result = cli_module.main(
                    ["--home", home, "--json", "plan", "show", str(plan_path)]
                )
            with redirect_stdout(text_output):
                text_result = cli_module.main(
                    ["--home", home, "plan", "show", str(plan_path)]
                )

        shown = json.loads(json_output.getvalue())
        self.assertEqual(0, json_result)
        self.assertEqual(0, text_result)
        self.assertEqual("clean-plan", shown["kind"])
        self.assertEqual(
            {
                "path": "/cache/build",
                "reason": "swiftpm",
                "marker": "workspace-state.json+build.db",
                "action": "delete-tree",
                "bytes": 4096,
            },
            shown["candidates"][0],
        )
        self.assertEqual(
            {"path": "/cache/open", "reason": "open", "count": 1},
            shown["skipped"][0],
        )
        for value in (
            "Apply would perform 1 action over 4096 bytes",
            "/cache/build",
            "workspace-state.json+build.db",
            "delete-tree",
            "/cache/open",
        ):
            self.assertIn(value, text_output.getvalue())

    def test_plan_show_rejects_malformed_entries_cleanly(self) -> None:
        malformed = (
            {"kind": "archive-plan"},
            {"kind": "archive-plan", "sessions": [{}], "skipped": {}},
            {"kind": "clean-plan"},
            {"kind": "clean-plan", "candidates": [{}], "skipped_open": []},
            {"kind": "observer-gc-plan"},
            {"kind": "observer-gc-plan", "candidates": [{}], "protected": {}},
            {"kind": "archive-expiry-plan"},
            {
                "kind": "archive-expiry-plan",
                "provider": "claude",
                "manifests": [{}],
                "cas_candidates": [],
            },
            {"kind": "observer-expiry-plan"},
            {
                "kind": "observer-expiry-plan",
                "provider": "claude-observer",
                "manifests": [],
                "cas_candidates": [{}],
            },
            {"kind": "clean-expiry-plan"},
            {
                "kind": "clean-expiry-plan",
                "retention_days": 7,
                "journals": [{}],
            },
        )
        with tempfile.TemporaryDirectory() as home:
            for index, payload in enumerate(malformed):
                with self.subTest(kind=payload["kind"], index=index):
                    plan_path = Path(home) / f"malformed-{index}.json"
                    atomic_json(plan_path, payload)
                    stderr = io.StringIO()
                    with redirect_stderr(stderr):
                        result = cli_module.main(
                            ["--home", home, "plan", "show", str(plan_path)]
                        )
                    self.assertEqual(1, result)
                    self.assertIn("plan entries are invalid", stderr.getvalue())

    def test_plan_show_supports_every_current_plan_kind(self) -> None:
        plans = (
            {
                "kind": "archive-plan",
                "sessions": [
                    {
                        "files": [{"path": "/session", "size": 1}],
                        "source_root": "/",
                        "retention_days": 30,
                        "provider": "claude",
                        "session_id": "s",
                    }
                ],
                "skipped": {"recent": 1},
            },
            {
                "kind": "observer-gc-plan",
                "candidates": [
                    {
                        "files": [{"path": "/observer", "size": 2}],
                        "source_root": "/",
                        "session_id": "o",
                    }
                ],
                "protected": {"open": 1},
            },
            {
                "kind": "archive-expiry-plan",
                "provider": "codex",
                "manifests": [{"path": "/manifest", "reasons": ["ttl"], "size": 3}],
                "cas_candidates": [
                    {"path": "/object", "relative": "object", "size": 4}
                ],
            },
            {
                "kind": "observer-expiry-plan",
                "provider": "claude-observer",
                "manifests": [],
                "cas_candidates": [
                    {"path": "/object", "relative": "object", "size": 4}
                ],
            },
            {
                "kind": "clean-expiry-plan",
                "retention_days": 7,
                "journals": [{"path": "/journal", "size": 5}],
            },
        )
        with tempfile.TemporaryDirectory() as home:
            for index, payload in enumerate(plans):
                with self.subTest(kind=payload["kind"]):
                    path = Path(home) / f"plan-{index}.json"
                    atomic_json(path, payload)
                    shown = cli_module._plan_show(path)
                    self.assertEqual(payload["kind"], shown["kind"])
                    self.assertTrue(shown["candidates"])
                    self.assertTrue(shown["summary"])

    def test_clean_undo_and_expiry_commands_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            journal = Path(home) / "journal.json"
            expiry = Path(home) / "expiry.json"
            with (
                mock.patch.object(
                    cli_module, "undo_clean", return_value={"restored": 1}
                ) as undo,
                mock.patch.object(
                    cli_module,
                    "create_clean_expiry_plan",
                    return_value=(
                        expiry,
                        {"journals": [{"path": str(journal)}], "retention_days": 9},
                    ),
                ) as create,
                mock.patch.object(
                    cli_module,
                    "apply_clean_expiry_plan",
                    return_value={"journals_removed": 1},
                ) as apply,
            ):
                self.assertEqual(
                    0,
                    cli_module.main(["--home", home, "clean", "undo", str(journal)]),
                )
                self.assertEqual(
                    0,
                    cli_module.main(
                        [
                            "--home",
                            home,
                            "clean",
                            "expire",
                            "plan",
                            "--retention-days",
                            "9",
                        ]
                    ),
                )
                self.assertEqual(
                    0,
                    cli_module.main(
                        [
                            "--home",
                            home,
                            "clean",
                            "expire",
                            "apply",
                            str(expiry),
                            "--yes",
                        ]
                    ),
                )

        undo.assert_called_once_with(mock.ANY, journal)
        create.assert_called_once_with(mock.ANY, retention_days=9)
        apply.assert_called_once_with(mock.ANY, expiry)

    def test_clean_plan_dispatches_exact_policy_path(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            policy = Path(home) / "cleanup-policy.json"
            plan_path = Path(home) / "clean-plan.json"
            with (
                mock.patch.object(
                    cli_module,
                    "create_clean_plan",
                    return_value=(
                        plan_path,
                        {"candidates": [], "allocated_bytes": 0, "skipped_open": []},
                    ),
                ) as create,
                redirect_stdout(io.StringIO()),
            ):
                result = cli_module.main(
                    [
                        "--home",
                        home,
                        "clean",
                        "plan",
                        "--policy",
                        str(policy),
                    ]
                )

        self.assertEqual(0, result)
        create.assert_called_once_with(mock.ANY, "practical", policy_path=policy)

    def test_archive_expiry_plan_is_dry_run_output(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            plan_path = Path(home) / "expiry.json"
            plan = {
                "provider": "codex",
                "manifests": [{"path": "/manifest"}],
                "cas_candidates": [{"path": "/object"}],
                "archive_bytes_before": 100,
                "archive_bytes_after": 40,
            }
            stdout = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "create_archive_expiry_plan",
                    return_value=(plan_path, plan),
                ) as create,
                redirect_stdout(stdout),
            ):
                result = cli_module.main(
                    [
                        "--home",
                        home,
                        "--json",
                        "archive",
                        "expire",
                        "plan",
                        "--provider",
                        "codex",
                        "--ttl-days",
                        "9",
                        "--cap-gib",
                        "2",
                    ]
                )

        self.assertEqual(0, result)
        create.assert_called_once_with(
            mock.ANY, "codex", ttl_days=9, cap_bytes=2 * 1024**3
        )
        self.assertEqual(
            {
                "plan": str(plan_path),
                "provider": "codex",
                "manifests": 1,
                "cas_candidates": 1,
                "archive_bytes_before": 100,
                "archive_bytes_after": 40,
            },
            json.loads(stdout.getvalue()),
        )

    def test_archive_schema_check_reports_state_and_exit_status(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            for current, expected_status in ((True, 0), (False, 1)):
                with self.subTest(current=current):
                    stdout = io.StringIO()
                    report = {
                        "compatible": True,
                        "latest_indexes_current": current,
                        "manifests": 2,
                    }
                    with (
                        mock.patch.object(
                            cli_module, "check_archive_schema", return_value=report
                        ) as check,
                        redirect_stdout(stdout),
                    ):
                        result = cli_module.main(
                            ["--home", home, "--json", "archive", "schema", "check"]
                        )
                    self.assertEqual(expected_status, result)
                    check.assert_called_once_with(mock.ANY)
                    self.assertEqual(report, json.loads(stdout.getvalue()))

    def test_archive_schema_rebuild_requires_yes_and_dispatches(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    cli_module.main(
                        ["--home", home, "archive", "schema", "rebuild-index"]
                    )
            self.assertEqual(2, raised.exception.code)

            stdout = io.StringIO()
            report = {
                "compatible": True,
                "latest_indexes_current": True,
                "indexes_written": 1,
                "indexes_removed": 0,
            }
            with (
                mock.patch.object(
                    cli_module, "rebuild_latest_indexes", return_value=report
                ) as rebuild,
                redirect_stdout(stdout),
            ):
                result = cli_module.main(
                    [
                        "--home",
                        home,
                        "--json",
                        "archive",
                        "schema",
                        "rebuild-index",
                        "--yes",
                    ]
                )

        self.assertEqual(0, result)
        rebuild.assert_called_once_with(mock.ANY)
        self.assertEqual(report, json.loads(stdout.getvalue()))

    def test_runtime_error_returns_one_with_concise_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            stderr = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "apply_archive_plan",
                    side_effect=ValueError("invalid archive plan"),
                ),
                redirect_stderr(stderr),
            ):
                result = cli_module.main(
                    [
                        "--home",
                        home,
                        "archive",
                        "apply",
                        str(Path(home) / "plan.json"),
                        "--yes",
                    ]
                )

        self.assertEqual(1, result)
        self.assertEqual("sesh-compresh: invalid archive plan\n", stderr.getvalue())

    def test_archive_list_dispatches_filters_sort_and_structured_output(self) -> None:
        entry = {
            "manifest": "/archive/manifest.json",
            "provider": "claude-observer",
            "session_id": "session-1",
            "session_key": "a" * 20,
            "version": 0,
            "archive_id": "a" * 20,
            "last_activity": "2026-04-09T00:00:00Z",
            "archived_at": "2026-04-10T00:00:00Z",
            "raw_bytes": 120,
            "compressed_bytes": 40,
            "compression_ratio": 3.0,
        }
        with tempfile.TemporaryDirectory() as home:
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module, "list_archives", return_value=[entry]
                ) as listing,
                redirect_stdout(output),
            ):
                result = cli_module.main(
                    [
                        "--home",
                        home,
                        "--json",
                        "archive",
                        "list",
                        "--provider",
                        "claude-observer",
                        "--session-id",
                        "session-1",
                        "--date",
                        "2026-04-10",
                        "--version",
                        "0",
                        "--sort",
                        "version",
                        "--reverse",
                    ]
                )

        self.assertEqual(0, result)
        listing.assert_called_once_with(
            mock.ANY,
            provider="claude-observer",
            session_id="session-1",
            archived_on="2026-04-10",
            version=0,
            sort="version",
            reverse=True,
        )
        self.assertEqual(
            {
                "count": 1,
                "manifests": ["/archive/manifest.json"],
                "archives": [entry],
            },
            json.loads(output.getvalue()),
        )

    def test_archive_list_rejects_invalid_date_and_negative_version(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            for selection, message in (
                (["--date", "2026-4-10"], "YYYY-MM-DD"),
                (["--version", "-1"], "non-negative"),
            ):
                with self.subTest(selection=selection):
                    stderr = io.StringIO()
                    with redirect_stderr(stderr):
                        result = cli_module.main(
                            ["--home", home, "archive", "list", *selection]
                        )
                    self.assertEqual(1, result)
                    self.assertIn(message, stderr.getvalue())

    def test_dictionary_benchmark_and_training_dispatch_thresholds(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "benchmark_dictionary",
                    return_value={"beneficial": True},
                ) as benchmark,
                redirect_stdout(output),
            ):
                result = cli_module.main(
                    [
                        "--home",
                        home,
                        "--json",
                        "archive",
                        "benchmark",
                        "--provider",
                        "claude",
                        "--samples",
                        "40",
                        "--max-dict-kib",
                        "8",
                        "--minimum-benefit-kib",
                        "2",
                    ]
                )

            self.assertEqual(0, result)
            benchmark.assert_called_once_with(
                mock.ANY,
                "claude",
                sample_limit=40,
                max_dict_bytes=8 * 1024,
                minimum_benefit_bytes=2 * 1024,
            )
            self.assertEqual({"beneficial": True}, json.loads(output.getvalue()))

            with mock.patch.object(
                cli_module,
                "train_dictionary",
                return_value={"promoted": False},
            ) as train:
                result = cli_module.main(
                    [
                        "--home",
                        home,
                        "archive",
                        "train-dictionary",
                        "--provider",
                        "codex",
                        "--minimum-benefit-kib",
                        "3",
                    ]
                )

            self.assertEqual(0, result)
            train.assert_called_once_with(
                mock.ANY,
                "codex",
                sample_limit=256,
                max_dict_bytes=112 * 1024,
                minimum_benefit_bytes=3 * 1024,
            )

    def test_restore_dispatches_exact_member_and_provider_date_batch(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            destination = Path(home) / "restored"
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "restore_manifest",
                    return_value={"files": 1, "member": "bundle/note.txt"},
                ) as restore_one,
                mock.patch.object(
                    cli_module,
                    "restore_manifest_set",
                    return_value={"manifests": 2, "files": 2},
                ) as restore_set,
                redirect_stdout(output),
            ):
                exact_result = cli_module.main(
                    [
                        "--home",
                        home,
                        "--json",
                        "archive",
                        "restore",
                        "archive-id",
                        "--member",
                        "bundle/note.txt",
                        "--destination",
                        str(destination),
                    ]
                )
                batch_result = cli_module.main(
                    [
                        "--home",
                        home,
                        "--json",
                        "archive",
                        "restore",
                        "--provider",
                        "claude",
                        "--from-date",
                        "2026-04-10",
                        "--to-date",
                        "2026-04-12",
                        "--destination",
                        str(destination),
                    ]
                )

        self.assertEqual(0, exact_result)
        self.assertEqual(0, batch_result)
        restore_one.assert_called_once_with(
            mock.ANY,
            "archive-id",
            destination,
            member="bundle/note.txt",
        )
        restore_set.assert_called_once_with(
            mock.ANY,
            "claude",
            "2026-04-10",
            "2026-04-12",
            destination,
        )
        self.assertIn('"member": "bundle/note.txt"', output.getvalue())
        self.assertIn('"manifests": 2', output.getvalue())

    def test_restore_rejects_incomplete_or_mixed_batch_selection(self) -> None:
        cases = (
            ["--provider", "claude", "--from-date", "2026-04-10"],
            [
                "archive-id",
                "--provider",
                "claude",
                "--from-date",
                "2026-04-10",
                "--to-date",
                "2026-04-12",
            ],
            ["--member", "member.jsonl"],
        )
        with tempfile.TemporaryDirectory() as home:
            for index, selection in enumerate(cases):
                with self.subTest(index=index):
                    stderr = io.StringIO()
                    with (
                        mock.patch.object(
                            cli_module, "restore_manifest"
                        ) as restore_one,
                        mock.patch.object(
                            cli_module, "restore_manifest_set"
                        ) as restore_set,
                        redirect_stderr(stderr),
                    ):
                        result = cli_module.main(
                            ["--home", home, "archive", "restore", *selection]
                        )
                    self.assertEqual(1, result)
                    self.assertIn("restore requires", stderr.getvalue())
                    restore_one.assert_not_called()
                    restore_set.assert_not_called()

    def test_extract_dispatches_exact_range_and_tail(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            manifest = Path(home) / "manifest.json"
            output = Path(home) / "output.bin"
            stdout = io.StringIO()
            with (
                mock.patch.object(
                    cli_module,
                    "extract_member_range",
                    return_value={"length": 7, "decoded_frames": 2},
                ) as extract_range,
                mock.patch.object(
                    cli_module,
                    "extract_member_tail",
                    return_value={"length": 11, "decoded_frames": 1},
                ) as extract_tail,
                redirect_stdout(stdout),
            ):
                range_result = cli_module.main(
                    [
                        "--home",
                        home,
                        "--json",
                        "archive",
                        "extract",
                        str(manifest),
                        "--member",
                        "session.jsonl",
                        "--output",
                        str(output),
                        "--offset",
                        "5",
                        "--length",
                        "7",
                    ]
                )
                tail_result = cli_module.main(
                    [
                        "--home",
                        home,
                        "archive",
                        "extract",
                        str(manifest),
                        "--member",
                        "session.jsonl",
                        "--output",
                        str(output),
                        "--tail-bytes",
                        "11",
                    ]
                )

        self.assertEqual(0, range_result)
        self.assertEqual(0, tail_result)
        extract_range.assert_called_once_with(
            mock.ANY, manifest, "session.jsonl", 5, 7, output
        )
        extract_tail.assert_called_once_with(
            mock.ANY, manifest, "session.jsonl", 11, output
        )
        self.assertIn('"decoded_frames": 2', stdout.getvalue())
        self.assertIn("length: 11", stdout.getvalue())

    def test_extract_rejects_incomplete_or_mixed_selection(self) -> None:
        selections = (
            (),
            ("--offset", "1"),
            ("--length", "2"),
            ("--offset", "1", "--length", "2", "--tail-bytes", "3"),
        )
        with tempfile.TemporaryDirectory() as home:
            for selection in selections:
                with self.subTest(selection=selection):
                    stderr = io.StringIO()
                    with (
                        mock.patch.object(
                            cli_module, "extract_member_range"
                        ) as extract_range,
                        mock.patch.object(
                            cli_module, "extract_member_tail"
                        ) as extract_tail,
                        redirect_stderr(stderr),
                    ):
                        result = cli_module.main(
                            [
                                "--home",
                                home,
                                "archive",
                                "extract",
                                str(Path(home) / "manifest.json"),
                                "--member",
                                "session.jsonl",
                                "--output",
                                str(Path(home) / "output.bin"),
                                *selection,
                            ]
                        )
                    self.assertEqual(1, result)
                    self.assertIn("--offset with --length", stderr.getvalue())
                    extract_range.assert_not_called()
                    extract_tail.assert_not_called()


if __name__ == "__main__":
    unittest.main()
