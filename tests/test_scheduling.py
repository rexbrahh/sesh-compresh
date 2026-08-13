from __future__ import annotations

import plistlib
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

import sesh_compresh.scheduling as scheduling_module
import sesh_compresh.common as common_module
from sesh_compresh.common import AppPaths
from sesh_compresh.scheduling import (
    LAUNCHD_LABEL,
    record_maintenance_event,
    schedule_install,
    schedule_status,
    schedule_uninstall,
)


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.launchd_active = False
        self.systemd_enabled = False
        self.systemd_active = False

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if command[:2] == ["launchctl", "print"]:
            code = 0 if self.launchd_active else 113
            stderr = "" if self.launchd_active else "Could not find service"
        elif command[:2] == ["launchctl", "bootstrap"]:
            self.launchd_active = True
            code = 0
            stderr = ""
        elif command[:2] == ["launchctl", "bootout"]:
            self.launchd_active = False
            code = 0
            stderr = ""
        elif "is-enabled" in command:
            code = 0 if self.systemd_enabled else 1
            stderr = ""
        elif "is-active" in command:
            code = 0 if self.systemd_active else 3
            stderr = ""
        elif "enable" in command:
            self.systemd_enabled = True
            code = 0
            stderr = ""
        elif "restart" in command:
            self.systemd_active = True
            code = 0
            stderr = ""
        elif "disable" in command:
            self.systemd_enabled = self.systemd_active = False
            code = 0
            stderr = ""
        else:
            code = 0
            stderr = ""
        return subprocess.CompletedProcess(command, code, "", stderr)


class SchedulingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.paths = AppPaths.discover(self.home)
        self.executable = self.home / "bin/sesh-compresh"
        self.executable.parent.mkdir()
        self.executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.executable.chmod(0o700)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_launchd_lifecycle_is_idempotent_and_reports_contract(self) -> None:
        runner = FakeRunner()
        first = schedule_install(
            self.paths,
            executable=self.executable,
            interval_seconds=901,
            platform_name="darwin",
            runner=runner,
        )
        definition = Path(first["definitions"][0])
        first_commands = len(runner.commands)

        self.assertTrue(first["installed"])
        self.assertTrue(first["active"])
        self.assertEqual(901, first["interval_seconds"])
        self.assertEqual(
            [str(self.executable), "--json", "scheduled-maintain"],
            first["command"],
        )
        self.assertTrue(first["command_available"])
        self.assertTrue(first["event_mode"])
        self.assertFalse(first["notify"])
        self.assertEqual(0o600, definition.stat().st_mode & 0o777)
        self.assertEqual(0o700, definition.parent.stat().st_mode & 0o777)

        second = schedule_install(
            self.paths,
            executable=self.executable,
            interval_seconds=901,
            platform_name="darwin",
            runner=runner,
        )
        self.assertEqual(first, second)
        new_commands = runner.commands[first_commands:]
        self.assertTrue(new_commands)
        self.assertTrue(all(command[:2] == ["launchctl", "print"] for command in new_commands))

        removed = schedule_uninstall(
            self.paths, platform_name="darwin", runner=runner
        )
        self.assertFalse(removed["installed"])
        self.assertFalse(removed["active"])
        self.assertFalse(definition.exists())
        repeated = schedule_uninstall(
            self.paths, platform_name="darwin", runner=runner
        )
        self.assertEqual(removed, repeated)

    def test_systemd_lifecycle_repairs_live_state_without_rewriting(self) -> None:
        runner = FakeRunner()
        installed = schedule_install(
            self.paths,
            executable=self.executable,
            interval_seconds=77,
            notify=True,
            platform_name="linux",
            runner=runner,
        )
        definitions = [Path(path) for path in installed["definitions"]]
        before = [path.stat().st_mtime_ns for path in definitions]
        first_commands = len(runner.commands)

        repeated = schedule_install(
            self.paths,
            executable=self.executable,
            interval_seconds=77,
            notify=True,
            platform_name="linux",
            runner=runner,
        )
        self.assertEqual(installed, repeated)
        self.assertTrue(
            all(
                "is-enabled" in command or "is-active" in command
                for command in runner.commands[first_commands:]
            )
        )
        self.assertEqual(before, [path.stat().st_mtime_ns for path in definitions])

        runner.systemd_active = False
        runner.commands.clear()

        repaired = schedule_install(
            self.paths,
            executable=self.executable,
            interval_seconds=77,
            notify=True,
            platform_name="linux",
            runner=runner,
        )

        self.assertTrue(repaired["enabled"])
        self.assertTrue(repaired["active"])
        self.assertEqual(77, repaired["interval_seconds"])
        self.assertTrue(repaired["notify"])
        self.assertEqual("--notify", repaired["command"][-1])
        self.assertEqual(before, [path.stat().st_mtime_ns for path in definitions])
        self.assertIn(
            ["systemctl", "--user", "restart", "sesh-compresh.timer"],
            runner.commands,
        )
        removed = schedule_uninstall(
            self.paths, platform_name="linux", runner=runner
        )
        self.assertFalse(removed["installed"])
        self.assertFalse(removed["enabled"])
        self.assertTrue(all(not path.exists() for path in definitions))
        first_commands = len(runner.commands)
        repeated = schedule_uninstall(
            self.paths, platform_name="linux", runner=runner
        )
        self.assertEqual(removed, repeated)
        self.assertTrue(
            all(
                "is-enabled" in command or "is-active" in command
                for command in runner.commands[first_commands:]
            )
        )

    def test_status_rejects_partial_tampered_and_unsafe_installations(self) -> None:
        runner = FakeRunner()
        root = self.home / ".config/systemd/user"
        root.mkdir(parents=True, mode=0o700)
        service = root / "sesh-compresh.service"
        service.write_text("not ours\n", encoding="utf-8")
        service.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            schedule_status(self.paths, platform_name="linux", runner=runner)
        timer = root / "sesh-compresh.timer"
        timer.write_text("not ours\n", encoding="utf-8")
        timer.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "service definition is invalid"):
            schedule_status(self.paths, platform_name="linux", runner=runner)
        service.write_text(
            "[Unit]\n"
            "Description=Sesh Compresh maintenance\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            f"ExecStart={self.executable} --json maintain --yes\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "timer definition is invalid"):
            schedule_status(self.paths, platform_name="linux", runner=runner)
        service.write_text(
            "# maintain --yes\n[Service]\nExecStart=/bin/false\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "service command is invalid"):
            schedule_status(self.paths, platform_name="linux", runner=runner)

        launchd_root = self.home / "Library/LaunchAgents"
        launchd_root.mkdir(parents=True, mode=0o700)
        definition = launchd_root / f"{LAUNCHD_LABEL}.plist"
        definition.write_bytes(
            plistlib.dumps(
                {
                    "Label": LAUNCHD_LABEL,
                    "ProgramArguments": [
                        str(self.executable),
                        "maintain",
                        "--yes",
                        "--json",
                    ],
                    "RunAtLoad": True,
                    "StartInterval": 3600,
                }
            )
        )
        definition.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "definition is invalid"):
            schedule_status(self.paths, platform_name="darwin", runner=runner)
        definition.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "definition is not private"):
            schedule_status(self.paths, platform_name="darwin", runner=runner)
        definition.chmod(0o600)
        definition.unlink()
        definition.symlink_to(service)
        with self.assertRaisesRegex(ValueError, "regular"):
            schedule_status(self.paths, platform_name="darwin", runner=runner)

    def test_invalid_inputs_and_command_failures_preserve_definition(self) -> None:
        runner = FakeRunner()
        for value in (0, -1, 2**31, True):
            with self.subTest(interval=value):
                with self.assertRaisesRegex(ValueError, "schedule interval"):
                    schedule_install(
                        self.paths,
                        executable=self.executable,
                        interval_seconds=value,
                        platform_name="linux",
                        runner=runner,
                    )
        relative = Path("relative/sesh-compresh")
        with self.assertRaisesRegex(ValueError, "absolute safe path"):
            schedule_install(
                self.paths,
                executable=relative,
                platform_name="linux",
                runner=runner,
            )
        with self.assertRaisesRegex(ValueError, "absolute safe path"):
            schedule_install(
                self.paths,
                executable=self.home / "bin/../bin/sesh-compresh",
                platform_name="linux",
                runner=runner,
            )
        unsafe = self.home / "bin/sesh%compresh"
        unsafe.write_bytes(self.executable.read_bytes())
        unsafe.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "unsafe unit character"):
            schedule_install(
                self.paths,
                executable=unsafe,
                platform_name="linux",
                runner=runner,
            )

        runner = FakeRunner()
        original = runner.__call__

        def fail_bootstrap(command: list[str]) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["launchctl", "bootstrap"]:
                runner.commands.append(command)
                return subprocess.CompletedProcess(command, 9, "", "forced failure")
            return original(command)

        with self.assertRaisesRegex(RuntimeError, "forced failure"):
            schedule_install(
                self.paths,
                executable=self.executable,
                platform_name="darwin",
                runner=fail_bootstrap,
            )
        definition = self.home / f"Library/LaunchAgents/{LAUNCHD_LABEL}.plist"
        self.assertTrue(definition.is_file())
        self.assertEqual(
            3600,
            schedule_status(
                self.paths, platform_name="darwin", runner=runner
            )["interval_seconds"],
        )

    def test_atomic_replacement_failure_preserves_existing_definition(self) -> None:
        runner = FakeRunner()
        installed = schedule_install(
            self.paths,
            executable=self.executable,
            interval_seconds=60,
            platform_name="darwin",
            runner=runner,
        )
        definition = Path(installed["definitions"][0])
        original = definition.read_bytes()
        real_replace = scheduling_module.os.replace

        def fail_definition_replace(source: Path, destination: Path) -> None:
            if Path(destination) == definition:
                raise OSError("replace failed")
            real_replace(source, destination)

        with mock.patch.object(
            scheduling_module.os, "replace", side_effect=fail_definition_replace
        ), self.assertRaisesRegex(OSError, "replace failed"):
            schedule_install(
                self.paths,
                executable=self.executable,
                interval_seconds=61,
                platform_name="darwin",
                runner=runner,
            )

        self.assertEqual(original, definition.read_bytes())

    def test_query_errors_block_status_install_and_uninstall_for_both_backends(
        self,
    ) -> None:
        for platform_name in ("darwin", "linux"):
            with self.subTest(platform=platform_name):
                runner = FakeRunner()
                installed = schedule_install(
                    self.paths,
                    executable=self.executable,
                    interval_seconds=60,
                    platform_name=platform_name,
                    runner=runner,
                )
                definitions = [Path(path) for path in installed["definitions"]]
                original = [path.read_bytes() for path in definitions]
                denied_commands: list[list[str]] = []

                def denied(command: list[str]) -> subprocess.CompletedProcess[str]:
                    denied_commands.append(command)
                    if command[:2] == ["launchctl", "print"] or any(
                        query in command for query in ("is-enabled", "is-active")
                    ):
                        return subprocess.CompletedProcess(
                            command, 5, "", "permission denied"
                        )
                    return runner(command)

                operations = (
                    lambda: schedule_status(
                        self.paths,
                        platform_name=platform_name,
                        runner=denied,
                    ),
                    lambda: schedule_install(
                        self.paths,
                        executable=self.executable,
                        interval_seconds=61,
                        platform_name=platform_name,
                        runner=denied,
                    ),
                    lambda: schedule_uninstall(
                        self.paths,
                        platform_name=platform_name,
                        runner=denied,
                    ),
                )
                for operation in operations:
                    denied_commands.clear()
                    with self.assertRaisesRegex(
                        RuntimeError, "query failed with status 5.*permission denied"
                    ):
                        operation()
                    self.assertEqual(
                        original, [path.read_bytes() for path in definitions]
                    )
                    self.assertFalse(
                        any(
                            command[:2] in (
                                ["launchctl", "bootout"],
                                ["launchctl", "bootstrap"],
                            )
                            or "disable" in command
                            or "enable" in command
                            or "restart" in command
                            for command in denied_commands
                        )
                    )

    def test_deleted_executable_reports_unavailable_and_does_not_block_removal(
        self,
    ) -> None:
        for platform_name in ("darwin", "linux"):
            with self.subTest(platform=platform_name):
                if not self.executable.exists():
                    self.executable.write_text(
                        "#!/bin/sh\nexit 0\n", encoding="utf-8"
                    )
                    self.executable.chmod(0o700)
                runner = FakeRunner()
                installed = schedule_install(
                    self.paths,
                    executable=self.executable,
                    platform_name=platform_name,
                    runner=runner,
                )
                definitions = [Path(path) for path in installed["definitions"]]
                original = [path.read_bytes() for path in definitions]
                self.executable.unlink()

                status = schedule_status(
                    self.paths, platform_name=platform_name, runner=runner
                )
                self.assertTrue(status["installed"])
                self.assertFalse(status["command_available"])
                self.assertEqual(str(self.executable), status["command"][0])

                definitions[0].write_bytes(original[0] + b"\n")
                with self.assertRaisesRegex(ValueError, "not canonical"):
                    schedule_uninstall(
                        self.paths, platform_name=platform_name, runner=runner
                    )
                self.assertTrue(all(path.exists() for path in definitions))
                definitions[0].write_bytes(original[0])
                definitions[0].chmod(0o600)

                removed = schedule_uninstall(
                    self.paths, platform_name=platform_name, runner=runner
                )
                self.assertFalse(removed["installed"])
                self.assertIsNone(removed["command_available"])
                self.assertTrue(all(not path.exists() for path in definitions))
                with self.assertRaisesRegex(ValueError, "is not executable"):
                    schedule_install(
                        self.paths,
                        executable=self.executable,
                        platform_name=platform_name,
                        runner=runner,
                    )

    def test_install_rejects_symlinked_definition_root(self) -> None:
        outside = self.home / "outside"
        (outside / "systemd/user").mkdir(parents=True)
        (self.home / ".config").symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "scheduler directory is unsafe"):
            schedule_install(
                self.paths,
                executable=self.executable,
                platform_name="linux",
                runner=FakeRunner(),
            )
        self.assertFalse((outside / "systemd/user/sesh-compresh.service").exists())

    def test_status_and_uninstall_accept_exact_legacy_definitions(self) -> None:
        cases = (
            (
                "darwin",
                (scheduling_module._launchd_bytes(
                    self.executable, 120, legacy=True
                ),),
            ),
            (
                "linux",
                scheduling_module._systemd_bytes(
                    self.executable, 120, legacy=True
                ),
            ),
        )
        for platform_name, contents in cases:
            with self.subTest(platform=platform_name):
                runner = FakeRunner()
                definitions = scheduling_module.schedule_definition_paths(
                    self.paths, platform_name=platform_name
                )
                definitions[0].parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                definitions[0].parent.chmod(0o700)
                for path, content in zip(definitions, contents, strict=True):
                    path.write_bytes(content)
                    path.chmod(0o600)

                status = schedule_status(
                    self.paths, platform_name=platform_name, runner=runner
                )
                self.assertTrue(status["installed"])
                self.assertFalse(status["event_mode"])
                self.assertFalse(status["notify"])
                self.assertEqual(
                    [str(self.executable), "--json", "maintain", "--yes"],
                    status["command"],
                )
                upgraded = schedule_install(
                    self.paths,
                    executable=self.executable,
                    interval_seconds=120,
                    notify=True,
                    platform_name=platform_name,
                    runner=runner,
                )
                self.assertTrue(upgraded["event_mode"])
                self.assertTrue(upgraded["notify"])
                self.assertEqual("scheduled-maintain", upgraded["command"][2])
                removed = schedule_uninstall(
                    self.paths, platform_name=platform_name, runner=runner
                )
                self.assertFalse(removed["installed"])

    def test_events_are_sanitized_private_bounded_and_notifier_failures_are_data(
        self,
    ) -> None:
        counts = {
            "archived": 2,
            "protected": 3,
            "manifests_removed": 4,
            "objects_removed": 5,
        }
        commands: list[list[str]] = []

        def failed_notifier(command: list[str]) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            return subprocess.CompletedProcess(command, 9, "private/path", "secret")

        current = datetime(2026, 1, 1, tzinfo=UTC)
        first = record_maintenance_event(
            self.paths,
            counts=counts,
            reason_codes=("success", "protected", "low_space"),
            notify=True,
            platform_name="linux",
            runner=failed_notifier,
            resolver=lambda name: "/usr/bin/notify-send" if name == "notify-send" else None,
            now=current,
            event_limit=2,
        )
        self.assertEqual("pending", first["event"]["notification"])
        self.assertEqual("failed", first["notification_result"]["notification"])
        self.assertEqual(
            ["/usr/bin/notify-send", "Sesh Compresh"], commands[0][:2]
        )
        self.assertIn("reasons=success,protected,low_space", commands[0][2])
        self.assertNotIn(str(self.home), commands[0][2])

        second = record_maintenance_event(
            self.paths,
            counts=counts,
            reason_codes=("corruption", "failure"),
            notify=True,
            platform_name="win32",
            now=current + timedelta(seconds=1),
            event_limit=2,
        )
        self.assertEqual("failure", second["event"]["status"])
        self.assertEqual(
            "unavailable", second["notification_result"]["notification"]
        )
        third = record_maintenance_event(
            self.paths,
            counts=counts,
            reason_codes=("success",),
            now=current + timedelta(seconds=2),
            event_limit=2,
        )
        self.assertEqual("not_requested", third["event"]["notification"])
        self.assertIsNone(third["notification_result"])

        root = self.paths.state / "events"
        events = sorted(root.iterdir())
        self.assertEqual(3, len(events))
        self.assertEqual(0o700, root.stat().st_mode & 0o777)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in events))
        payloads = [path.read_text(encoding="utf-8") for path in events]
        self.assertTrue(all(str(self.home) not in payload for payload in payloads))
        self.assertTrue(all("secret" not in payload for payload in payloads))
        self.assertTrue(all('"path"' not in payload for payload in payloads))

    def test_event_validation_and_native_notification_argv(self) -> None:
        counts = {
            "archived": 0,
            "protected": 0,
            "manifests_removed": 0,
            "objects_removed": 0,
        }
        with self.assertRaisesRegex(ValueError, "counts"):
            record_maintenance_event(
                self.paths,
                counts=counts | {"archived": True},
                reason_codes=("success",),
            )
        with self.assertRaisesRegex(ValueError, "outcome"):
            record_maintenance_event(
                self.paths,
                counts=counts,
                reason_codes=("success", "failure"),
            )

        commands: list[list[str]] = []

        def sent(command: list[str]) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        event = record_maintenance_event(
            self.paths,
            counts=counts,
            reason_codes=("success",),
            notify=True,
            platform_name="darwin",
            runner=sent,
            resolver=lambda name: "/usr/bin/osascript" if name == "osascript" else None,
        )
        self.assertEqual("pending", event["event"]["notification"])
        self.assertEqual("sent", event["notification_result"]["notification"])
        self.assertEqual(["/usr/bin/osascript", "-e"], commands[0][:2])
        self.assertIn("display notification", commands[0][2])

        failed = record_maintenance_event(
            self.paths,
            counts=counts,
            reason_codes=("success",),
            notify=True,
            platform_name="linux",
            resolver=mock.Mock(side_effect=OSError("resolver failed")),
        )
        self.assertEqual("failed", failed["notification_result"]["notification"])

    def test_event_publication_precedes_notification_and_history_pruning(self) -> None:
        counts = {
            "archived": 0,
            "protected": 0,
            "manifests_removed": 0,
            "objects_removed": 0,
        }
        notifications: list[list[str]] = []

        def sent(command: list[str]) -> subprocess.CompletedProcess[str]:
            notifications.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        current = datetime(2026, 1, 1, tzinfo=UTC)
        with mock.patch.object(
            scheduling_module, "atomic_json", side_effect=OSError("publish failed")
        ), self.assertRaisesRegex(OSError, "publish failed"):
            record_maintenance_event(
                self.paths,
                counts=counts,
                reason_codes=("success",),
                notify=True,
                platform_name="linux",
                runner=sent,
                resolver=lambda _name: "/usr/bin/notify-send",
                now=current,
                event_limit=1,
            )
        self.assertEqual([], notifications)
        self.assertEqual([], list((self.paths.state / "events").iterdir()))

        prior = record_maintenance_event(
            self.paths,
            counts=counts,
            reason_codes=("success",),
            now=current,
            event_limit=1,
        )
        root = self.paths.state / "events"
        prior_path = root / f"{prior['event']['event_id']}.json"
        real_atomic_json = scheduling_module.atomic_json

        def fail_new_publication(path: Path, payload: dict, **kwargs) -> None:
            if kwargs.get("replace") is False:
                raise OSError("publish failed")
            real_atomic_json(path, payload, **kwargs)

        with mock.patch.object(
            scheduling_module, "atomic_json", side_effect=fail_new_publication
        ), self.assertRaisesRegex(OSError, "publish failed"):
            record_maintenance_event(
                self.paths,
                counts=counts,
                reason_codes=("success",),
                now=current + timedelta(seconds=1),
                event_limit=1,
            )
        self.assertEqual([prior_path], list(root.iterdir()))

        syncs = 0
        real_fsync_dir = common_module.fsync_dir

        def fail_notification_result_sync(path: Path) -> None:
            nonlocal syncs
            if Path(path) == root:
                syncs += 1
                if syncs == 2:
                    raise OSError("notification result sync failed")
            real_fsync_dir(path)

        with mock.patch.object(
            common_module, "fsync_dir", side_effect=fail_notification_result_sync
        ), mock.patch.object(
            scheduling_module.os, "link", wraps=scheduling_module.os.link
        ) as link, self.assertRaisesRegex(OSError, "notification result sync failed"):
            record_maintenance_event(
                self.paths,
                counts=counts,
                reason_codes=("success",),
                notify=True,
                platform_name="linux",
                runner=sent,
                resolver=lambda _name: "/usr/bin/notify-send",
                now=current + timedelta(seconds=2),
                event_limit=1,
            )
        events = sorted(root.iterdir())
        self.assertEqual(3, len(events))
        self.assertEqual(1, len(notifications))
        self.assertEqual(2, link.call_count)
        pending = [
            path
            for path in events
            if '"notification": "pending"' in path.read_text(encoding="utf-8")
        ]
        self.assertEqual(1, len(pending))
        self.assertTrue(prior_path.exists())

    def test_unsupported_platform_fails_without_state(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unsupported"):
            schedule_status(self.paths, platform_name="win32", runner=FakeRunner())
        self.assertFalse((self.home / "Library/LaunchAgents").exists())
        self.assertFalse((self.home / ".config/systemd/user").exists())


if __name__ == "__main__":
    unittest.main()
