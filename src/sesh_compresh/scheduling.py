from __future__ import annotations

import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable

from .common import (
    AppPaths,
    atomic_json,
    ensure_private_subdirectory,
    fsync_dir,
    iso_utc,
    load_json,
    new_run_id,
    regular_file_stat,
    utc_now,
)


LAUNCHD_LABEL = "com.local.sesh-compresh"
SYSTEMD_NAME = "sesh-compresh"
DEFAULT_INTERVAL_SECONDS = 3600
MAX_INTERVAL_SECONDS = 2**31 - 1
DEFAULT_LOW_SPACE_BYTES = 5 * 1024**3
EVENT_HISTORY_LIMIT = 100
EVENT_REASON_CODES = (
    "success",
    "protected",
    "corruption",
    "low_space",
    "failure",
)
EVENT_COUNT_KEYS = (
    "archived",
    "protected",
    "manifests_removed",
    "objects_removed",
)
_EVENT_FILE = re.compile(
    r"^[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9a-f]{32}\.json$"
)
_NOTIFICATION_FILE = re.compile(
    r"^(?P<event_id>[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9a-f]{32})"
    r"-notification\.json$"
)

Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]
Resolver = Callable[[str], str | None]


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _selected_platform(value: str | None) -> str:
    current = value or sys.platform
    if current == "darwin":
        return "launchd"
    if current.startswith("linux"):
        return "systemd"
    raise RuntimeError(f"scheduling is unsupported on this platform: {current}")


def _validate_interval(value: int) -> int:
    if type(value) is not int or not 1 <= value <= MAX_INTERVAL_SECONDS:
        raise ValueError(
            f"schedule interval must be between 1 and {MAX_INTERVAL_SECONDS} seconds"
        )
    return value


def _validate_executable_path(value: Path) -> Path:
    path = value.expanduser()
    if (
        not path.is_absolute()
        or Path(os.path.normpath(path)) != path
        or any(char in str(path) for char in "\0\r\n")
    ):
        raise ValueError(f"schedule executable must be an absolute safe path: {path}")
    return path


def _executable_available(path: Path) -> bool:
    try:
        info = path.stat(follow_symlinks=True)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and os.access(path, os.X_OK)


def _validate_executable(value: Path) -> Path:
    path = _validate_executable_path(value)
    if not _executable_available(path):
        raise ValueError(f"schedule executable is not executable: {path}")
    return path


def _default_executable() -> Path:
    executable = shutil.which("sesh-compresh")
    if executable is None:
        raise RuntimeError(
            "cannot find sesh-compresh; pass --executable with an absolute path"
        )
    return Path(executable)


def _command(
    executable: Path, *, notify: bool = False, legacy: bool = False
) -> list[str]:
    if legacy:
        return [str(executable), "--json", "maintain", "--yes"]
    command = [str(executable), "--json", "scheduled-maintain"]
    if notify:
        command.append("--notify")
    return command


def _paths(paths: AppPaths, backend: str) -> tuple[Path, ...]:
    if backend == "launchd":
        return (paths.home / "Library/LaunchAgents" / f"{LAUNCHD_LABEL}.plist",)
    root = paths.home / ".config/systemd/user"
    return (root / f"{SYSTEMD_NAME}.service", root / f"{SYSTEMD_NAME}.timer")


def schedule_definition_paths(
    paths: AppPaths, *, platform_name: str | None = None
) -> tuple[Path, ...]:
    return _paths(paths, _selected_platform(platform_name))


def _inspect_directory(path: Path, *, private: bool) -> None:
    info = path.lstat()
    if path.resolve(strict=True) != path or not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"scheduler directory is unsafe: {path}")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError(f"scheduler directory has the wrong owner: {path}")
    mode = stat.S_IMODE(info.st_mode)
    if private and os.name != "nt" and mode != 0o700:
        raise ValueError(f"scheduler directory is not private: {path}")
    if not private and mode & 0o022:
        raise ValueError(f"scheduler directory is writable by another user: {path}")


def _ensure_definition_root(paths: AppPaths, backend: str) -> Path:
    target = _paths(paths, backend)[0].parent
    current = paths.home
    _inspect_directory(current, private=False)
    for part in target.relative_to(paths.home).parts:
        child = current / part
        if not child.exists() and not child.is_symlink():
            child.mkdir(mode=0o700)
            fsync_dir(current)
        _inspect_directory(child, private=False)
        if child == target and os.name != "nt":
            child.chmod(0o700)
            fsync_dir(current)
        _inspect_directory(child, private=child == target)
        current = child
    return target


def _inspect_definition_root(paths: AppPaths, backend: str) -> Path | None:
    target = _paths(paths, backend)[0].parent
    if not target.exists() and not target.is_symlink():
        return None
    current = paths.home
    _inspect_directory(current, private=False)
    for part in target.relative_to(paths.home).parts:
        current /= part
        _inspect_directory(current, private=current == target)
    return target


def _read_definition(path: Path) -> bytes | None:
    if not path.exists() and not path.is_symlink():
        return None
    info = regular_file_stat(path)
    if hasattr(os, "getuid") and path.lstat().st_uid != os.getuid():
        raise ValueError(f"scheduler definition has the wrong owner: {path}")
    if os.name != "nt" and info["mode"] != 0o600:
        raise ValueError(f"scheduler definition is not private: {path}")
    return path.read_bytes()


def _atomic_write(path: Path, content: bytes) -> bool:
    current = _read_definition(path)
    if current == content:
        return False
    fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(raw)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        fsync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def _unlink(path: Path) -> bool:
    if _read_definition(path) is None:
        return False
    path.unlink()
    fsync_dir(path.parent)
    return True


def _launchd_bytes(
    executable: Path, interval: int, *, notify: bool = False, legacy: bool = False
) -> bytes:
    return plistlib.dumps(
        {
            "Label": LAUNCHD_LABEL,
            "ProgramArguments": _command(executable, notify=notify, legacy=legacy),
            "RunAtLoad": True,
            "StartInterval": interval,
        },
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )


def _parse_launchd(content: bytes) -> tuple[Path, int, bool, bool]:
    payload = plistlib.loads(content)
    if not isinstance(payload, dict) or set(payload) != {
        "Label",
        "ProgramArguments",
        "RunAtLoad",
        "StartInterval",
    }:
        raise ValueError("launchd schedule definition has invalid fields")
    arguments = payload.get("ProgramArguments")
    interval = payload.get("StartInterval")
    if (
        payload.get("Label") != LAUNCHD_LABEL
        or payload.get("RunAtLoad") is not True
        or not isinstance(arguments, list)
        or len(arguments) not in {3, 4}
        or type(arguments[0]) is not str
    ):
        raise ValueError("launchd schedule definition is invalid")
    tail = arguments[1:]
    legacy = tail == ["--json", "maintain", "--yes"]
    notify = tail == ["--json", "scheduled-maintain", "--notify"]
    if not legacy and not notify and tail != ["--json", "scheduled-maintain"]:
        raise ValueError("launchd schedule definition is invalid")
    executable = _validate_executable_path(Path(arguments[0]))
    interval = _validate_interval(interval)
    if content != _launchd_bytes(
        executable, interval, notify=notify, legacy=legacy
    ):
        raise ValueError("launchd schedule definition is not canonical")
    return executable, interval, notify, legacy


def _systemd_timer_bytes(interval: int) -> bytes:
    return (
        "[Unit]\n"
        "Description=Run Sesh Compresh maintenance\n\n"
        "[Timer]\n"
        f"OnBootSec={interval}s\n"
        f"OnUnitActiveSec={interval}s\n"
        "Persistent=true\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    ).encode()


def _systemd_bytes(
    executable: Path, interval: int, *, notify: bool = False, legacy: bool = False
) -> tuple[bytes, bytes]:
    if any(
        not (char.isascii() and (char.isalnum() or char in "/._+-"))
        for char in str(executable)
    ):
        raise ValueError(
            "systemd schedule executable path contains an unsafe unit character"
        )
    service = (
        "[Unit]\n"
        "Description=Sesh Compresh maintenance\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={' '.join(_command(executable, notify=notify, legacy=legacy))}\n"
    ).encode()
    return service, _systemd_timer_bytes(interval)


def _parse_systemd_service(content: bytes) -> tuple[Path, bool, bool]:
    try:
        line = next(
            value for value in content.decode().splitlines() if value.startswith("ExecStart=")
        )
    except (UnicodeError, StopIteration) as exc:
        raise ValueError("systemd service definition is invalid") from exc
    arguments = line.removeprefix("ExecStart=").split()
    if len(arguments) not in {3, 4}:
        raise ValueError("systemd service command is invalid")
    tail = arguments[1:]
    legacy = tail == ["--json", "maintain", "--yes"]
    notify = tail == ["--json", "scheduled-maintain", "--notify"]
    if not legacy and not notify and tail != ["--json", "scheduled-maintain"]:
        raise ValueError("systemd service command is invalid")
    executable = _validate_executable_path(Path(arguments[0]))
    if content != _systemd_bytes(
        executable, DEFAULT_INTERVAL_SECONDS, notify=notify, legacy=legacy
    )[0]:
        raise ValueError("systemd service definition is not canonical")
    return executable, notify, legacy


def _parse_systemd_timer(content: bytes) -> int:
    try:
        values = {
            key: value
            for key, separator, value in (
                line.partition("=") for line in content.decode().splitlines()
            )
            if separator and key in {"OnBootSec", "OnUnitActiveSec"}
        }
        if set(values) != {"OnBootSec", "OnUnitActiveSec"}:
            raise ValueError
        suffix = values["OnUnitActiveSec"]
        if values["OnBootSec"] != suffix or not suffix.endswith("s"):
            raise ValueError
        interval = _validate_interval(int(suffix[:-1]))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("systemd timer definition is invalid") from exc
    if content != _systemd_timer_bytes(interval):
        raise ValueError("systemd timer definition is not canonical")
    return interval


def _query(
    runner: Runner,
    command: list[str],
    *,
    false_codes: frozenset[int],
    false_message: str | None = None,
) -> bool:
    result = runner(command)
    if result.returncode == 0:
        return True
    detail = (result.stderr or result.stdout).strip()
    expected_detail = (
        not detail
        if false_message is None
        else false_message.casefold() in detail.casefold()
    )
    if result.returncode in false_codes and expected_detail:
        return False
    suffix = f": {detail}" if detail else ""
    raise RuntimeError(
        f"scheduler query failed with status {result.returncode}: "
        f"{' '.join(command)}{suffix}"
    )


def _checked(runner: Runner, command: list[str]) -> None:
    result = runner(command)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(
            f"scheduler command failed with status {result.returncode}: "
            f"{' '.join(command)}{suffix}"
        )


def _launchd_live(runner: Runner) -> bool:
    return _query(
        runner,
        ["launchctl", "print", f"gui/{os.getuid()}/{LAUNCHD_LABEL}"],
        false_codes=frozenset({113}),
        false_message="could not find service",
    )


def _systemd_live(runner: Runner) -> tuple[bool, bool]:
    timer = f"{SYSTEMD_NAME}.timer"
    enabled = _query(
        runner,
        ["systemctl", "--user", "is-enabled", "--quiet", timer],
        false_codes=frozenset({1}),
    )
    active = _query(
        runner,
        ["systemctl", "--user", "is-active", "--quiet", timer],
        false_codes=frozenset({3, 4}),
    )
    return enabled, active


def schedule_status(
    paths: AppPaths,
    *,
    platform_name: str | None = None,
    runner: Runner = _run,
) -> dict[str, Any]:
    backend = _selected_platform(platform_name)
    definitions = _paths(paths, backend)
    _inspect_definition_root(paths, backend)
    contents = [_read_definition(path) for path in definitions]
    if backend == "launchd":
        active = _launchd_live(runner)
        if contents[0] is None:
            return _status(backend, definitions, False, active, active, None, None)
        executable, interval, notify, legacy = _parse_launchd(contents[0])
        return _status(
            backend,
            definitions,
            True,
            active,
            active,
            executable,
            interval,
            notify,
            legacy,
        )
    enabled, active = _systemd_live(runner)
    if contents == [None, None]:
        return _status(backend, definitions, False, active, enabled, None, None)
    if any(content is None for content in contents):
        raise ValueError("systemd schedule installation is incomplete")
    executable, notify, legacy = _parse_systemd_service(contents[0])
    interval = _parse_systemd_timer(contents[1])
    return _status(
        backend,
        definitions,
        True,
        active,
        enabled,
        executable,
        interval,
        notify,
        legacy,
    )


def _status(
    backend: str,
    definitions: tuple[Path, ...],
    installed: bool,
    active: bool,
    enabled: bool,
    executable: Path | None,
    interval: int | None,
    notify: bool = False,
    legacy: bool = False,
) -> dict[str, Any]:
    return {
        "backend": backend,
        "installed": installed,
        "active": active,
        "enabled": enabled,
        "command": (
            _command(executable, notify=notify, legacy=legacy)
            if executable is not None
            else None
        ),
        "command_available": (
            _executable_available(executable) if executable is not None else None
        ),
        "interval_seconds": interval,
        "notify": notify,
        "event_mode": installed and not legacy,
        "definitions": [str(path) for path in definitions],
    }


def schedule_install(
    paths: AppPaths,
    *,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
    executable: Path | None = None,
    notify: bool = False,
    platform_name: str | None = None,
    runner: Runner = _run,
) -> dict[str, Any]:
    backend = _selected_platform(platform_name)
    interval = _validate_interval(interval_seconds)
    if type(notify) is not bool:
        raise ValueError("schedule notification option is invalid")
    program = _validate_executable(executable or _default_executable())
    definitions = _paths(paths, backend)
    _ensure_definition_root(paths, backend)
    if backend == "launchd":
        current = _read_definition(definitions[0])
        if current is not None:
            _parse_launchd(current)
        active = _launchd_live(runner)
        desired = _launchd_bytes(program, interval, notify=notify)
        if current == desired and active:
            return schedule_status(paths, platform_name=platform_name, runner=runner)
        if active:
            _checked(
                runner,
                ["launchctl", "bootout", f"gui/{os.getuid()}/{LAUNCHD_LABEL}"],
            )
        _atomic_write(definitions[0], desired)
        _checked(
            runner,
            ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(definitions[0])],
        )
    else:
        desired = _systemd_bytes(program, interval, notify=notify)
        current_definitions = [_read_definition(path) for path in definitions]
        for path, current in zip(definitions, current_definitions, strict=True):
            if current is not None:
                (
                    _parse_systemd_service(current)
                    if path.suffix == ".service"
                    else _parse_systemd_timer(current)
                )
        enabled, active = _systemd_live(runner)
        definitions_match = current_definitions == list(desired)
        if definitions_match and enabled and active:
            return schedule_status(paths, platform_name=platform_name, runner=runner)
        timer = f"{SYSTEMD_NAME}.timer"
        if not definitions_match and (enabled or active):
            _checked(
                runner,
                ["systemctl", "--user", "disable", "--now", timer],
            )
        for path, content in zip(definitions, desired, strict=True):
            _atomic_write(path, content)
        _checked(runner, ["systemctl", "--user", "daemon-reload"])
        _checked(runner, ["systemctl", "--user", "enable", timer])
        _checked(runner, ["systemctl", "--user", "restart", timer])
    return schedule_status(paths, platform_name=platform_name, runner=runner)


def schedule_uninstall(
    paths: AppPaths,
    *,
    platform_name: str | None = None,
    runner: Runner = _run,
) -> dict[str, Any]:
    backend = _selected_platform(platform_name)
    definitions = _paths(paths, backend)
    _inspect_definition_root(paths, backend)
    contents = [_read_definition(path) for path in definitions]
    if backend == "launchd":
        if contents[0] is not None:
            _parse_launchd(contents[0])
        if _launchd_live(runner):
            _checked(
                runner,
                ["launchctl", "bootout", f"gui/{os.getuid()}/{LAUNCHD_LABEL}"],
            )
    else:
        if contents[0] is not None:
            _parse_systemd_service(contents[0])
        if contents[1] is not None:
            _parse_systemd_timer(contents[1])
        enabled, active = _systemd_live(runner)
        if enabled or active:
            _checked(
                runner,
                [
                    "systemctl",
                    "--user",
                    "disable",
                    "--now",
                    f"{SYSTEMD_NAME}.timer",
                ],
            )
    changes = [_unlink(path) for path in definitions]
    changed = any(changes)
    if backend == "systemd" and changed:
        _checked(runner, ["systemctl", "--user", "daemon-reload"])
    return schedule_status(paths, platform_name=platform_name, runner=runner)


def _validate_event_counts(counts: dict[str, int]) -> dict[str, int]:
    if set(counts) != set(EVENT_COUNT_KEYS) or any(
        type(counts[key]) is not int or counts[key] < 0 for key in EVENT_COUNT_KEYS
    ):
        raise ValueError("maintenance event counts are invalid")
    return {key: counts[key] for key in EVENT_COUNT_KEYS}


def _validate_event_reasons(reason_codes: Iterable[str]) -> list[str]:
    requested = list(reason_codes)
    if (
        not requested
        or len(requested) != len(set(requested))
        or any(code not in EVENT_REASON_CODES for code in requested)
    ):
        raise ValueError("maintenance event reason codes are invalid")
    selected = [code for code in EVENT_REASON_CODES if code in requested]
    failing = any(code in selected for code in ("corruption", "failure"))
    if ("success" in selected) == failing:
        raise ValueError("maintenance event outcome is inconsistent")
    return selected


def _event_summary(event: dict[str, Any]) -> str:
    counts = event["counts"]
    reasons = ",".join(event["reason_codes"])
    return (
        f"status={event['status']} reasons={reasons} "
        f"archived={counts['archived']} protected={counts['protected']} "
        f"manifests_removed={counts['manifests_removed']} "
        f"objects_removed={counts['objects_removed']}"
    )


def _notify_event(
    event: dict[str, Any],
    *,
    platform_name: str | None,
    runner: Runner,
    resolver: Resolver,
) -> str:
    current = platform_name or sys.platform
    summary = _event_summary(event)
    try:
        if current == "darwin":
            notifier = resolver("osascript")
            command = (
                [
                    notifier,
                    "-e",
                    f'display notification "{summary}" with title "Sesh Compresh"',
                ]
                if notifier is not None
                else None
            )
        elif current.startswith("linux"):
            notifier = resolver("notify-send")
            command = (
                [notifier, "Sesh Compresh", summary]
                if notifier is not None
                else None
            )
        else:
            command = None
    except OSError:
        return "failed"
    if command is None:
        return "unavailable"
    try:
        result = runner(command)
    except (OSError, subprocess.SubprocessError):
        return "failed"
    return "sent" if result.returncode == 0 else "failed"


def _event_file(path: Path) -> None:
    info = regular_file_stat(path)
    if hasattr(os, "getuid") and path.lstat().st_uid != os.getuid():
        raise ValueError("maintenance event file has the wrong owner")
    if os.name != "nt" and info["mode"] != 0o600:
        raise ValueError("maintenance event file is not private")


def _event_files(root: Path) -> tuple[list[Path], dict[str, Path]]:
    events = []
    notifications = {}
    for path in sorted(root.iterdir()):
        event_match = _EVENT_FILE.fullmatch(path.name)
        notification_match = _NOTIFICATION_FILE.fullmatch(path.name)
        if event_match is None and notification_match is None:
            continue
        _event_file(path)
        payload = load_json(path)
        if event_match is not None:
            if (
                set(payload)
                != {
                    "schema_version",
                    "kind",
                    "event_id",
                    "occurred_at",
                    "status",
                    "reason_codes",
                    "counts",
                    "notification",
                }
                or payload.get("schema_version") != 1
                or payload.get("kind") != "scheduled-maintenance-event"
                or payload.get("event_id") != path.stem
                or payload.get("notification") not in {"pending", "not_requested"}
            ):
                raise ValueError("maintenance event record is invalid")
            _validate_event_counts(payload.get("counts"))
            reasons = _validate_event_reasons(payload.get("reason_codes", ()))
            expected_status = (
                "failure"
                if any(code in reasons for code in ("corruption", "failure"))
                else "success"
            )
            if payload.get("status") != expected_status:
                raise ValueError("maintenance event record is invalid")
            events.append(path)
            continue
        assert notification_match is not None
        event_id = notification_match.group("event_id")
        if (
            set(payload)
            != {"schema_version", "kind", "event_id", "notification"}
            or payload.get("schema_version") != 1
            or payload.get("kind") != "scheduled-maintenance-notification"
            or payload.get("event_id") != event_id
            or payload.get("notification") not in {"sent", "failed", "unavailable"}
            or event_id in notifications
        ):
            raise ValueError("maintenance notification record is invalid")
        notifications[event_id] = path
    if any(event_id not in {event.stem for event in events} for event_id in notifications):
        raise ValueError("maintenance notification has no event")
    return events, notifications


def record_maintenance_event(
    paths: AppPaths,
    *,
    counts: dict[str, int],
    reason_codes: Iterable[str],
    notify: bool = False,
    platform_name: str | None = None,
    runner: Runner = _run,
    resolver: Resolver = shutil.which,
    now: datetime | None = None,
    event_limit: int = EVENT_HISTORY_LIMIT,
) -> dict[str, Any]:
    if type(notify) is not bool or type(event_limit) is not int or event_limit < 1:
        raise ValueError("maintenance event options are invalid")
    current = (now or utc_now()).astimezone(UTC)
    reasons = _validate_event_reasons(reason_codes)
    event = {
        "schema_version": 1,
        "kind": "scheduled-maintenance-event",
        "event_id": new_run_id(current),
        "occurred_at": iso_utc(current),
        "status": (
            "failure"
            if any(code in reasons for code in ("corruption", "failure"))
            else "success"
        ),
        "reason_codes": reasons,
        "counts": _validate_event_counts(counts),
        "notification": "pending" if notify else "not_requested",
    }
    paths.ensure_private()
    root = ensure_private_subdirectory(paths.state, "events")
    event_path = root / f"{event['event_id']}.json"
    atomic_json(event_path, event, replace=False)
    notification_result = None
    if notify:
        notification_result = {
            "schema_version": 1,
            "kind": "scheduled-maintenance-notification",
            "event_id": event["event_id"],
            "notification": _notify_event(
                event,
                platform_name=platform_name,
                runner=runner,
                resolver=resolver,
            ),
        }
        notification_path = root / f"{event['event_id']}-notification.json"
        atomic_json(notification_path, notification_result, replace=False)

    existing, notifications = _event_files(root)
    remove_count = max(0, len(existing) - event_limit)
    stale_events = [path for path in existing if path != event_path]
    for stale in stale_events[:remove_count]:
        notification = notifications.get(stale.stem)
        if notification is not None:
            notification.unlink()
        stale.unlink()
    if remove_count:
        fsync_dir(root)
    return {"event": event, "notification_result": notification_result}
