from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from .archive import (
    _close_recovery_item,
    _inventory_recovery_items,
    _require_recovery_primitives,
    _validate_recovery_item,
    apply_archive_plan,
    archive_stats,
    benchmark_dictionary,
    create_archive_plan,
    list_archives,
    recover_quarantine,
    restore_manifest,
    restore_manifest_set,
    train_dictionary,
    verify_all,
)
from .clean import (
    DEFAULT_CLEAN_QUARANTINE_DAYS,
    _clean_quarantine_journals,
    apply_clean_expiry_plan,
    apply_clean_plan,
    create_clean_expiry_plan,
    create_clean_plan,
    undo_clean,
)
from .common import AppPaths, allocated_bytes, app_lock, load_json, regular_file_stat
from .extract import extract_member_range, extract_member_tail
from .history import history_summary
from .encryption import (
    enable_archive_encryption,
    encryption_status,
    restore_archive_key,
)
from .observer import (
    DEFAULT_ARCHIVE_CAP_BYTES,
    DEFAULT_ARCHIVE_TTL_DAYS,
    DEFAULT_GRACE_SECONDS,
    ClaudeMemPaths,
    apply_archive_expiry_plan,
    apply_observer_expiry_plan,
    apply_observer_gc_plan,
    create_archive_expiry_plan,
    create_observer_expiry_plan,
    create_observer_gc_plan,
)
from .pressure import PressurePlanError, plan_disk_pressure
from .portable import (
    apply_portable_import_plan,
    create_portable_import_plan,
    export_portable_archive,
    recover_portable_imports,
)
from .repack import apply_repack_plan, create_repack_plan, recover_repack
from .scheduling import (
    DEFAULT_INTERVAL_SECONDS,
    DEFAULT_LOW_SPACE_BYTES,
    record_maintenance_event,
    schedule_definition_paths,
    schedule_install,
    schedule_status,
    schedule_uninstall,
)
from .schema import check_archive_schema, rebuild_latest_indexes


def _bytes(value: int) -> str:
    return f"{value / (1024**3):.2f} GiB"


def _emit(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    for key, value in payload.items():
        if "bytes" in key and isinstance(value, int):
            print(f"{key}: {_bytes(value)}")
        elif isinstance(value, (list, dict)):
            print(f"{key}: {json.dumps(value, sort_keys=True)}")
        else:
            print(f"{key}: {value}")


def _audit(paths: AppPaths) -> dict[str, Any]:
    disk = shutil.disk_usage(paths.home)
    targets = {
        "private_tmp": Path("/private/tmp"),
        "claude_projects": paths.home / ".claude/projects",
        "codex_sessions": paths.home / ".codex/sessions",
        "claude_mem": paths.home / ".claude-mem",
        "archives": paths.archive,
    }
    sizes = {}
    for key, path in targets.items():
        if path.exists() and not path.is_symlink():
            try:
                sizes[key] = allocated_bytes(path)
            except (OSError, PermissionError):
                sizes[key] = None
    return {
        "disk_total_bytes": disk.total,
        "disk_used_bytes": disk.used,
        "disk_free_bytes": disk.free,
        "paths": sizes,
    }


def _plan_show_unchecked(plan_path: Path) -> dict[str, Any]:
    regular_file_stat(plan_path)
    plan = load_json(plan_path)
    kind = plan.get("kind")
    if not isinstance(kind, str):
        raise ValueError("plan kind is invalid")
    candidates = []
    skipped = []
    if kind == "archive-plan":
        _require_plan_fields(plan, sessions=list, skipped=dict)
        _require_plan_counts(plan["skipped"])
        for session in plan["sessions"]:
            _require_plan_fields(
                session,
                files=list,
                source_root=str,
                retention_days=int,
                provider=str,
                session_id=str,
            )
            files = session["files"]
            for item in files:
                _require_plan_fields(item, path=str, size=int)
            candidates.append(
                {
                    "path": files[0]["path"] if files else session.get("source_root"),
                    "reason": f"older than {session.get('retention_days')} days",
                    "marker": f"{session.get('provider')}:{session.get('session_id')}",
                    "action": "archive",
                    "bytes": sum(item.get("size", 0) for item in files),
                }
            )
        skipped = [
            {"reason": reason, "count": count}
            for reason, count in plan["skipped"].items()
            if type(reason) is str and type(count) is int
        ]
    elif kind == "clean-plan":
        _require_plan_fields(plan, candidates=list, skipped_open=list)
        for item in plan["candidates"]:
            _require_plan_fields(
                item,
                path=str,
                family=str,
                marker=str,
                action=str,
                allocated_bytes=int,
            )
        if any(type(path) is not str for path in plan["skipped_open"]):
            raise ValueError("plan entries are invalid")
        candidates = [
            {
                "path": item.get("path"),
                "reason": item.get("family"),
                "marker": item.get("marker"),
                "action": item.get("action"),
                "bytes": item.get("allocated_bytes", 0),
            }
            for item in plan["candidates"]
        ]
        skipped = [
            {"path": path, "reason": "open", "count": 1}
            for path in plan["skipped_open"]
        ]
    elif kind == "observer-gc-plan":
        _require_plan_fields(plan, candidates=list, protected=dict)
        _require_plan_counts(plan["protected"])
        for session in plan["candidates"]:
            _require_plan_fields(session, files=list, source_root=str, session_id=str)
            files = session["files"]
            for item in files:
                _require_plan_fields(item, path=str, size=int)
            candidates.append(
                {
                    "path": files[0]["path"] if files else session.get("source_root"),
                    "reason": "unreferenced observer session",
                    "marker": session.get("session_id"),
                    "action": "archive",
                    "bytes": sum(item.get("size", 0) for item in files),
                }
            )
        skipped = [
            {"reason": reason, "count": count}
            for reason, count in plan["protected"].items()
            if count
        ]
    elif kind in {"archive-expiry-plan", "observer-expiry-plan"}:
        _require_plan_fields(plan, provider=str, manifests=list, cas_candidates=list)
        for item in plan["manifests"]:
            _require_plan_fields(item, path=str, reasons=list, size=int)
            if any(type(reason) is not str for reason in item["reasons"]):
                raise ValueError("plan entries are invalid")
        for item in plan["cas_candidates"]:
            _require_plan_fields(item, path=str, relative=str, size=int)
        candidates = [
            {
                "path": item.get("path"),
                "reason": ",".join(item.get("reasons", [])),
                "marker": plan.get("provider"),
                "action": "delete-manifest",
                "bytes": item.get("size", 0),
            }
            for item in plan["manifests"]
        ] + [
            {
                "path": item.get("path"),
                "reason": "unreachable CAS object",
                "marker": item.get("relative"),
                "action": "delete-object",
                "bytes": item.get("size", 0),
            }
            for item in plan["cas_candidates"]
        ]
    elif kind == "clean-expiry-plan":
        _require_plan_fields(plan, retention_days=int, journals=list)
        for item in plan["journals"]:
            _require_plan_fields(item, path=str, size=int)
        candidates = [
            {
                "path": item.get("path"),
                "reason": f"older than {plan.get('retention_days')} days",
                "marker": "cleanup quarantine journal",
                "action": "expire-quarantine",
                "bytes": item.get("size", 0),
            }
            for item in plan["journals"]
        ]
    elif kind == "portable-import-plan":
        _require_plan_fields(
            plan,
            artifact=dict,
            bundle_id=str,
            manifests=int,
            objects=int,
        )
        _require_plan_fields(plan["artifact"], path=str, size=int, sha256=str)
        candidates = [
            {
                "path": plan["artifact"]["path"],
                "reason": "validated portable archive",
                "marker": plan["bundle_id"],
                "action": "import",
                "bytes": plan["artifact"]["size"],
            }
        ]
    else:
        raise ValueError(f"unsupported plan kind: {kind}")
    for item in candidates:
        _require_plan_fields(
            item, path=str, reason=str, marker=str, action=str, bytes=int
        )
        if item["bytes"] < 0:
            raise ValueError("plan entries are invalid")
    for item in skipped:
        _require_plan_fields(item, reason=str, count=int)
        if item["count"] < 0 or ("path" in item and type(item["path"]) is not str):
            raise ValueError("plan entries are invalid")
    skipped_count = sum(item["count"] for item in skipped)
    total_bytes = sum(item["bytes"] for item in candidates)
    action_word = "action" if len(candidates) == 1 else "actions"
    item_word = "item is" if skipped_count == 1 else "items are"
    return {
        "plan": str(plan_path),
        "kind": kind,
        "summary": (
            f"Apply would perform {len(candidates)} {action_word} over {total_bytes} bytes; "
            f"{skipped_count} {item_word} skipped or protected."
        ),
        "candidates": candidates,
        "skipped": skipped,
    }


def _require_plan_fields(value: Any, **fields: type) -> None:
    if not isinstance(value, dict) or any(
        type(value.get(key)) is not expected for key, expected in fields.items()
    ):
        raise ValueError("plan entries are invalid")


def _require_plan_counts(value: dict[Any, Any]) -> None:
    if any(
        type(key) is not str or type(count) is not int or count < 0
        for key, count in value.items()
    ):
        raise ValueError("plan entries are invalid")


def _plan_show(plan_path: Path) -> dict[str, Any]:
    try:
        return _plan_show_unchecked(plan_path)
    except (AttributeError, KeyError, TypeError) as exc:
        raise ValueError(f"plan entries are invalid: {plan_path}") from exc


def _required_tool(name: str) -> str:
    executable = shutil.which(name)
    if executable is None:
        raise RuntimeError(f"required tool is unavailable: {name}")
    args = [executable, "--version"] if name == "zstd" else [executable, "-v"]
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"required tool failed: {name} (status {result.returncode})")
    return executable


def _check_anchors(paths: AppPaths) -> str:
    fixed = [
        paths.archive,
        paths.archive / "manifests",
        paths.archive / "dictionaries",
        paths.archive / "objects",
        paths.archive / "objects/sha256",
        paths.state,
        paths.state / "clean-quarantine",
        paths.state / "latest",
        paths.state / "plans",
        paths.state / "quarantine",
    ]
    dynamic = []
    for root in (
        paths.archive / "manifests",
        paths.archive / "objects/sha256",
        paths.state / "quarantine",
    ):
        if root.is_dir() and not root.is_symlink():
            dynamic.extend(Path(entry.path) for entry in os.scandir(root))
    anchors = fixed + dynamic
    for path in anchors:
        info = path.lstat()
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError(f"directory is not canonical: {path}")
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"directory is not a real directory: {path}")
        if os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError(f"directory permissions are not private: {path}")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise ValueError(f"directory owner is not the current user: {path}")
    return f"{len(anchors)} private directory anchors"


def _check_lock(paths: AppPaths) -> str:
    with app_lock(paths):
        return "application lock acquired"


def _check_manifests(paths: AppPaths) -> str:
    with app_lock(paths):
        result = verify_all(paths)
    return f"{result['manifests']} manifests and {result['files']} files verified"


def _check_archive_quarantine(paths: AppPaths) -> str:
    with app_lock(paths):
        _require_recovery_primitives()
        root_fd, items = _inventory_recovery_items(paths.state / "quarantine")
        try:
            claimed: set[Path] = set()
            for item in items:
                _validate_recovery_item(paths, item, claimed)
            return f"{len(items)} archive quarantine journals verified"
        finally:
            for item in items:
                _close_recovery_item(item)
            os.close(root_fd)


def _check_clean_quarantine(paths: AppPaths) -> str:
    with app_lock(paths):
        journals = _clean_quarantine_journals(paths)
        return f"{len(journals)} cleanup quarantine journals verified"


def _scheduler_artifacts(paths: AppPaths) -> tuple[Path, ...]:
    try:
        return schedule_definition_paths(paths)
    except RuntimeError:
        return ()


def _check_scheduler(paths: AppPaths) -> str:
    status = schedule_status(paths)
    if not status["installed"]:
        return "scheduler is not installed"
    if not status["command_available"]:
        raise RuntimeError("installed scheduler executable is unavailable")
    if not status["enabled"] or not status["active"]:
        raise RuntimeError("installed scheduler is not enabled and active")
    return "installed scheduler is enabled and active"


def _doctor_check(name: str, required: bool, action: Any) -> dict[str, Any]:
    try:
        detail = action()
        return {"name": name, "ok": True, "required": required, "detail": detail}
    except Exception as exc:
        return {
            "name": name,
            "ok": False,
            "required": required,
            "detail": f"{exc.__class__.__name__}: {exc}",
        }


def _doctor(paths: AppPaths) -> dict[str, Any]:
    scheduler_required = any(
        path.exists() or path.is_symlink() for path in _scheduler_artifacts(paths)
    )
    checks = [
        _doctor_check("tool:zstd", True, lambda: _required_tool("zstd")),
        _doctor_check("tool:lsof", True, lambda: _required_tool("lsof")),
        _doctor_check("directories", True, lambda: _check_anchors(paths)),
        _doctor_check("lock", True, lambda: _check_lock(paths)),
        _doctor_check("manifests", True, lambda: _check_manifests(paths)),
        _doctor_check(
            "archive-quarantine", True, lambda: _check_archive_quarantine(paths)
        ),
        _doctor_check("clean-quarantine", True, lambda: _check_clean_quarantine(paths)),
        _doctor_check("scheduler", scheduler_required, lambda: _check_scheduler(paths)),
    ]
    failures = [
        check["name"] for check in checks if check["required"] and not check["ok"]
    ]
    return {"ok": not failures, "required_failures": failures, "checks": checks}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sesh-compresh")
    parser.add_argument(
        "--home", type=Path, help="override home directory (primarily for tests)"
    )
    parser.add_argument(
        "--claude-config-dir", type=Path, help="override CLAUDE_CONFIG_DIR"
    )
    parser.add_argument(
        "--claude-mem-data-dir", type=Path, help="override CLAUDE_MEM_DATA_DIR"
    )
    parser.add_argument("--json", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("audit")
    sub.add_parser("doctor")

    schedule = sub.add_parser("schedule")
    schedule_sub = schedule.add_subparsers(dest="schedule_command", required=True)
    schedule_install_parser = schedule_sub.add_parser("install")
    schedule_install_parser.add_argument(
        "--interval-seconds", type=int, default=DEFAULT_INTERVAL_SECONDS
    )
    schedule_install_parser.add_argument("--executable", type=Path)
    schedule_install_parser.add_argument(
        "--notify", action="store_true", help="send local maintenance notifications"
    )
    schedule_sub.add_parser("status")
    schedule_sub.add_parser("uninstall")

    plan = sub.add_parser("plan")
    plan_sub = plan.add_subparsers(dest="plan_command", required=True)
    plan_show = plan_sub.add_parser("show")
    plan_show.add_argument("plan", type=Path)

    pressure = sub.add_parser("pressure")
    pressure_sub = pressure.add_subparsers(dest="pressure_command", required=True)
    pressure_plan = pressure_sub.add_parser("plan")
    pressure_plan.add_argument("--trigger-free-gib", required=True)
    pressure_plan.add_argument("--target-free-gib", required=True)
    pressure_plan.add_argument("--policy", type=Path)

    history = sub.add_parser("history", help="show aggregated maintenance history")
    history.add_argument("--top", type=int, default=10)

    archive = sub.add_parser("archive")
    archive_sub = archive.add_subparsers(dest="archive_command", required=True)
    archive_sub.add_parser("plan")
    archive_apply = archive_sub.add_parser("apply")
    archive_apply.add_argument("plan", type=Path)
    archive_apply.add_argument("--yes", action="store_true", required=True)
    archive_list = archive_sub.add_parser("list")
    archive_list.add_argument("--provider")
    archive_list.add_argument("--session-id")
    archive_list.add_argument("--date")
    archive_list.add_argument("--version", type=int)
    archive_list.add_argument(
        "--sort",
        choices=("activity", "archive", "raw", "ratio", "version"),
        default="archive",
    )
    archive_list.add_argument("--reverse", action="store_true")
    archive_sub.add_parser("stats")
    archive_schema = archive_sub.add_parser("schema")
    archive_schema_sub = archive_schema.add_subparsers(
        dest="archive_schema_command", required=True
    )
    archive_schema_sub.add_parser("check")
    archive_schema_rebuild = archive_schema_sub.add_parser("rebuild-index")
    archive_schema_rebuild.add_argument("--yes", action="store_true", required=True)
    archive_verify = archive_sub.add_parser("verify")
    archive_verify.add_argument(
        "--continue", dest="continue_on_error", action="store_true"
    )
    archive_expire = archive_sub.add_parser("expire")
    archive_expire_sub = archive_expire.add_subparsers(
        dest="archive_expire_command", required=True
    )
    archive_expire_plan = archive_expire_sub.add_parser("plan")
    archive_expire_plan.add_argument(
        "--provider", required=True, choices=("claude", "codex", "codex-archived")
    )
    archive_expire_plan.add_argument(
        "--ttl-days", type=int, default=DEFAULT_ARCHIVE_TTL_DAYS
    )
    archive_expire_plan.add_argument(
        "--cap-gib", type=float, default=DEFAULT_ARCHIVE_CAP_BYTES / 1024**3
    )
    archive_expire_apply = archive_expire_sub.add_parser("apply")
    archive_expire_apply.add_argument("plan", type=Path)
    archive_expire_apply.add_argument("--yes", action="store_true", required=True)
    archive_train = archive_sub.add_parser("train-dictionary")
    archive_train.add_argument(
        "--provider", required=True, choices=("claude", "codex", "codex-archived")
    )
    archive_train.add_argument("--samples", type=int, default=256)
    archive_train.add_argument("--max-dict-kib", type=int, default=112)
    archive_train.add_argument("--minimum-benefit-kib", type=int, default=0)
    archive_benchmark = archive_sub.add_parser("benchmark")
    archive_benchmark.add_argument(
        "--provider", required=True, choices=("claude", "codex", "codex-archived")
    )
    archive_benchmark.add_argument("--samples", type=int, default=256)
    archive_benchmark.add_argument("--max-dict-kib", type=int, default=112)
    archive_benchmark.add_argument("--minimum-benefit-kib", type=int, default=0)
    archive_restore = archive_sub.add_parser("restore")
    archive_restore.add_argument("manifest", nargs="?")
    archive_restore.add_argument("--destination", type=Path)
    archive_restore.add_argument("--member")
    archive_restore.add_argument("--provider")
    archive_restore.add_argument("--from-date")
    archive_restore.add_argument("--to-date")
    archive_extract = archive_sub.add_parser("extract")
    archive_extract.add_argument("manifest", type=Path)
    archive_extract.add_argument("--member", required=True)
    archive_extract.add_argument("--output", required=True, type=Path)
    archive_extract.add_argument("--offset", type=int)
    archive_extract.add_argument("--length", type=int)
    archive_extract.add_argument("--tail-bytes", type=int)
    archive_sub.add_parser("recover")
    archive_repack = archive_sub.add_parser("repack")
    archive_repack_sub = archive_repack.add_subparsers(
        dest="archive_repack_command", required=True
    )
    archive_repack_plan = archive_repack_sub.add_parser("plan")
    archive_repack_plan.add_argument(
        "--minimum-compressed-mib", type=int, default=8
    )
    archive_repack_apply = archive_repack_sub.add_parser("apply")
    archive_repack_apply.add_argument("plan", type=Path)
    archive_repack_apply.add_argument("--yes", action="store_true", required=True)
    archive_repack_sub.add_parser("recover")
    archive_encryption = archive_sub.add_parser("encryption")
    archive_encryption_sub = archive_encryption.add_subparsers(
        dest="archive_encryption_command", required=True
    )
    archive_encryption_enable = archive_encryption_sub.add_parser("enable")
    archive_encryption_enable.add_argument("--recovery-file", required=True, type=Path)
    archive_encryption_enable.add_argument("--yes", action="store_true", required=True)
    archive_encryption_sub.add_parser("status")
    archive_encryption_restore = archive_encryption_sub.add_parser("restore-key")
    archive_encryption_restore.add_argument("--recovery-file", required=True, type=Path)
    archive_encryption_restore.add_argument("--yes", action="store_true", required=True)

    portable = sub.add_parser("portable")
    portable_sub = portable.add_subparsers(dest="portable_command", required=True)
    portable_export = portable_sub.add_parser("export")
    portable_export.add_argument("destination", type=Path)
    portable_export.add_argument("manifests", nargs="+")
    portable_import = portable_sub.add_parser("import")
    portable_import_sub = portable_import.add_subparsers(
        dest="portable_import_command", required=True
    )
    portable_import_plan = portable_import_sub.add_parser("plan")
    portable_import_plan.add_argument("artifact", type=Path)
    portable_import_apply = portable_import_sub.add_parser("apply")
    portable_import_apply.add_argument("plan", type=Path)
    portable_import_apply.add_argument("--yes", action="store_true", required=True)
    portable_import_recover = portable_import_sub.add_parser("recover")
    portable_import_recover.add_argument("--yes", action="store_true", required=True)

    clean = sub.add_parser("clean")
    clean_sub = clean.add_subparsers(dest="clean_command", required=True)
    clean_plan = clean_sub.add_parser("plan")
    clean_plan.add_argument("--profile", default="practical", choices=("practical",))
    clean_plan.add_argument("--policy", type=Path)
    clean_apply = clean_sub.add_parser("apply")
    clean_apply.add_argument("plan", type=Path)
    clean_apply.add_argument("--yes", action="store_true", required=True)
    clean_undo = clean_sub.add_parser("undo")
    clean_undo.add_argument("journal", type=Path)
    clean_expire = clean_sub.add_parser("expire")
    clean_expire_sub = clean_expire.add_subparsers(
        dest="clean_expire_command", required=True
    )
    clean_expire_plan = clean_expire_sub.add_parser("plan")
    clean_expire_plan.add_argument(
        "--retention-days", type=int, default=DEFAULT_CLEAN_QUARANTINE_DAYS
    )
    clean_expire_apply = clean_expire_sub.add_parser("apply")
    clean_expire_apply.add_argument("plan", type=Path)
    clean_expire_apply.add_argument("--yes", action="store_true", required=True)

    observer = sub.add_parser("observer", help="manage claude-mem observer transcripts")
    observer_sub = observer.add_subparsers(dest="observer_command", required=True)
    observer_plan = observer_sub.add_parser("plan")
    observer_plan.add_argument(
        "--grace-hours", type=float, default=DEFAULT_GRACE_SECONDS / 3600
    )
    observer_apply = observer_sub.add_parser("apply")
    observer_apply.add_argument("plan", type=Path)
    observer_apply.add_argument("--yes", action="store_true", required=True)
    observer_expire = observer_sub.add_parser("expire")
    observer_expire_sub = observer_expire.add_subparsers(
        dest="expire_command", required=True
    )
    observer_expire_plan = observer_expire_sub.add_parser("plan")
    observer_expire_plan.add_argument(
        "--ttl-days", type=int, default=DEFAULT_ARCHIVE_TTL_DAYS
    )
    observer_expire_plan.add_argument(
        "--cap-gib",
        type=float,
        default=DEFAULT_ARCHIVE_CAP_BYTES / 1024**3,
    )
    observer_expire_apply = observer_expire_sub.add_parser("apply")
    observer_expire_apply.add_argument("plan", type=Path)
    observer_expire_apply.add_argument("--yes", action="store_true", required=True)

    maintain = sub.add_parser(
        "maintain", help="scheduler-friendly observer plan/apply/expiry cycle"
    )
    maintain.add_argument(
        "--yes", action="store_true", help="apply the plans created in this run"
    )
    maintain.add_argument(
        "--grace-hours", type=float, default=DEFAULT_GRACE_SECONDS / 3600
    )
    maintain.add_argument(
        "--archive-ttl-days", type=int, default=DEFAULT_ARCHIVE_TTL_DAYS
    )
    maintain.add_argument(
        "--archive-cap-gib",
        type=float,
        default=DEFAULT_ARCHIVE_CAP_BYTES / 1024**3,
    )
    scheduled_maintain = sub.add_parser(
        "scheduled-maintain",
        help="apply maintenance and publish one sanitized local event",
    )
    scheduled_maintain.add_argument("--notify", action="store_true")
    return parser


def _runtime(args: argparse.Namespace, paths: AppPaths) -> ClaudeMemPaths:
    return ClaudeMemPaths.discover(
        paths,
        claude_config=args.claude_config_dir,
        data=args.claude_mem_data_dir,
    )


def _seconds_from_hours(value: float) -> int:
    if value < 0:
        raise ValueError("grace hours must be non-negative")
    return int(value * 3600)


def _bytes_from_gib(value: float) -> int:
    if value < 0:
        raise ValueError("archive cap must be non-negative")
    return int(value * 1024**3)


def _pressure_bytes_from_gib(value: str, label: str) -> int:
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"disk pressure {label} must be a GiB number") from exc
    if not amount.is_finite():
        raise ValueError(f"disk pressure {label} must be a finite GiB number")
    byte_count = amount * (1024**3)
    if amount < 0 or byte_count != byte_count.to_integral():
        raise ValueError(
            f"disk pressure {label} must resolve to a non-negative whole byte count"
        )
    return int(byte_count)


def _maintenance_count(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"maintenance {label} count is invalid")
    return value


def _maintenance_cycle(
    paths: AppPaths,
    runtime: ClaudeMemPaths,
    *,
    grace_seconds: int,
    ttl_days: int,
    cap_bytes: int,
    apply: bool,
) -> tuple[dict[str, Any], dict[str, int] | None]:
    gc_path, gc_plan = create_observer_gc_plan(
        paths,
        runtime,
        grace_seconds=grace_seconds,
    )
    if not apply:
        expiry_path, expiry_plan = create_observer_expiry_plan(
            paths,
            ttl_days=ttl_days,
            cap_bytes=cap_bytes,
        )
        return (
            {
                "applied": False,
                "observer_plan": str(gc_path),
                "observer_candidates": len(gc_plan["candidates"]),
                "observer_logical_bytes": gc_plan["logical_bytes"],
                "expiry_plan": str(expiry_path),
                "expiry_manifests": len(expiry_plan["manifests"]),
            },
            None,
        )

    gc_result = apply_observer_gc_plan(paths, runtime, gc_path)
    # Plan expiry after archiving. This ordering bounds a runaway cycle with
    # the configured observer-only cap.
    expiry_path, _ = create_observer_expiry_plan(
        paths,
        ttl_days=ttl_days,
        cap_bytes=cap_bytes,
    )
    expiry_result = apply_observer_expiry_plan(paths, expiry_path)
    protected = gc_plan.get("protected")
    gc_skipped = gc_result.get("skipped")
    expiry_skipped = expiry_result.get("skipped")
    if (
        not isinstance(protected, dict)
        or not isinstance(gc_skipped, list)
        or not isinstance(expiry_skipped, list)
    ):
        raise ValueError("maintenance protected outcomes are invalid")
    protected_count = sum(
        _maintenance_count(value, "protected") for value in protected.values()
    ) + len(gc_skipped) + len(expiry_skipped)
    counts = {
        "archived": _maintenance_count(gc_result.get("archived"), "archived"),
        "protected": protected_count,
        "manifests_removed": _maintenance_count(
            expiry_result.get("manifests_removed"), "manifests removed"
        ),
        "objects_removed": _maintenance_count(
            expiry_result.get("objects_removed"), "objects removed"
        ),
    }
    return (
        {
            "applied": True,
            "observer_plan": str(gc_path),
            "observer": gc_result,
            "expiry_plan": str(expiry_path),
            "expiry": expiry_result,
        },
        counts,
    )


def _scheduled_maintenance(
    args: argparse.Namespace, paths: AppPaths
) -> dict[str, Any]:
    counts = {
        "archived": 0,
        "protected": 0,
        "manifests_removed": 0,
        "objects_removed": 0,
    }
    try:
        _, completed_counts = _maintenance_cycle(
            paths,
            _runtime(args, paths),
            grace_seconds=DEFAULT_GRACE_SECONDS,
            ttl_days=DEFAULT_ARCHIVE_TTL_DAYS,
            cap_bytes=DEFAULT_ARCHIVE_CAP_BYTES,
            apply=True,
        )
        if completed_counts is None:
            raise RuntimeError("scheduled maintenance did not apply")
        counts = completed_counts
        verification = verify_all(paths, continue_on_error=True)
        failed_manifests = _maintenance_count(
            verification.get("failed_manifests"), "failed manifests"
        )
        if failed_manifests:
            reasons = ["corruption"]
        else:
            reasons = ["success"]
        if counts["protected"]:
            reasons.append("protected")
        if shutil.disk_usage(paths.home).free < DEFAULT_LOW_SPACE_BYTES:
            reasons.append("low_space")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        reasons = ["failure"]
    return record_maintenance_event(
        paths,
        counts=counts,
        reason_codes=reasons,
        notify=args.notify,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    paths = AppPaths.discover(args.home)
    try:
        if args.command == "audit":
            _emit(_audit(paths), args.json)
        elif args.command == "doctor":
            result = _doctor(paths)
            _emit(result, args.json)
            return 0 if result["ok"] else 1
        elif args.command == "schedule":
            if args.schedule_command == "install":
                result = schedule_install(
                    paths,
                    interval_seconds=args.interval_seconds,
                    executable=args.executable,
                    notify=args.notify,
                )
            elif args.schedule_command == "status":
                result = schedule_status(paths)
            else:
                result = schedule_uninstall(paths)
            _emit(result, args.json)
        elif args.command == "plan":
            _emit(_plan_show(args.plan), args.json)
        elif args.command == "pressure":
            try:
                result = plan_disk_pressure(
                    paths,
                    trigger_free_bytes=_pressure_bytes_from_gib(
                        args.trigger_free_gib, "trigger"
                    ),
                    target_free_bytes=_pressure_bytes_from_gib(
                        args.target_free_gib, "target"
                    ),
                    policy_path=args.policy,
                )
            except PressurePlanError as exc:
                _emit(exc.result, args.json)
                return 1
            _emit(result, args.json)
        elif args.command == "history":
            _emit(history_summary(paths, top=args.top), args.json)
        elif args.command == "archive":
            if args.archive_command == "plan":
                plan_path, plan = create_archive_plan(paths)
                _emit(
                    {
                        "plan": str(plan_path),
                        "sessions": len(plan["sessions"]),
                        "logical_bytes": plan["logical_bytes"],
                        "skipped": plan["skipped"],
                    },
                    args.json,
                )
            elif args.archive_command == "apply":
                _emit(apply_archive_plan(paths, args.plan), args.json)
            elif args.archive_command == "list":
                archives = list_archives(
                    paths,
                    provider=args.provider,
                    session_id=args.session_id,
                    archived_on=args.date,
                    version=args.version,
                    sort=args.sort,
                    reverse=args.reverse,
                )
                _emit(
                    {
                        "count": len(archives),
                        "manifests": [entry["manifest"] for entry in archives],
                        "archives": archives,
                    },
                    args.json,
                )
            elif args.archive_command == "stats":
                _emit(archive_stats(paths), args.json)
            elif args.archive_command == "schema":
                if args.archive_schema_command == "check":
                    result = check_archive_schema(paths)
                    _emit(result, args.json)
                    return (
                        0
                        if result["compatible"] and result["latest_indexes_current"]
                        else 1
                    )
                _emit(rebuild_latest_indexes(paths), args.json)
            elif args.archive_command == "train-dictionary":
                _emit(
                    train_dictionary(
                        paths,
                        args.provider,
                        sample_limit=args.samples,
                        max_dict_bytes=args.max_dict_kib * 1024,
                        minimum_benefit_bytes=args.minimum_benefit_kib * 1024,
                    ),
                    args.json,
                )
            elif args.archive_command == "benchmark":
                _emit(
                    benchmark_dictionary(
                        paths,
                        args.provider,
                        sample_limit=args.samples,
                        max_dict_bytes=args.max_dict_kib * 1024,
                        minimum_benefit_bytes=args.minimum_benefit_kib * 1024,
                    ),
                    args.json,
                )
            elif args.archive_command == "verify":
                if args.continue_on_error:
                    result = verify_all(paths, continue_on_error=True)
                    _emit(result, args.json)
                    return 1 if result["failed_manifests"] else 0
                _emit(verify_all(paths), args.json)
            elif args.archive_command == "expire":
                if args.archive_expire_command == "plan":
                    plan_path, plan = create_archive_expiry_plan(
                        paths,
                        args.provider,
                        ttl_days=args.ttl_days,
                        cap_bytes=_bytes_from_gib(args.cap_gib),
                    )
                    _emit(
                        {
                            "plan": str(plan_path),
                            "provider": plan["provider"],
                            "manifests": len(plan["manifests"]),
                            "cas_candidates": len(plan["cas_candidates"]),
                            "archive_bytes_before": plan["archive_bytes_before"],
                            "archive_bytes_after": plan["archive_bytes_after"],
                        },
                        args.json,
                    )
                elif args.archive_expire_command == "apply":
                    _emit(apply_archive_expiry_plan(paths, args.plan), args.json)
            elif args.archive_command == "restore":
                batch_values = (args.provider, args.from_date, args.to_date)
                if any(value is not None for value in batch_values):
                    if (
                        any(value is None for value in batch_values)
                        or args.manifest is not None
                        or args.member is not None
                        or args.destination is None
                    ):
                        raise ValueError(
                            "batch restore requires --provider, --from-date, "
                            "--to-date, and --destination without a manifest or member"
                        )
                    result = restore_manifest_set(
                        paths,
                        args.provider,
                        args.from_date,
                        args.to_date,
                        args.destination,
                    )
                else:
                    if args.manifest is None:
                        raise ValueError("manifest restore requires an exact reference")
                    result = restore_manifest(
                        paths,
                        args.manifest,
                        args.destination,
                        member=args.member,
                    )
                _emit(result, args.json)
            elif args.archive_command == "extract":
                range_selected = args.offset is not None or args.length is not None
                tail_selected = args.tail_bytes is not None
                if range_selected == tail_selected or (
                    range_selected and (args.offset is None or args.length is None)
                ):
                    raise ValueError(
                        "archive extract requires --offset with --length or "
                        "--tail-bytes, but not both"
                    )
                if tail_selected:
                    result = extract_member_tail(
                        paths,
                        args.manifest,
                        args.member,
                        args.tail_bytes,
                        args.output,
                    )
                else:
                    result = extract_member_range(
                        paths,
                        args.manifest,
                        args.member,
                        args.offset,
                        args.length,
                        args.output,
                    )
                _emit(result, args.json)
            elif args.archive_command == "recover":
                _emit(recover_quarantine(paths), args.json)
            elif args.archive_command == "repack":
                if args.archive_repack_command == "plan":
                    plan_path, plan = create_repack_plan(
                        paths,
                        minimum_compressed_bytes=(
                            args.minimum_compressed_mib * 1024**2
                        ),
                    )
                    _emit({"plan": str(plan_path), **plan}, args.json)
                elif args.archive_repack_command == "apply":
                    _emit(apply_repack_plan(paths, args.plan), args.json)
                else:
                    _emit(recover_repack(paths), args.json)
            elif args.archive_command == "encryption":
                if args.archive_encryption_command == "enable":
                    result = enable_archive_encryption(paths, args.recovery_file)
                elif args.archive_encryption_command == "status":
                    result = encryption_status(paths)
                else:
                    result = restore_archive_key(paths, args.recovery_file)
                _emit(result, args.json)
        elif args.command == "portable":
            if args.portable_command == "export":
                _emit(
                    export_portable_archive(paths, args.manifests, args.destination),
                    args.json,
                )
            elif args.portable_import_command == "plan":
                plan_path, plan = create_portable_import_plan(paths, args.artifact)
                _emit(
                    {
                        "plan": str(plan_path),
                        "bundle_id": plan["bundle_id"],
                        "manifests": plan["manifests"],
                        "objects": plan["objects"],
                        "artifact_sha256": plan["artifact"]["sha256"],
                    },
                    args.json,
                )
            elif args.portable_import_command == "apply":
                _emit(apply_portable_import_plan(paths, args.plan), args.json)
            else:
                _emit(recover_portable_imports(paths), args.json)
        elif args.command == "clean":
            if args.clean_command == "plan":
                plan_path, plan = create_clean_plan(
                    paths, args.profile, policy_path=args.policy
                )
                _emit(
                    {
                        "plan": str(plan_path),
                        "candidates": len(plan["candidates"]),
                        "allocated_bytes": plan["allocated_bytes"],
                        "skipped_open": plan["skipped_open"],
                    },
                    args.json,
                )
            elif args.clean_command == "apply":
                _emit(apply_clean_plan(paths, args.plan), args.json)
            elif args.clean_command == "undo":
                _emit(undo_clean(paths, args.journal), args.json)
            elif args.clean_command == "expire":
                if args.clean_expire_command == "plan":
                    plan_path, plan = create_clean_expiry_plan(
                        paths, retention_days=args.retention_days
                    )
                    _emit(
                        {
                            "plan": str(plan_path),
                            "journals": len(plan["journals"]),
                            "retention_days": plan["retention_days"],
                        },
                        args.json,
                    )
                elif args.clean_expire_command == "apply":
                    _emit(apply_clean_expiry_plan(paths, args.plan), args.json)
        elif args.command == "observer":
            runtime = _runtime(args, paths)
            if args.observer_command == "plan":
                plan_path, plan = create_observer_gc_plan(
                    paths,
                    runtime,
                    grace_seconds=_seconds_from_hours(args.grace_hours),
                )
                _emit(
                    {
                        "plan": str(plan_path),
                        "candidates": len(plan["candidates"]),
                        "logical_bytes": plan["logical_bytes"],
                        "protected": plan["protected"],
                        "reference_counts": plan["reference_counts"],
                    },
                    args.json,
                )
            elif args.observer_command == "apply":
                _emit(apply_observer_gc_plan(paths, runtime, args.plan), args.json)
            elif args.observer_command == "expire":
                if args.expire_command == "plan":
                    plan_path, plan = create_observer_expiry_plan(
                        paths,
                        ttl_days=args.ttl_days,
                        cap_bytes=_bytes_from_gib(args.cap_gib),
                    )
                    _emit(
                        {
                            "plan": str(plan_path),
                            "manifests": len(plan["manifests"]),
                            "cas_candidates": len(plan["cas_candidates"]),
                            "observer_bytes_before": plan["observer_bytes_before"],
                            "observer_bytes_after": plan["observer_bytes_after"],
                        },
                        args.json,
                    )
                elif args.expire_command == "apply":
                    _emit(apply_observer_expiry_plan(paths, args.plan), args.json)
        elif args.command == "maintain":
            result, _ = _maintenance_cycle(
                paths,
                _runtime(args, paths),
                grace_seconds=_seconds_from_hours(args.grace_hours),
                ttl_days=args.archive_ttl_days,
                cap_bytes=_bytes_from_gib(args.archive_cap_gib),
                apply=args.yes,
            )
            _emit(result, args.json)
        elif args.command == "scheduled-maintain":
            result = _scheduled_maintenance(args, paths)
            _emit(result, args.json)
            return 1 if result["event"]["status"] == "failure" else 0
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"sesh-compresh: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
