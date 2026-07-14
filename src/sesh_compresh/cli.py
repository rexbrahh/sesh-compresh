from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .archive import (
    apply_archive_plan,
    create_archive_plan,
    iter_manifests,
    recover_quarantine,
    restore_manifest,
    verify_all,
)
from .clean import apply_clean_plan, create_clean_plan
from .common import AppPaths, allocated_bytes
from .observer import (
    DEFAULT_ARCHIVE_CAP_BYTES,
    DEFAULT_ARCHIVE_TTL_DAYS,
    DEFAULT_GRACE_SECONDS,
    ClaudeMemPaths,
    apply_observer_expiry_plan,
    apply_observer_gc_plan,
    create_observer_expiry_plan,
    create_observer_gc_plan,
)


def _bytes(value: int) -> str:
    return f"{value / (1024**3):.2f} GiB"


def _emit(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    for key, value in payload.items():
        if key.endswith("bytes") and isinstance(value, int):
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sesh-compresh")
    parser.add_argument("--home", type=Path, help="override home directory (primarily for tests)")
    parser.add_argument("--claude-config-dir", type=Path, help="override CLAUDE_CONFIG_DIR")
    parser.add_argument("--claude-mem-data-dir", type=Path, help="override CLAUDE_MEM_DATA_DIR")
    parser.add_argument("--json", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("audit")

    archive = sub.add_parser("archive")
    archive_sub = archive.add_subparsers(dest="archive_command", required=True)
    archive_sub.add_parser("plan")
    archive_apply = archive_sub.add_parser("apply")
    archive_apply.add_argument("plan", type=Path)
    archive_apply.add_argument("--yes", action="store_true", required=True)
    archive_sub.add_parser("list")
    archive_sub.add_parser("verify")
    archive_restore = archive_sub.add_parser("restore")
    archive_restore.add_argument("manifest")
    archive_restore.add_argument("--destination", type=Path)
    archive_sub.add_parser("recover")

    clean = sub.add_parser("clean")
    clean_sub = clean.add_subparsers(dest="clean_command", required=True)
    clean_plan = clean_sub.add_parser("plan")
    clean_plan.add_argument("--profile", default="practical", choices=("practical",))
    clean_apply = clean_sub.add_parser("apply")
    clean_apply.add_argument("plan", type=Path)
    clean_apply.add_argument("--yes", action="store_true", required=True)

    observer = sub.add_parser("observer", help="manage claude-mem observer transcripts")
    observer_sub = observer.add_subparsers(dest="observer_command", required=True)
    observer_plan = observer_sub.add_parser("plan")
    observer_plan.add_argument("--grace-hours", type=float, default=DEFAULT_GRACE_SECONDS / 3600)
    observer_apply = observer_sub.add_parser("apply")
    observer_apply.add_argument("plan", type=Path)
    observer_apply.add_argument("--yes", action="store_true", required=True)
    observer_expire = observer_sub.add_parser("expire")
    observer_expire_sub = observer_expire.add_subparsers(dest="expire_command", required=True)
    observer_expire_plan = observer_expire_sub.add_parser("plan")
    observer_expire_plan.add_argument("--ttl-days", type=int, default=DEFAULT_ARCHIVE_TTL_DAYS)
    observer_expire_plan.add_argument(
        "--cap-gib",
        type=float,
        default=DEFAULT_ARCHIVE_CAP_BYTES / 1024**3,
    )
    observer_expire_apply = observer_expire_sub.add_parser("apply")
    observer_expire_apply.add_argument("plan", type=Path)
    observer_expire_apply.add_argument("--yes", action="store_true", required=True)

    maintain = sub.add_parser("maintain", help="scheduler-friendly observer plan/apply/expiry cycle")
    maintain.add_argument("--yes", action="store_true", help="apply the plans created in this run")
    maintain.add_argument("--grace-hours", type=float, default=DEFAULT_GRACE_SECONDS / 3600)
    maintain.add_argument("--archive-ttl-days", type=int, default=DEFAULT_ARCHIVE_TTL_DAYS)
    maintain.add_argument(
        "--archive-cap-gib",
        type=float,
        default=DEFAULT_ARCHIVE_CAP_BYTES / 1024**3,
    )
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    paths = AppPaths.discover(args.home)
    try:
        if args.command == "audit":
            _emit(_audit(paths), args.json)
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
                manifests = [str(path) for path in iter_manifests(paths)]
                _emit({"count": len(manifests), "manifests": manifests}, args.json)
            elif args.archive_command == "verify":
                _emit(verify_all(paths), args.json)
            elif args.archive_command == "restore":
                _emit(restore_manifest(paths, args.manifest, args.destination), args.json)
            elif args.archive_command == "recover":
                _emit(recover_quarantine(paths), args.json)
        elif args.command == "clean":
            if args.clean_command == "plan":
                plan_path, plan = create_clean_plan(paths, args.profile)
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
            runtime = _runtime(args, paths)
            gc_path, gc_plan = create_observer_gc_plan(
                paths,
                runtime,
                grace_seconds=_seconds_from_hours(args.grace_hours),
            )
            if not args.yes:
                expiry_path, expiry_plan = create_observer_expiry_plan(
                    paths,
                    ttl_days=args.archive_ttl_days,
                    cap_bytes=_bytes_from_gib(args.archive_cap_gib),
                )
                _emit(
                    {
                        "applied": False,
                        "observer_plan": str(gc_path),
                        "observer_candidates": len(gc_plan["candidates"]),
                        "observer_logical_bytes": gc_plan["logical_bytes"],
                        "expiry_plan": str(expiry_path),
                        "expiry_manifests": len(expiry_plan["manifests"]),
                    },
                    args.json,
                )
            else:
                gc_result = apply_observer_gc_plan(paths, runtime, gc_path)
                # Expiry is planned after archiving so a single runaway cycle
                # is bounded by the configured observer-only cap.
                expiry_path, _ = create_observer_expiry_plan(
                    paths,
                    ttl_days=args.archive_ttl_days,
                    cap_bytes=_bytes_from_gib(args.archive_cap_gib),
                )
                expiry_result = apply_observer_expiry_plan(paths, expiry_path)
                _emit(
                    {
                        "applied": True,
                        "observer_plan": str(gc_path),
                        "observer": gc_result,
                        "expiry_plan": str(expiry_path),
                        "expiry": expiry_result,
                    },
                    args.json,
                )
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"sesh-compresh: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
