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
    parser = argparse.ArgumentParser(prog="storage-safeguard")
    parser.add_argument("--home", type=Path, help="override home directory (primarily for tests)")
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
    return parser


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
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"storage-safeguard: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
