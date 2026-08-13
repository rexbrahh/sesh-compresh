from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .archive import create_archive_plan
from .clean import create_clean_plan
from .common import (
    AppPaths,
    identity_matches,
    load_json,
    new_run_id,
    regular_directory_stat,
    regular_file_stat,
    utc_now,
)


class PressurePlanError(RuntimeError):
    """Pressure planning failed, possibly after publishing one child plan."""

    def __init__(self, result: dict[str, Any]) -> None:
        super().__init__(result["error"])
        self.result = result


def _validate_threshold(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"disk pressure {label} must be a non-negative byte count")
    return value


def _published_child(
    paths: AppPaths, prefix: str, kind: str, run_id: str
) -> tuple[Path, dict[str, Any]] | None:
    plan_path = paths.state / "plans" / f"{prefix}-{run_id}.json"
    try:
        identity = regular_file_stat(plan_path)
        plan = load_json(plan_path)
    except (OSError, ValueError):
        return None
    if (
        not identity_matches(plan_path, identity)
        or plan.get("kind") != kind
        or plan.get("run_id") != run_id
    ):
        return None
    return plan_path, plan


def plan_disk_pressure(
    paths: AppPaths,
    *,
    trigger_free_bytes: int,
    target_free_bytes: int,
    policy_path: Path | None = None,
) -> dict[str, Any]:
    """Create independent plans for the home filesystem when space is low."""

    trigger = _validate_threshold(trigger_free_bytes, "trigger")
    target = _validate_threshold(target_free_bytes, "target")
    if target < trigger:
        raise ValueError("disk pressure target must be at least the trigger")

    home_before = regular_directory_stat(paths.home)
    usage = shutil.disk_usage(paths.home)
    home_after = regular_directory_stat(paths.home)
    if (home_before["device"], home_before["inode"]) != (
        home_after["device"],
        home_after["inode"],
    ):
        raise RuntimeError("disk pressure filesystem changed while measuring")
    source_device = home_after["device"]
    result: dict[str, Any] = {
        "triggered": usage.free < trigger,
        "partial": False,
        "filesystem_device": source_device,
        "disk_total_bytes": usage.total,
        "disk_used_bytes": usage.used,
        "disk_free_bytes": usage.free,
        "trigger_free_bytes": trigger,
        "target_free_bytes": target,
        "target_deficit_bytes": max(0, target - usage.free),
    }
    if not result["triggered"]:
        return result

    clean_run_id = new_run_id(utc_now())
    try:
        clean_path, clean_plan = create_clean_plan(
            paths,
            policy_path=policy_path,
            source_device=source_device,
            run_id=clean_run_id,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        published = _published_child(
            paths, "clean", "clean-plan", clean_run_id
        )
        partial = published is not None
        published_result = (
            {
                "clean_plan": str(published[0]),
                "clean_candidates": len(published[1]["candidates"]),
                "clean_quarantined_bytes_candidate": published[1][
                    "allocated_bytes"
                ],
            }
            if published is not None
            else {}
        )
        raise PressurePlanError(
            {
                **result,
                **published_result,
                "partial": partial,
                "failed_stage": "clean",
                "error_type": exc.__class__.__name__,
                "error": str(exc),
            }
        ) from exc
    result.update(
        {
            "clean_plan": str(clean_path),
            "clean_candidates": len(clean_plan["candidates"]),
            "clean_quarantined_bytes_candidate": clean_plan["allocated_bytes"],
        }
    )
    archive_run_id = new_run_id(utc_now())
    try:
        archive_path, archive_plan = create_archive_plan(
            paths, source_device=source_device, run_id=archive_run_id
        )
    except (OSError, ValueError, RuntimeError) as exc:
        published = _published_child(
            paths, "archive", "archive-plan", archive_run_id
        )
        published_result = (
            {
                "archive_plan": str(published[0]),
                "archive_sessions": len(published[1]["sessions"]),
                "archive_logical_bytes": published[1]["logical_bytes"],
            }
            if published is not None
            else {}
        )
        raise PressurePlanError(
            {
                **result,
                **published_result,
                "partial": True,
                "failed_stage": "archive",
                "error_type": exc.__class__.__name__,
                "error": str(exc),
            }
        ) from exc
    return {
        **result,
        "archive_plan": str(archive_path),
        "archive_sessions": len(archive_plan["sessions"]),
        "archive_logical_bytes": archive_plan["logical_bytes"],
    }
