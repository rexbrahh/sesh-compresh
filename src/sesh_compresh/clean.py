from __future__ import annotations

import os
import re
import shutil
import stat
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterator

from .common import (
    SCHEMA_VERSION,
    AppPaths,
    allocated_bytes,
    any_open,
    atomic_json,
    iso_utc,
    load_json,
    open_file_paths,
    parse_timestamp,
    utc_now,
)


KEEP_MIXED_METADATA = {"README", "README.md", "trim.txt"}
GO_CACHE_NAME = re.compile(r"^(?:wr|wsms).*?(?:go-cache|gocache|go-mod|gomodcache|gomod)$")


def _walk_markers(root: Path, names: set[str], max_depth: int = 4) -> Iterator[Path]:
    if not root.is_dir():
        return
    base_depth = len(root.parts)
    for current, dirs, files in os.walk(root, followlinks=False):
        path = Path(current)
        depth = len(path.parts) - base_depth
        if depth >= max_depth:
            dirs[:] = []
        dirs[:] = [name for name in dirs if name not in {"claude-501", "chronicle", "wr-pointcloud-qa"}]
        for name in names.intersection(files):
            yield path / name


def _has_git(candidate: Path) -> bool:
    if (candidate / ".git").exists():
        return True
    for current, dirs, files in os.walk(candidate, followlinks=False):
        if ".git" in dirs or ".git" in files:
            return True
        if len(Path(current).parts) - len(candidate.parts) >= 3:
            dirs[:] = []
    return False


def _fingerprint(path: Path) -> dict[str, Any]:
    info = path.stat(follow_symlinks=False)
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mtime_ns": info.st_mtime_ns,
        "type": "file" if stat.S_ISREG(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "other",
    }


def _candidate(path: Path, family: str, marker: str, action: str = "delete-tree") -> dict[str, Any] | None:
    try:
        if path.is_symlink() or not path.exists():
            return None
        identity = _fingerprint(path)
        if identity["type"] not in {"file", "directory"}:
            return None
        if identity["type"] == "directory" and action == "delete-tree" and _has_git(path):
            return None
        return {
            "path": str(path),
            "family": family,
            "marker": marker,
            "action": action,
            "allocated_bytes": allocated_bytes(path),
            **identity,
        }
    except (FileNotFoundError, PermissionError, OSError):
        return None


def discover_practical(paths: AppPaths) -> list[dict[str, Any]]:
    tmp = Path("/private/tmp")
    user_tmp = Path(os.environ.get("TMPDIR", "/var/folders/np/yz42gl6j5111dqz2b2s41s080000gn/T"))
    results: dict[str, dict[str, Any]] = {}

    def add(value: dict[str, Any] | None) -> None:
        if value is not None:
            results[value["path"]] = value

    for marker in _walk_markers(tmp, {"workspace-state.json"}):
        add(_candidate(marker.parent, "swiftpm", "workspace-state.json+build.db"))

    for marker in _walk_markers(tmp, {".rustc_info.json"}, max_depth=3):
        add(_candidate(marker.parent, "rust-target", ".rustc_info.json+CACHEDIR.TAG"))

    for marker in _walk_markers(tmp, {"CMakeCache.txt"}):
        root = marker.parent
        if str(root).startswith("/private/tmp/fieldforge-vcpkg-buildtrees/"):
            root = tmp / "fieldforge-vcpkg-buildtrees"
        add(_candidate(root, "cmake-build", "CMakeCache.txt"))

    if tmp.is_dir():
        for child in tmp.iterdir():
            if not child.is_dir() or child.is_symlink() or not GO_CACHE_NAME.match(child.name):
                continue
            action = "prune-mixed-cache" if child.name.startswith("wsms") else "delete-tree"
            add(_candidate(child, "go-cache", "allowlisted cache name", action))

    generated_dirs = {
        "wr-implicit-preview": "generated-preview",
        "aerogalactica-native-pointcloud-sdf": "generated-pointcloud",
        "wr-go-cache": "go-cache",
        "wr-go-mod-cache": "go-cache",
        "swift-generated-sources": "generated-sources",
        "node-compile-cache": "node-cache",
        "tsx-501": "node-cache",
    }
    if user_tmp.is_dir():
        for name, family in generated_dirs.items():
            add(_candidate(user_tmp / name, family, "exact practical-profile path"))
        for child in user_tmp.glob("go-build*"):
            add(_candidate(child, "go-build", "go-build prefix"))
        for child in user_tmp.glob("preamble-*.pch"):
            add(_candidate(child, "clang-preamble", "preamble-*.pch"))

    for path, family in (
        (paths.home / ".cache/.bun", "bun-cache"),
        (paths.home / ".cache/bun", "bun-cache"),
        (paths.home / ".cache/nix", "nix-client-cache"),
    ):
        add(_candidate(path, family, "exact practical-profile path"))

    darwin_cache = Path(os.environ.get("DARWIN_USER_CACHE_DIR", "/var/folders/np/yz42gl6j5111dqz2b2s41s080000gn/C"))
    for path, family in (
        (darwin_cache / "clang", "clang-cache"),
        (darwin_cache / "com.apple.dt.InstrumentsCLI", "instruments-cache"),
    ):
        add(_candidate(path, family, "exact practical-profile path"))

    return sorted(results.values(), key=lambda item: (-item["allocated_bytes"], item["path"]))


def create_clean_plan(paths: AppPaths, profile: str = "practical") -> tuple[Path, dict[str, Any]]:
    if profile != "practical":
        raise ValueError(f"unsupported cleanup profile: {profile}")
    paths.ensure_private()
    now = utc_now()
    opened = open_file_paths()
    candidates = []
    skipped_open = []
    for item in discover_practical(paths):
        if any_open([Path(item["path"])], opened):
            skipped_open.append(item["path"])
        else:
            candidates.append(item)
    run_id = now.strftime("%Y%m%dT%H%M%SZ")
    plan = {
        "schema_version": SCHEMA_VERSION,
        "kind": "clean-plan",
        "profile": profile,
        "run_id": run_id,
        "created_at": iso_utc(now),
        "expires_at": iso_utc(now + timedelta(hours=2)),
        "allocated_bytes": sum(item["allocated_bytes"] for item in candidates),
        "candidates": candidates,
        "skipped_open": skipped_open,
    }
    plan_path = paths.state / "plans" / f"clean-{run_id}.json"
    atomic_json(plan_path, plan)
    return plan_path, plan


def _identity_matches(path: Path, expected: dict[str, Any]) -> bool:
    try:
        current = _fingerprint(path)
    except (FileNotFoundError, OSError):
        return False
    return all(current[key] == expected[key] for key in ("device", "inode", "mtime_ns", "type"))


def _make_writable(path: Path) -> None:
    try:
        mode = path.stat(follow_symlinks=False).st_mode
        if not path.is_symlink():
            path.chmod(mode | stat.S_IWUSR, follow_symlinks=False)
    except (FileNotFoundError, PermissionError):
        pass
    if path.is_dir() and not path.is_symlink():
        for current, dirs, files in os.walk(path, followlinks=False):
            for name in dirs + files:
                candidate = Path(current, name)
                try:
                    mode = candidate.stat(follow_symlinks=False).st_mode
                    if not candidate.is_symlink():
                        candidate.chmod(mode | stat.S_IWUSR, follow_symlinks=False)
                except (FileNotFoundError, PermissionError):
                    continue


def _delete_tree(path: Path) -> None:
    if path.is_file():
        path.unlink()
        return
    _make_writable(path)
    shutil.rmtree(path)


def _prune_mixed(path: Path) -> None:
    for child in path.iterdir():
        if child.name in KEEP_MIXED_METADATA:
            continue
        if child.is_symlink() or child.is_file():
            child.unlink()
        else:
            _delete_tree(child)


def apply_clean_plan(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    plan = load_json(plan_path)
    if plan.get("schema_version") != SCHEMA_VERSION or plan.get("kind") != "clean-plan":
        raise ValueError("unsupported cleanup plan")
    if utc_now() > parse_timestamp(plan["expires_at"]):
        raise RuntimeError("cleanup plan expired")
    opened = open_file_paths()
    reclaimed = 0
    removed = []
    skipped = []
    for item_number, item in enumerate(plan["candidates"], start=1):
        path = Path(item["path"])
        if not _identity_matches(path, item):
            skipped.append({"path": str(path), "reason": "identity drift"})
            continue
        if any_open([path], opened):
            skipped.append({"path": str(path), "reason": "open"})
            continue
        if item["type"] == "directory" and item["action"] == "delete-tree" and _has_git(path):
            skipped.append({"path": str(path), "reason": "Git metadata"})
            continue
        try:
            before = allocated_bytes(path)
            if item["action"] == "prune-mixed-cache":
                _prune_mixed(path)
            else:
                _delete_tree(path)
            reclaimed += before
            removed.append(str(path))
            if item_number % 25 == 0:
                print(
                    f"cleanup progress: {item_number}/{len(plan['candidates'])} candidates processed",
                    file=sys.stderr,
                    flush=True,
                )
        except OSError as exc:
            skipped.append({"path": str(path), "reason": f"{exc.__class__.__name__}: {exc}"})
    return {"reclaimed_bytes": reclaimed, "removed": removed, "skipped": skipped}
