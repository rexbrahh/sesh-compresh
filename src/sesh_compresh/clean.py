from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator, Mapping

from .common import (
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    AppPaths,
    any_open,
    app_lock,
    atomic_json,
    ensure_private_subdirectory,
    fsync_dir,
    identity_matches,
    iso_utc,
    load_json,
    new_run_id,
    open_file_paths,
    open_file_paths_for,
    parse_timestamp,
    _prune_expired_plans_locked,
    regular_directory_stat,
    regular_file_stat,
    utc_now,
    validate_run_id,
)
from .history import record_history_after_success


KEEP_MIXED_METADATA = {"README", "README.md", "trim.txt"}
GO_CACHE_NAME = re.compile(
    r"^(?:wr|wsms).*?(?:go-cache|gocache|go-mod|gomodcache|gomod)$"
)
_CLEAN_CANDIDATE_TYPES = {
    "path": str,
    "family": str,
    "marker": str,
    "action": str,
    "allocated_bytes": int,
    "tree_fingerprint": str,
    "device": int,
    "inode": int,
    "mtime_ns": int,
    "type": str,
}
_CLEAN_PLAN_TYPES = {
    "schema_version": int,
    "kind": str,
    "profile": str,
    "run_id": str,
    "created_at": str,
    "expires_at": str,
    "allocated_bytes": int,
    "candidates": list,
    "skipped_open": list,
}
_CLEAN_PLAN_KEYS = set(_CLEAN_PLAN_TYPES) | {"policy"}
_CLEAN_POLICY_KEYS = {"schema_version", "kind", "rules"}
_CLEAN_POLICY_RULE_KEYS = {
    "root",
    "name",
    "retention_days",
    "markers",
    "action",
}
_CLEAN_POLICY_REFERENCE_KEYS = {"path", "sha256"}
_CLEAN_POLICY_SCHEMA_VERSION = 1
_LEGACY_CLEAN_PLAN_SCHEMA_VERSION = 2
_MAX_CLEAN_POLICY_BYTES = 64 * 1024
_MAX_CLEAN_POLICY_RULES = 128
_MAX_CLEAN_POLICY_RETENTION_DAYS = 36_500
CLEAN_ACTIONS = {"delete-tree", "prune-mixed-cache"}
DEFAULT_CLEAN_QUARANTINE_DAYS = 7
LOCAL_QUARANTINE_NAME = ".sesh-compresh-clean-quarantine"
_CLEAN_MOVE_KEYS = {
    "candidate",
    "source",
    "quarantine",
    "allocated_bytes",
    "tree_fingerprint",
    "device",
    "inode",
    "mtime_ns",
    "type",
    "candidate_device",
    "candidate_inode",
    "candidate_mode",
    "candidate_mtime_ns",
}
_CLEAN_JOURNAL_KEYS = {
    "schema_version",
    "kind",
    "run_id",
    "created_at",
    "moves",
}
_CLEAN_EXPIRY_PLAN_KEYS = {
    "schema_version",
    "kind",
    "run_id",
    "created_at",
    "expires_at",
    "retention_days",
    "journals",
}
REQUIRED_MARKERS = {
    "swiftpm": ("workspace-state.json", "build.db"),
    "rust-target": (".rustc_info.json", "CACHEDIR.TAG"),
}


class _DifferentFilesystemError(RuntimeError):
    """A cleanup tree crosses the requested source filesystem."""


def _configured_platform_root(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute: {path}")
    return path.resolve()


def _temporary_root(environ: Mapping[str, str]) -> Path:
    value = environ.get("TMPDIR")
    if value:
        return _configured_platform_root(value, "TMPDIR")
    return Path(tempfile.gettempdir()).resolve()


def _darwin_cache_root(environ: Mapping[str, str]) -> Path | None:
    value = environ.get("DARWIN_USER_CACHE_DIR")
    if value:
        return _configured_platform_root(value, "DARWIN_USER_CACHE_DIR")
    if sys.platform != "darwin":
        return None
    try:
        completed = subprocess.run(
            ["getconf", "DARWIN_USER_CACHE_DIR"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    values = completed.stdout.splitlines()
    if completed.returncode != 0 or len(values) != 1 or not values[0]:
        return None
    return _configured_platform_root(values[0], "getconf DARWIN_USER_CACHE_DIR")


def _walk_markers(root: Path, names: set[str], max_depth: int = 4) -> Iterator[Path]:
    if not root.is_dir():
        return
    base_depth = len(root.parts)
    for current, dirs, files in os.walk(root, followlinks=False):
        path = Path(current)
        depth = len(path.parts) - base_depth
        if depth >= max_depth:
            dirs[:] = []
        dirs[:] = [
            name
            for name in dirs
            if name not in {"claude-501", "chronicle", "wr-pointcloud-qa"}
        ]
        for name in names.intersection(files):
            yield path / name


def _has_git(candidate: Path) -> bool:
    for current, dirs, files in os.walk(candidate, followlinks=False):
        if any(name.casefold() == ".git" for name in (*dirs, *files)):
            return True
    return False


def _fingerprint(path: Path) -> dict[str, Any]:
    info = path.stat(follow_symlinks=False)
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mtime_ns": info.st_mtime_ns,
        "type": (
            "file"
            if stat.S_ISREG(info.st_mode)
            else "directory"
            if stat.S_ISDIR(info.st_mode)
            else "symlink"
            if stat.S_ISLNK(info.st_mode)
            else "other"
        ),
    }


def _tree_snapshot(
    path: Path, *, source_device: int | None = None
) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0

    def add(candidate: Path) -> None:
        nonlocal total
        info = candidate.stat(follow_symlinks=False)
        if source_device is not None and info.st_dev != source_device:
            raise _DifferentFilesystemError(
                f"cleanup candidate crosses filesystems: {path}"
            )
        relative = os.fsencode(str(candidate.relative_to(path) or Path(".")))
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        values = (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_blocks,
            info.st_mtime_ns,
        )
        if candidate != path:
            values += (info.st_ctime_ns,)
        digest.update(",".join(str(value) for value in values).encode())
        if candidate == path and stat.S_ISREG(info.st_mode):
            with candidate.open("rb") as handle:
                digest.update(hashlib.file_digest(handle, "sha256").digest())
        total += info.st_blocks * 512

    add(path)
    if path.is_dir() and not path.is_symlink():

        def fail(error: OSError) -> None:
            raise error

        for current, dirs, files in os.walk(path, followlinks=False, onerror=fail):
            dirs.sort()
            files.sort()
            for name in (*dirs, *files):
                add(Path(current, name))
    return total, digest.hexdigest()


def _newest_tree_mtime_ns(path: Path) -> int:
    latest = path.stat(follow_symlinks=False).st_mtime_ns
    if path.is_dir() and not path.is_symlink():

        def fail(error: OSError) -> None:
            raise error

        for current, dirs, files in os.walk(path, followlinks=False, onerror=fail):
            dirs.sort()
            files.sort()
            for name in (*dirs, *files):
                latest = max(
                    latest,
                    Path(current, name).stat(follow_symlinks=False).st_mtime_ns,
                )
    return latest


def _clean_policy_component(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 255
        or value in {".", ".."}
        or any(character in value for character in "\0/\\*?[]")
        or Path(value).parts != (value,)
    ):
        raise ValueError(f"cleanup policy {label} must be one exact path component")
    return value


def _clean_policy_root(value: Any) -> Path:
    if type(value) is not str or not value or "\0" in value:
        raise ValueError("cleanup policy root is invalid")
    root = Path(value)
    if not root.is_absolute() or str(root) != value or root.parent == root:
        raise ValueError(
            f"cleanup policy root must be an absolute non-root path: {root}"
        )
    try:
        if root.resolve(strict=True) != root:
            raise ValueError(f"cleanup policy root is not canonical: {root}")
        info = root.lstat()
    except OSError as exc:
        raise ValueError(f"cleanup policy root is unavailable: {root}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"cleanup policy root is not a real directory: {root}")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError(f"cleanup policy root has the wrong owner: {root}")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError(f"cleanup policy root is writable by another user: {root}")
    return root


def _load_clean_policy(
    paths: AppPaths, policy_path: Path
) -> tuple[dict[str, Any], dict[str, str]]:
    if not isinstance(policy_path, Path) or not policy_path.is_absolute():
        raise ValueError("cleanup policy path must be absolute")
    try:
        if policy_path.resolve(strict=True) != policy_path:
            raise ValueError(f"cleanup policy path is not canonical: {policy_path}")
        info = policy_path.lstat()
    except OSError as exc:
        raise ValueError(
            f"cleanup policy is unavailable: {policy_path}: {exc}"
        ) from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size > _MAX_CLEAN_POLICY_BYTES
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        or (os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o022)
    ):
        raise ValueError(f"cleanup policy is not a safe regular file: {policy_path}")
    identity = regular_file_stat(policy_path)
    raw = policy_path.read_bytes()
    if len(raw) > _MAX_CLEAN_POLICY_BYTES or not identity_matches(
        policy_path, identity
    ):
        raise ValueError(f"cleanup policy changed while reading: {policy_path}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"cleanup policy contains a duplicate key: {key}")
            value[key] = item
        return value

    try:
        policy = json.loads(
            raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cleanup policy is not valid JSON: {policy_path}") from exc
    if (
        not isinstance(policy, dict)
        or set(policy) != _CLEAN_POLICY_KEYS
        or type(policy.get("schema_version")) is not int
        or policy["schema_version"] != _CLEAN_POLICY_SCHEMA_VERSION
        or policy.get("kind") != "clean-policy"
        or type(policy.get("rules")) is not list
        or len(policy["rules"]) > _MAX_CLEAN_POLICY_RULES
    ):
        raise ValueError(f"cleanup policy shape is invalid: {policy_path}")
    targets: list[Path] = []
    for rule in policy["rules"]:
        if (
            not isinstance(rule, dict)
            or set(rule) != _CLEAN_POLICY_RULE_KEYS
            or type(rule.get("retention_days")) is not int
            or not 0 <= rule["retention_days"] <= _MAX_CLEAN_POLICY_RETENTION_DAYS
            or type(rule.get("markers")) is not list
            or len(rule["markers"]) > 16
            or type(rule.get("action")) is not str
            or rule["action"] not in CLEAN_ACTIONS
        ):
            raise ValueError(f"cleanup policy rule is invalid: {policy_path}")
        root = _clean_policy_root(rule.get("root"))
        name = _clean_policy_component(rule.get("name"), "candidate name")
        markers = [
            _clean_policy_component(marker, "marker") for marker in rule["markers"]
        ]
        if markers != sorted(set(markers)):
            raise ValueError(
                f"cleanup policy markers must be sorted and unique: {policy_path}"
            )
        candidate = root / name
        protected = (paths.home, paths.archive, paths.state)
        if (
            candidate == policy_path
            or policy_path.is_relative_to(candidate)
            or candidate.is_relative_to(paths.archive)
            or candidate.is_relative_to(paths.state)
            or any(
                target == candidate or target.is_relative_to(candidate)
                for target in protected
            )
        ):
            raise ValueError(
                f"cleanup policy candidate overlaps protected state: {candidate}"
            )
        if any(
            candidate.is_relative_to(target) or target.is_relative_to(candidate)
            for target in targets
        ):
            raise ValueError(
                f"cleanup policy detector targets overlap: {candidate}"
            )
        targets.append(candidate)
    return policy, {
        "path": str(policy_path),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _validate_clean_policy_reference(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != _CLEAN_POLICY_REFERENCE_KEYS
        or type(value.get("path")) is not str
        or type(value.get("sha256")) is not str
        or len(value["sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in value["sha256"])
    ):
        raise ValueError("cleanup plan policy reference is invalid")
    return value


def _load_bound_clean_policy(paths: AppPaths, reference: Any) -> dict[str, Any] | None:
    expected = _validate_clean_policy_reference(reference)
    if expected is None:
        return None
    policy, actual = _load_clean_policy(paths, Path(expected["path"]))
    if actual != expected:
        raise ValueError("cleanup policy path or SHA-256 changed after planning")
    return policy


def _candidate(
    path: Path, family: str, marker: str, action: str = "delete-tree"
) -> dict[str, Any] | None:
    try:
        if path.is_symlink() or not path.exists():
            return None
        identity = _fingerprint(path)
        if identity["type"] not in {"file", "directory"}:
            return None
        if identity["type"] == "directory" and _has_git(path):
            return None
        required = REQUIRED_MARKERS.get(family)
        if required is not None:
            if any(
                not stat.S_ISREG((path / name).stat(follow_symlinks=False).st_mode)
                for name in required
            ):
                return None
            marker = "+".join(required)
        allocated, tree_fingerprint = _tree_snapshot(path)
        return {
            "path": str(path),
            "family": family,
            "marker": marker,
            "action": action,
            "allocated_bytes": allocated,
            "tree_fingerprint": tree_fingerprint,
            **identity,
        }
    except (FileNotFoundError, PermissionError, OSError):
        return None


def discover_practical(
    paths: AppPaths,
    *,
    only: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    environ = os.environ if environ is None else environ
    tmp = _temporary_root(environ)
    results: dict[str, dict[str, Any]] = {}

    def add_candidate(
        path: Path, family: str, marker: str, action: str = "delete-tree"
    ) -> None:
        if only is not None and path != only:
            return
        value = _candidate(path, family, marker, action)
        if value is not None:
            results[value["path"]] = value

    for marker in _walk_markers(tmp, {"workspace-state.json"}):
        add_candidate(marker.parent, "swiftpm", "workspace-state.json+build.db")

    for marker in _walk_markers(tmp, {".rustc_info.json"}, max_depth=3):
        add_candidate(marker.parent, "rust-target", ".rustc_info.json+CACHEDIR.TAG")

    for marker in _walk_markers(tmp, {"CMakeCache.txt"}):
        root = marker.parent
        vcpkg_root = tmp / "fieldforge-vcpkg-buildtrees"
        if vcpkg_root in root.parents:
            root = vcpkg_root
        add_candidate(root, "cmake-build", "CMakeCache.txt")

    if tmp.is_dir():
        for child in tmp.iterdir():
            if (
                not child.is_dir()
                or child.is_symlink()
                or not GO_CACHE_NAME.match(child.name)
            ):
                continue
            action = (
                "prune-mixed-cache" if child.name.startswith("wsms") else "delete-tree"
            )
            add_candidate(child, "go-cache", "allowlisted cache name", action)

    generated_dirs = {
        "wr-implicit-preview": "generated-preview",
        "aerogalactica-native-pointcloud-sdf": "generated-pointcloud",
        "wr-go-cache": "go-cache",
        "wr-go-mod-cache": "go-cache",
        "swift-generated-sources": "generated-sources",
        "node-compile-cache": "node-cache",
        "tsx-501": "node-cache",
    }
    if tmp.is_dir():
        for name, family in generated_dirs.items():
            add_candidate(tmp / name, family, "exact practical-profile path")
        for child in tmp.glob("go-build*"):
            add_candidate(child, "go-build", "go-build prefix")
        for child in tmp.glob("preamble-*.pch"):
            add_candidate(child, "clang-preamble", "preamble-*.pch")

    for path, family in (
        (paths.home / ".cache/.bun", "bun-cache"),
        (paths.home / ".cache/bun", "bun-cache"),
        (paths.home / ".cache/nix", "nix-client-cache"),
    ):
        add_candidate(path, family, "exact practical-profile path")

    darwin_cache = _darwin_cache_root(environ)
    if darwin_cache is not None:
        for path, family in (
            (darwin_cache / "clang", "clang-cache"),
            (darwin_cache / "com.apple.dt.InstrumentsCLI", "instruments-cache"),
        ):
            add_candidate(path, family, "exact practical-profile path")

    return sorted(
        results.values(), key=lambda item: (-item["allocated_bytes"], item["path"])
    )


def _discover_policy_candidates(
    paths: AppPaths,
    policy: dict[str, Any] | None,
    *,
    now: datetime,
    only: Path | None = None,
) -> list[dict[str, Any]]:
    if policy is None:
        return []
    candidates = []
    current_ns = int(now.timestamp() * 1_000_000_000)
    for rule in policy["rules"]:
        path = Path(rule["root"]) / rule["name"]
        if only is not None and path != only:
            continue
        try:
            if path.is_symlink() or not path.exists():
                continue
            info = path.stat(follow_symlinks=False)
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                continue
            if rule["action"] == "prune-mixed-cache" and not stat.S_ISDIR(info.st_mode):
                continue
            if any(
                not stat.S_ISREG((path / marker).stat(follow_symlinks=False).st_mode)
                for marker in rule["markers"]
            ):
                continue
            cutoff_ns = current_ns - rule["retention_days"] * 86_400 * 1_000_000_000
            if _newest_tree_mtime_ns(path) > cutoff_ns:
                continue
        except (FileNotFoundError, PermissionError, OSError):
            continue
        marker = "+".join(rule["markers"]) or "policy exact name"
        candidate = _candidate(
            path,
            f"policy:{rule['name']}",
            marker,
            rule["action"],
        )
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _discover_clean_candidates(
    paths: AppPaths,
    policy_reference: Any,
    *,
    only: Path | None = None,
) -> list[dict[str, Any]]:
    results = {item["path"]: item for item in discover_practical(paths, only=only)}
    policy = _load_bound_clean_policy(paths, policy_reference)
    for item in _discover_policy_candidates(paths, policy, now=utc_now(), only=only):
        results.setdefault(item["path"], item)
    return sorted(
        results.values(), key=lambda item: (-item["allocated_bytes"], item["path"])
    )


def create_clean_plan(
    paths: AppPaths,
    profile: str = "practical",
    *,
    policy_path: Path | None = None,
    source_device: int | None = None,
    run_id: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    if profile != "practical":
        raise ValueError(f"unsupported cleanup profile: {profile}")
    if source_device is not None and (
        type(source_device) is not int or source_device < 0
    ):
        raise ValueError("cleanup source device must be a non-negative integer")
    paths.ensure_private()
    now = utc_now()
    policy_reference = None
    policy = None
    if policy_path is not None:
        policy, policy_reference = _load_clean_policy(paths, policy_path)
    opened = open_file_paths()
    candidates = []
    skipped_open = []
    discovered = {item["path"]: item for item in discover_practical(paths)}
    for item in _discover_policy_candidates(paths, policy, now=now):
        discovered.setdefault(item["path"], item)
    for item in sorted(
        discovered.values(),
        key=lambda value: (-value["allocated_bytes"], value["path"]),
    ):
        if source_device is not None and item["device"] != source_device:
            continue
        if source_device is not None:
            try:
                allocated, fingerprint = _tree_snapshot(
                    Path(item["path"]), source_device=source_device
                )
            except (OSError, _DifferentFilesystemError):
                continue
            if (
                allocated != item["allocated_bytes"]
                or fingerprint != item["tree_fingerprint"]
            ):
                continue
        if any_open([Path(item["path"])], opened):
            skipped_open.append(item["path"])
        else:
            candidates.append(item)
    run_id = new_run_id(now) if run_id is None else validate_run_id(run_id)
    plan = {
        "schema_version": SCHEMA_VERSION,
        "kind": "clean-plan",
        "profile": profile,
        "run_id": run_id,
        "created_at": iso_utc(now),
        "expires_at": iso_utc(max(now, utc_now()) + timedelta(hours=2)),
        "allocated_bytes": sum(item["allocated_bytes"] for item in candidates),
        "candidates": candidates,
        "skipped_open": skipped_open,
        "policy": policy_reference,
    }
    plan_path = paths.state / "plans" / f"clean-{run_id}.json"
    with app_lock(paths):
        _prune_expired_plans_locked(paths, keep=32)
        atomic_json(plan_path, plan, replace=False)
    return plan_path, plan


def _identity_matches(path: Path, expected: dict[str, Any]) -> bool:
    try:
        current = _fingerprint(path)
    except (FileNotFoundError, OSError):
        return False
    return all(
        current[key] == expected[key] for key in ("device", "inode", "mtime_ns", "type")
    )


def _validated_clean_candidates(
    paths: AppPaths, plan: dict[str, Any]
) -> list[dict[str, Any]]:
    keys = set(plan)
    legacy_without_policy = (
        keys == set(_CLEAN_PLAN_TYPES)
        and plan.get("schema_version") == _LEGACY_CLEAN_PLAN_SCHEMA_VERSION
    )
    if (keys != _CLEAN_PLAN_KEYS and not legacy_without_policy) or any(
        type(plan.get(key)) is not expected
        for key, expected in _CLEAN_PLAN_TYPES.items()
    ):
        raise ValueError("invalid cleanup plan shape")
    if legacy_without_policy:
        plan["policy"] = None
    _validate_clean_policy_reference(plan["policy"])
    if (
        plan["schema_version"] not in SUPPORTED_SCHEMA_VERSIONS
        or plan["kind"] != "clean-plan"
    ):
        raise ValueError("unsupported cleanup plan")
    if plan["profile"] != "practical":
        raise ValueError("unsupported cleanup profile")
    if (
        not plan["run_id"]
        or Path(plan["run_id"]).parts != (plan["run_id"],)
        or plan["run_id"] in {".", ".."}
        or "\0" in plan["run_id"]
        or plan["allocated_bytes"] < 0
        or not all(isinstance(path, str) for path in plan["skipped_open"])
    ):
        raise ValueError("invalid cleanup plan shape")
    try:
        created_at = parse_timestamp(plan["created_at"])
        expires_at = parse_timestamp(plan["expires_at"])
    except ValueError as exc:
        raise ValueError("invalid cleanup plan timestamp") from exc
    if created_at > expires_at:
        raise ValueError("cleanup plan expires before it was created")

    candidates = plan["candidates"]
    seen: set[str] = set()
    for item in candidates:
        if not isinstance(item, dict) or set(item) != _CLEAN_CANDIDATE_TYPES.keys():
            raise ValueError("invalid cleanup candidate shape")
        if any(
            type(item[key]) is not expected
            for key, expected in _CLEAN_CANDIDATE_TYPES.items()
        ):
            raise ValueError("invalid cleanup candidate shape")
        if (
            not item["path"]
            or not item["tree_fingerprint"]
            or item["path"] in seen
            or any(
                item[key] < 0
                for key in ("allocated_bytes", "device", "inode", "mtime_ns")
            )
        ):
            raise ValueError("invalid cleanup candidate shape")
        if item["action"] not in CLEAN_ACTIONS:
            raise ValueError(f"unsupported cleanup action: {item['action']}")
        seen.add(item["path"])

    if plan["allocated_bytes"] != sum(item["allocated_bytes"] for item in candidates):
        raise ValueError("cleanup plan allocated bytes do not match its candidates")
    allowed = {
        item["path"]: item for item in _discover_clean_candidates(paths, plan["policy"])
    }
    for item in candidates:
        if allowed.get(item["path"]) != item:
            raise ValueError(
                f"cleanup candidate is not currently allowed: {item['path']}"
            )
    return candidates


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


def _clean_move(candidate: Path, source: Path, quarantine: Path) -> dict[str, Any]:
    allocated, tree_fingerprint = _tree_snapshot(source)
    candidate_info = candidate.lstat()
    return {
        "candidate": str(candidate),
        "source": str(source),
        "quarantine": str(quarantine),
        "allocated_bytes": allocated,
        "tree_fingerprint": tree_fingerprint,
        "candidate_device": candidate_info.st_dev,
        "candidate_inode": candidate_info.st_ino,
        "candidate_mode": stat.S_IMODE(candidate_info.st_mode),
        "candidate_mtime_ns": candidate_info.st_mtime_ns,
        **_fingerprint(source),
    }


def _clean_quarantine_root(path: Path, run_id: str) -> Path:
    parent = path.parent
    source_device = regular_directory_stat(parent)["device"]
    local_root = parent / LOCAL_QUARANTINE_NAME
    run_root = local_root / run_id
    for existing in (local_root, run_root):
        if existing.exists() or existing.is_symlink():
            info = regular_directory_stat(existing)
            if info["device"] != source_device:
                raise RuntimeError("cleanup quarantine is not on the source filesystem")
            if os.name != "nt" and info["mode"] != 0o700:
                raise ValueError(f"cleanup quarantine is not private: {existing}")
    token = hashlib.sha256(os.fsencode(str(path))).hexdigest()[:20]
    candidate_root = run_root / token
    if candidate_root.exists() or candidate_root.is_symlink():
        raise RuntimeError(f"cleanup quarantine already exists: {candidate_root}")
    return candidate_root


def _create_clean_quarantine_root(candidate: Path, candidate_root: Path) -> None:
    local_root = candidate.parent / LOCAL_QUARANTINE_NAME
    run_root = candidate_root.parent
    for directory in (local_root, run_root, candidate_root):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = regular_directory_stat(directory)
        if os.name != "nt" and info["mode"] != 0o700:
            raise ValueError(f"cleanup quarantine is not private: {directory}")
        fsync_dir(directory)
        fsync_dir(directory.parent)


def _clean_quarantine_moves(
    path: Path, action: str, run_id: str
) -> list[dict[str, Any]]:
    candidate_root = _clean_quarantine_root(path, run_id)
    sources = (
        [path]
        if action == "delete-tree"
        else [
            child
            for child in sorted(path.iterdir())
            if child.name not in KEEP_MIXED_METADATA
        ]
    )
    if any(
        _fingerprint(source)["type"] not in {"file", "directory", "symlink"}
        for source in sources
    ):
        raise ValueError(f"cleanup candidate contains an unsupported entry: {path}")
    return [
        _clean_move(
            path,
            source,
            candidate_root
            / f"{position:04d}-{hashlib.sha256(os.fsencode(str(source))).hexdigest()[:20]}",
        )
        for position, source in enumerate(sources)
    ]


def _validate_clean_journal(
    paths: AppPaths, journal_path: Path, *, expected_path: Path | None = None
) -> dict[str, Any]:
    expected_path = journal_path if expected_path is None else expected_path
    if (
        journal_path.parent != paths.state / "clean-quarantine"
        or expected_path.parent != journal_path.parent
    ):
        raise ValueError("cleanup quarantine journal escaped its root")
    regular_file_stat(journal_path)
    journal = load_json(journal_path)
    if (
        set(journal) != _CLEAN_JOURNAL_KEYS
        or type(journal.get("schema_version")) is not int
        or journal["schema_version"] not in SUPPORTED_SCHEMA_VERSIONS
        or journal.get("kind") != "clean-quarantine"
        or type(journal.get("run_id")) is not str
        or not journal["run_id"]
        or Path(journal["run_id"]).parts != (journal["run_id"],)
        or journal["run_id"] in {".", ".."}
        or "\0" in journal["run_id"]
        or type(journal.get("created_at")) is not str
        or type(journal.get("moves")) is not list
        or expected_path.name
        != f"{journal['run_id']}-{_canonical_json_digest(journal)}.json"
    ):
        raise ValueError(f"cleanup quarantine journal is invalid: {journal_path}")
    try:
        parse_timestamp(journal["created_at"])
    except ValueError as exc:
        raise ValueError(
            f"cleanup quarantine journal is invalid: {journal_path}"
        ) from exc
    intent_path = journal_path.parent / f"{journal['run_id']}.intent"
    regular_file_stat(intent_path)
    if load_json(intent_path) != journal:
        raise ValueError(f"cleanup quarantine journal identity changed: {journal_path}")
    seen: set[Path] = set()
    positions: dict[Path, int] = {}
    for move in journal["moves"]:
        if (
            not isinstance(move, dict)
            or set(move) != _CLEAN_MOVE_KEYS
            or any(
                type(move.get(key)) is not expected
                for key, expected in {
                    "source": str,
                    "candidate": str,
                    "quarantine": str,
                    "allocated_bytes": int,
                    "tree_fingerprint": str,
                    "device": int,
                    "inode": int,
                    "mtime_ns": int,
                    "type": str,
                    "candidate_device": int,
                    "candidate_inode": int,
                    "candidate_mode": int,
                    "candidate_mtime_ns": int,
                }.items()
            )
        ):
            raise ValueError(f"cleanup quarantine move is invalid: {journal_path}")
        source = Path(move["source"])
        candidate = Path(move["candidate"])
        quarantine = Path(move["quarantine"])
        token = hashlib.sha256(os.fsencode(str(candidate))).hexdigest()[:20]
        expected_root = (
            candidate.parent / LOCAL_QUARANTINE_NAME / journal["run_id"] / token
        )
        for ancestor in (
            candidate.parent / LOCAL_QUARANTINE_NAME,
            candidate.parent / LOCAL_QUARANTINE_NAME / journal["run_id"],
            expected_root,
        ):
            if _path_exists(ancestor):
                info = regular_directory_stat(ancestor)
                if info["device"] != move["device"] or (
                    os.name != "nt" and info["mode"] != 0o700
                ):
                    raise ValueError(
                        f"cleanup quarantine directory is unsafe: {ancestor}"
                    )
        position = positions.get(expected_root, 0)
        expected_name = (
            f"{position:04d}-"
            f"{hashlib.sha256(os.fsencode(str(source))).hexdigest()[:20]}"
        )
        if (
            not source.is_absolute()
            or not candidate.is_absolute()
            or any(
                "\0" in value
                for value in (move["source"], move["candidate"], move["quarantine"])
            )
            or (source != candidate and source.parent != candidate)
            or quarantine.parent != expected_root
            or quarantine.name != expected_name
            or quarantine in seen
            or move["type"] not in {"file", "directory", "symlink"}
            or any(
                move[key] < 0
                for key in (
                    "allocated_bytes",
                    "device",
                    "inode",
                    "mtime_ns",
                    "candidate_device",
                    "candidate_inode",
                    "candidate_mode",
                    "candidate_mtime_ns",
                )
            )
            or move["candidate_mode"] > 0o777
        ):
            raise ValueError(f"cleanup quarantine move is invalid: {journal_path}")
        seen.add(quarantine)
        positions[expected_root] = position + 1
    return journal


def _validate_clean_completion(
    paths: AppPaths, completion: Path, expected: Path
) -> dict[str, Any]:
    return _validate_clean_journal(paths, completion, expected_path=expected)


def _clean_move_matches(path: Path, move: dict[str, Any]) -> bool:
    if not _identity_matches(path, move):
        return False
    try:
        allocated, fingerprint = _tree_snapshot(path)
    except OSError:
        return False
    return (
        allocated == move["allocated_bytes"] and fingerprint == move["tree_fingerprint"]
    )


def _clean_tombstone(quarantine: Path) -> Path:
    return quarantine.with_name(f".{quarantine.name}.deleting")


def _clean_tombstone_state(tombstone: Path) -> Path:
    return tombstone.with_name(f"{tombstone.name}.json")


def _tombstone_identity(path: Path) -> dict[str, Any]:
    info = path.stat(follow_symlinks=False)
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "ctime_ns": info.st_ctime_ns,
        "type": _fingerprint(path)["type"],
    }


def _tombstone_state_payload(
    tombstone: Path, move: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "clean-deletion-staging",
        "tombstone": str(tombstone),
        "move_sha256": _canonical_json_digest(move),
        **_tombstone_identity(tombstone),
    }


def _load_tombstone_state(
    tombstone: Path, move: dict[str, Any], *, require_current: bool
) -> dict[str, Any]:
    state_path = _clean_tombstone_state(tombstone)
    info = state_path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or (os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o600)
        or (
            os.name != "nt"
            and hasattr(os, "getuid")
            and info.st_uid != os.getuid()
        )
    ):
        raise RuntimeError(f"cleanup deletion staging state is unsafe: {state_path}")
    payload = load_json(state_path)
    if (
        set(payload)
        != {
            "schema_version",
            "kind",
            "tombstone",
            "move_sha256",
            "device",
            "inode",
            "ctime_ns",
            "type",
        }
        or payload.get("schema_version") != SCHEMA_VERSION
        or payload.get("kind") != "clean-deletion-staging"
        or payload.get("tombstone") != str(tombstone)
        or payload.get("move_sha256") != _canonical_json_digest(move)
        or any(
            type(payload.get(key)) is not int
            for key in ("device", "inode", "ctime_ns")
        )
        or payload.get("type") not in {"file", "directory", "symlink"}
    ):
        raise RuntimeError(f"cleanup deletion staging state changed: {state_path}")
    if require_current:
        current = _tombstone_identity(tombstone)
        if any(
            payload[key] != current[key]
            for key in ("device", "inode", "ctime_ns", "type")
        ):
            raise RuntimeError(
                f"cleanup deletion staging identity changed: {tombstone}"
            )
    return payload


def _write_tombstone_state(tombstone: Path, move: dict[str, Any]) -> None:
    state_path = _clean_tombstone_state(tombstone)
    if _path_exists(state_path):
        _load_tombstone_state(tombstone, move, require_current=False)
    atomic_json(
        state_path,
        _tombstone_state_payload(tombstone, move),
        replace=_path_exists(state_path),
    )


def _path_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _remove_empty_clean_quarantine_parents(move: dict[str, Any]) -> None:
    current = Path(move["quarantine"]).parent
    stop = Path(move["candidate"]).parent
    while current != stop:
        try:
            current.rmdir()
            fsync_dir(current.parent)
        except OSError:
            break
        current = current.parent


def _canonical_json_digest(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _apply_clean_plan_locked(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    paths.ensure_private()
    plan = load_json(plan_path)
    candidates = _validated_clean_candidates(paths, plan)
    if utc_now() > parse_timestamp(plan["expires_at"]):
        raise RuntimeError("cleanup plan expired")
    # Prove the targeted recursive enumerator works for the complete plan
    # before the first destructive operation.
    open_file_paths_for(
        (
            Path(item["path"])
            for item in candidates
            if _identity_matches(Path(item["path"]), item)
        ),
        recursive=True,
    )
    _load_bound_clean_policy(paths, plan["policy"])
    journal_root = ensure_private_subdirectory(paths.state, "clean-quarantine")
    intent_path = journal_root / f"{plan['run_id']}.intent"
    if any(journal_root.glob(f"{plan['run_id']}-*.json")):
        raise RuntimeError(
            f"cleanup quarantine journal already exists for run: {plan['run_id']}"
        )
    planned_moves = {
        item["path"]: _clean_quarantine_moves(
            Path(item["path"]), item["action"], plan["run_id"]
        )
        for item in candidates
    }
    expected = {
        "schema_version": SCHEMA_VERSION,
        "kind": "clean-quarantine",
        "run_id": plan["run_id"],
        "moves": [move for item in candidates for move in planned_moves[item["path"]]],
    }
    if _path_exists(intent_path):
        regular_file_stat(intent_path)
        journal = load_json(intent_path)
        if (
            not isinstance(journal, dict)
            or type(journal.get("created_at")) is not str
            or {key: value for key, value in journal.items() if key != "created_at"}
            != expected
        ):
            raise RuntimeError(f"cleanup quarantine intent changed: {intent_path}")
        parse_timestamp(journal["created_at"])
    else:
        journal = {**expected, "created_at": iso_utc(utc_now())}
    journal_path = (
        journal_root / f"{plan['run_id']}-{_canonical_json_digest(journal)}.json"
    )
    if not _path_exists(intent_path):
        atomic_json(intent_path, journal, replace=False)
    atomic_json(journal_path, journal, replace=False)
    quarantined_bytes = 0
    removed = []
    skipped = []
    for item_number, item in enumerate(candidates, start=1):
        path = Path(item["path"])
        if not _identity_matches(path, item):
            skipped.append({"path": str(path), "reason": "identity drift"})
            continue
        opened = open_file_paths_for([path], recursive=True)
        if any_open([path], opened):
            skipped.append({"path": str(path), "reason": "open"})
            continue
        if item["type"] == "directory" and _has_git(path):
            skipped.append({"path": str(path), "reason": "Git metadata"})
            continue
        if not _identity_matches(path, item):
            skipped.append({"path": str(path), "reason": "identity drift"})
            continue
        current = next(
            iter(
                _discover_clean_candidates(
                    paths,
                    plan["policy"],
                    only=path,
                )
            ),
            None,
        )
        if current != item:
            skipped.append({"path": str(path), "reason": "marker or content drift"})
            continue
        moves = planned_moves[item["path"]]
        if moves:
            _create_clean_quarantine_root(path, Path(moves[0]["quarantine"]).parent)
        candidate_moved = False
        for move in moves:
            source = Path(move["source"])
            quarantine = Path(move["quarantine"])
            if quarantine.parent.stat().st_dev != source.parent.stat().st_dev:
                raise RuntimeError("cleanup quarantine is not on the source filesystem")
            try:
                os.replace(source, quarantine)
            except PermissionError as exc:
                if candidate_moved:
                    raise
                skipped.append(
                    {
                        "path": str(path),
                        "reason": f"{exc.__class__.__name__}: {exc}",
                    }
                )
                for planned in moves:
                    _remove_empty_clean_quarantine_parents(planned)
                break
            fsync_dir(source.parent)
            fsync_dir(quarantine.parent)
            candidate_moved = True
            quarantined_bytes += move["allocated_bytes"]
        else:
            removed.append(str(path))
            if item_number % 25 == 0:
                print(
                    f"cleanup progress: {item_number}/{len(plan['candidates'])} candidates processed",
                    file=sys.stderr,
                    flush=True,
                )
    if not any(_path_exists(Path(move["quarantine"])) for move in journal["moves"]):
        journal_path.unlink()
        fsync_dir(journal_path.parent)
        intent_path.unlink()
        fsync_dir(intent_path.parent)
    return {
        "reclaimed_bytes": 0,
        "quarantined_bytes": quarantined_bytes,
        "quarantine": str(journal_path) if journal_path.exists() else None,
        "removed": removed,
        "skipped": skipped,
    }


def apply_clean_plan(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    with app_lock(paths):
        result = _apply_clean_plan_locked(paths, plan_path)
        if result["quarantined_bytes"] == 0:
            return result
        return record_history_after_success(
            paths,
            result,
            operation="clean-apply",
            logical_reclaimed_bytes_delta=result["quarantined_bytes"],
        )


def undo_clean(paths: AppPaths, journal_path: Path) -> dict[str, Any]:
    """Restore every identity-pinned move from one cleanup quarantine."""

    with app_lock(paths):
        paths.ensure_private()
        completed_path = journal_path.with_suffix(".undo-complete")
        if not _path_exists(journal_path):
            _validate_clean_completion(paths, completed_path, journal_path)
            fsync_dir(journal_path.parent)
            return {"restored": 0, "restored_bytes": 0}
        if _path_exists(completed_path):
            raise RuntimeError(
                f"cleanup undo completion already exists: {completed_path}"
            )
        journal = _validate_clean_journal(paths, journal_path)
        moves = journal["moves"]
        states = []
        for move in moves:
            source = Path(move["source"])
            quarantine = Path(move["quarantine"])
            source_matches = _clean_move_matches(source, move)
            quarantine_matches = _clean_move_matches(quarantine, move)
            if (
                source_matches
                and not quarantine_matches
                and not _path_exists(_clean_tombstone(quarantine))
            ):
                states.append("not-moved")
                continue
            if quarantine_matches and not _path_exists(source):
                states.append("quarantined")
                continue
            if _path_exists(source) and not any(
                _path_exists(path)
                for path in (quarantine, _clean_tombstone(quarantine))
            ):
                states.append("skipped")
                continue
            if _path_exists(source):
                raise FileExistsError(f"cleanup undo destination exists: {source}")
            raise RuntimeError(f"cleanup quarantine identity changed: {quarantine}")
        restored = 0
        for move, state in reversed(list(zip(moves, states, strict=True))):
            if state in {"not-moved", "skipped"}:
                fsync_dir(Path(move["source"]).parent)
                quarantine_parent = Path(move["quarantine"]).parent
                if quarantine_parent.exists():
                    fsync_dir(quarantine_parent)
                continue
            source = Path(move["source"])
            quarantine = Path(move["quarantine"])
            if _path_exists(source):
                raise FileExistsError(f"cleanup undo destination exists: {source}")
            if not _clean_move_matches(quarantine, move):
                raise RuntimeError(f"cleanup quarantine identity changed: {quarantine}")
            os.replace(quarantine, source)
            fsync_dir(source.parent)
            fsync_dir(quarantine.parent)
            restored += 1
        roots: dict[Path, dict[str, Any]] = {
            Path(move["candidate"]): move
            for move, state in zip(moves, states, strict=True)
            if state != "skipped"
        }
        for root, move in roots.items():
            info = root.lstat()
            if (
                info.st_dev != move["candidate_device"]
                or info.st_ino != move["candidate_inode"]
            ):
                raise RuntimeError(f"cleanup candidate identity changed: {root}")
            root.chmod(move["candidate_mode"], follow_symlinks=False)
            os.utime(
                root,
                ns=(move["candidate_mtime_ns"], move["candidate_mtime_ns"]),
                follow_symlinks=False,
            )
            fsync_dir(root)
            fsync_dir(root.parent)
        os.replace(journal_path, completed_path)
        fsync_dir(journal_path.parent)
        for move in moves:
            _remove_empty_clean_quarantine_parents(move)
        result = {
            "restored": restored,
            "restored_bytes": sum(
                move["allocated_bytes"]
                for move, state in zip(moves, states, strict=True)
                if state == "quarantined"
            ),
        }
        if result["restored_bytes"] == 0:
            return result
        return record_history_after_success(
            paths,
            result,
            operation="clean-undo",
            logical_reclaimed_bytes_delta=-result["restored_bytes"],
        )


def _clean_quarantine_journals(paths: AppPaths) -> list[tuple[Path, dict[str, Any]]]:
    root = ensure_private_subdirectory(paths.state, "clean-quarantine")
    journals = []
    for entry in sorted(root.iterdir()):
        if entry.suffix == ".intent":
            payload = load_json(entry)
            if not isinstance(payload, dict):
                raise ValueError(f"cleanup quarantine intent is invalid: {entry}")
            expected = entry.with_name(
                f"{entry.stem}-{_canonical_json_digest(payload)}.json"
            )
            _validate_clean_journal(paths, entry, expected_path=expected)
            continue
        if entry.suffix == ".undo-complete":
            _validate_clean_completion(paths, entry, entry.with_suffix(".json"))
            continue
        if entry.suffix == ".expiry-complete":
            _validate_clean_completion(paths, entry, entry.with_suffix(".json"))
            continue
        if entry.suffix != ".json":
            raise ValueError(f"unknown cleanup quarantine entry: {entry}")
        journals.append((entry, _validate_clean_journal(paths, entry)))
    return journals


def create_clean_expiry_plan(
    paths: AppPaths,
    *,
    retention_days: int = DEFAULT_CLEAN_QUARANTINE_DAYS,
) -> tuple[Path, dict[str, Any]]:
    if type(retention_days) is not int or retention_days < 0:
        raise ValueError("cleanup quarantine retention must be a non-negative integer")
    with app_lock(paths):
        paths.ensure_private()
        current = utc_now()
        cutoff = current - timedelta(days=retention_days)
        selected = []
        for path, journal in _clean_quarantine_journals(paths):
            if parse_timestamp(journal["created_at"]) <= cutoff:
                selected.append({"path": str(path), **regular_file_stat(path)})
        run_id = new_run_id(current)
        plan = {
            "schema_version": SCHEMA_VERSION,
            "kind": "clean-expiry-plan",
            "run_id": run_id,
            "created_at": iso_utc(current),
            "expires_at": iso_utc(current + timedelta(hours=2)),
            "retention_days": retention_days,
            "journals": selected,
        }
        digest = _canonical_json_digest(plan)
        plan_path = paths.state / "plans" / f"clean-expiry-{run_id}-{digest}.json"
        _prune_expired_plans_locked(paths, keep=32)
        atomic_json(plan_path, plan, replace=False)
        return plan_path, plan


def _validate_clean_expiry_plan(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    if plan_path.parent != paths.state / "plans":
        raise ValueError("cleanup expiry plan escaped the plans root")
    regular_file_stat(plan_path)
    plan = load_json(plan_path)
    if (
        set(plan) != _CLEAN_EXPIRY_PLAN_KEYS
        or type(plan.get("schema_version")) is not int
        or plan["schema_version"] not in SUPPORTED_SCHEMA_VERSIONS
        or plan.get("kind") != "clean-expiry-plan"
        or type(plan.get("run_id")) is not str
        or not plan["run_id"]
        or Path(plan["run_id"]).parts != (plan["run_id"],)
        or plan["run_id"] in {".", ".."}
        or "\0" in plan["run_id"]
        or type(plan.get("created_at")) is not str
        or type(plan.get("expires_at")) is not str
        or type(plan.get("retention_days")) is not int
        or plan["retention_days"] < 0
        or type(plan.get("journals")) is not list
    ):
        raise ValueError("cleanup expiry plan is invalid")
    if plan_path.name != (
        f"clean-expiry-{plan['run_id']}-{_canonical_json_digest(plan)}.json"
    ):
        raise ValueError("cleanup expiry plan identity is invalid")
    created_at = parse_timestamp(plan["created_at"])
    expires_at = parse_timestamp(plan["expires_at"])
    if created_at > expires_at:
        raise ValueError("cleanup expiry timestamps are reversed")
    seen = set()
    for item in plan["journals"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "device", "inode", "size", "mtime_ns", "mode"}
            or type(item.get("path")) is not str
            or any(
                type(item.get(key)) is not int
                for key in ("device", "inode", "size", "mtime_ns", "mode")
            )
            or Path(item["path"]).parent != paths.state / "clean-quarantine"
            or item["path"] in seen
        ):
            raise ValueError("cleanup expiry journal entry is invalid")
        seen.add(item["path"])
    return plan


def apply_clean_expiry_plan(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    with app_lock(paths):
        paths.ensure_private()
        plan = _validate_clean_expiry_plan(paths, plan_path)
        if utc_now() > parse_timestamp(plan["expires_at"]):
            raise RuntimeError("cleanup expiry plan expired")
        cutoff = parse_timestamp(plan["created_at"]) - timedelta(
            days=plan["retention_days"]
        )
        current = {
            str(path): (path, journal)
            for path, journal in _clean_quarantine_journals(paths)
            if parse_timestamp(journal["created_at"]) <= cutoff
        }
        for item in plan["journals"]:
            path = Path(item["path"])
            if not _path_exists(path):
                _validate_clean_completion(
                    paths, path.with_suffix(".expiry-complete"), path
                )
        present = {
            item["path"]
            for item in plan["journals"]
            if _path_exists(Path(item["path"]))
        }
        if set(current) != present:
            raise RuntimeError("cleanup quarantine expiry eligibility changed")
        states: dict[str, list[tuple[dict[str, Any], str]]] = {}
        for item in plan["journals"]:
            if item["path"] not in current:
                states[item["path"]] = []
                continue
            path, journal = current[item["path"]]
            completion = path.with_suffix(".expiry-complete")
            if _path_exists(completion):
                raise RuntimeError(
                    f"cleanup expiry completion already exists: {completion}"
                )
            if not identity_matches(path, item):
                raise RuntimeError(f"cleanup quarantine journal changed: {path}")
            states[item["path"]] = []
            for move in journal["moves"]:
                source = Path(move["source"])
                quarantine = Path(move["quarantine"])
                tombstone = _clean_tombstone(quarantine)
                tombstone_state = _clean_tombstone_state(tombstone)
                if (
                    _clean_move_matches(quarantine, move)
                    and not _path_exists(source)
                    and not _path_exists(tombstone)
                    and not _path_exists(tombstone_state)
                ):
                    state = "quarantined"
                elif (
                    not _path_exists(source)
                    and not _path_exists(quarantine)
                    and _path_exists(tombstone)
                    and _path_exists(tombstone_state)
                ):
                    _load_tombstone_state(tombstone, move, require_current=True)
                    state = "deleting"
                elif (
                    _clean_move_matches(source, move)
                    and not _path_exists(quarantine)
                    and not _path_exists(tombstone)
                    and not _path_exists(tombstone_state)
                ):
                    state = "not-moved"
                elif _path_exists(source) and not any(
                    _path_exists(path)
                    for path in (quarantine, tombstone, tombstone_state)
                ):
                    state = "skipped"
                elif not any(
                    _path_exists(path) for path in (source, quarantine, tombstone)
                ) and _path_exists(tombstone_state):
                    _load_tombstone_state(tombstone, move, require_current=False)
                    state = "removed-staged"
                elif not any(
                    _path_exists(path)
                    for path in (source, quarantine, tombstone, tombstone_state)
                ):
                    state = "removed"
                else:
                    raise RuntimeError(
                        f"cleanup quarantine identity changed: {quarantine}"
                    )
                states[item["path"]].append((move, state))
        removed_bytes = 0
        removed = []
        for item in plan["journals"]:
            if item["path"] not in current:
                fsync_dir(Path(item["path"]).parent)
                removed.append(item["path"])
                continue
            path, journal = current[item["path"]]
            for move, state in states[item["path"]]:
                quarantine = Path(move["quarantine"])
                tombstone = _clean_tombstone(quarantine)
                tombstone_state = _clean_tombstone_state(tombstone)
                if state in {"not-moved", "skipped"}:
                    fsync_dir(Path(move["source"]).parent)
                    if quarantine.parent.exists():
                        fsync_dir(quarantine.parent)
                    continue
                if state == "removed-staged":
                    tombstone_state.unlink()
                    fsync_dir(quarantine.parent)
                    continue
                if state == "removed":
                    if quarantine.parent.exists():
                        fsync_dir(quarantine.parent)
                    continue
                if state == "quarantined":
                    if _path_exists(tombstone):
                        raise RuntimeError(
                            f"cleanup deletion staging already exists: {tombstone}"
                        )
                    os.rename(quarantine, tombstone)
                    _write_tombstone_state(tombstone, move)
                _load_tombstone_state(tombstone, move, require_current=True)
                try:
                    if tombstone.is_symlink():
                        tombstone.unlink()
                    else:
                        _delete_tree(tombstone)
                except BaseException:
                    if _path_exists(tombstone):
                        _write_tombstone_state(tombstone, move)
                    raise
                fsync_dir(quarantine.parent)
                _load_tombstone_state(tombstone, move, require_current=False)
                tombstone_state.unlink()
                fsync_dir(quarantine.parent)
                removed_bytes += move["allocated_bytes"]
                _remove_empty_clean_quarantine_parents(move)
            os.replace(path, completion)
            fsync_dir(path.parent)
            removed.append(str(path))
        result = {
            "journals_removed": len(removed),
            "reclaimed_bytes": removed_bytes,
            "removed": removed,
        }
        if removed_bytes == 0:
            return result
        return record_history_after_success(
            paths,
            result,
            operation="clean-expiry",
            physical_allocated_bytes_delta=-removed_bytes,
        )
