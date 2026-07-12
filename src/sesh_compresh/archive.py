from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from .common import (
    SCHEMA_VERSION,
    AppPaths,
    any_open,
    atomic_json,
    fsync_dir,
    identity_matches,
    iso_utc,
    load_json,
    open_file_paths,
    parse_timestamp,
    regular_file_stat,
    sha256_file,
    sha256_stream,
    utc_now,
)


@dataclass(frozen=True)
class SessionUnit:
    provider: str
    session_id: str
    source_root: Path
    files: tuple[Path, ...]
    retention_days: int


def _max_jsonl_timestamp(path: Path) -> datetime:
    latest: datetime | None = None
    with path.open(encoding="utf-8", errors="strict") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed JSONL at record {number}") from exc
            if not isinstance(item, dict) or "timestamp" not in item:
                continue
            value = item["timestamp"]
            if not isinstance(value, str):
                raise ValueError(f"non-string timestamp at record {number}")
            parsed = parse_timestamp(value)
            latest = parsed if latest is None or parsed > latest else latest
    if latest is None:
        raise ValueError("no valid top-level timestamp")
    return latest


def _bundle_files(primary: Path) -> tuple[Path, ...]:
    files = [primary]
    companion = primary.with_suffix("")
    if companion.is_dir() and not companion.is_symlink():
        files.extend(
            path
            for path in sorted(companion.rglob("*"))
            if path.is_file() and not path.is_symlink()
        )
    return tuple(files)


def discover_sessions(paths: AppPaths) -> Iterator[SessionUnit]:
    observer = paths.home / ".claude/projects/-Users-rexliu--claude-mem-observer-sessions"
    if observer.is_dir():
        for source in sorted(observer.glob("*.jsonl")):
            if source.is_file() and not source.is_symlink():
                yield SessionUnit("claude-observer", source.stem, observer, (source,), 7)

    claude_projects = paths.home / ".claude/projects"
    if claude_projects.is_dir():
        for project in sorted(claude_projects.iterdir()):
            if not project.is_dir() or project == observer or project.is_symlink():
                continue
            for primary in sorted(project.glob("*.jsonl")):
                if primary.is_file() and not primary.is_symlink():
                    yield SessionUnit(
                        "claude",
                        f"{project.name}:{primary.stem}",
                        project,
                        _bundle_files(primary),
                        30,
                    )

    for label, root in (
        ("codex", paths.home / ".codex/sessions"),
        ("codex-archived", paths.home / ".codex/archived_sessions"),
    ):
        if not root.is_dir():
            continue
        for source in sorted(root.rglob("*.jsonl")):
            if source.is_file() and not source.is_symlink():
                yield SessionUnit(label, source.stem, root, (source,), 30)


def _unit_activity(unit: SessionUnit) -> datetime:
    timestamps = [_max_jsonl_timestamp(path) for path in unit.files if path.suffix == ".jsonl"]
    if not timestamps:
        raise ValueError("session bundle has no JSONL member")
    return max(timestamps)


def create_archive_plan(paths: AppPaths, now: datetime | None = None) -> tuple[Path, dict[str, Any]]:
    paths.ensure_private()
    current = (now or utc_now()).astimezone(UTC)
    opened = open_file_paths()
    selected: list[dict[str, Any]] = []
    skipped: dict[str, int] = {}
    logical_bytes = 0

    for unit in discover_sessions(paths):
        try:
            if any_open(unit.files, opened):
                raise RuntimeError("open")
            activity = _unit_activity(unit)
            if activity > current - timedelta(days=unit.retention_days):
                raise RuntimeError("recent")
            members = []
            for source in unit.files:
                stat = regular_file_stat(source)
                logical_bytes += stat["size"]
                members.append({"path": str(source), "relative": str(source.relative_to(unit.source_root)), **stat})
            selected.append(
                {
                    "provider": unit.provider,
                    "session_id": unit.session_id,
                    "source_root": str(unit.source_root),
                    "retention_days": unit.retention_days,
                    "last_activity": iso_utc(activity),
                    "files": members,
                }
            )
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            reason = str(exc) or exc.__class__.__name__
            skipped[reason] = skipped.get(reason, 0) + 1

    run_id = current.strftime("%Y%m%dT%H%M%SZ")
    plan = {
        "schema_version": SCHEMA_VERSION,
        "kind": "archive-plan",
        "run_id": run_id,
        "created_at": iso_utc(current),
        "expires_at": iso_utc(current + timedelta(hours=2)),
        "logical_bytes": logical_bytes,
        "sessions": selected,
        "skipped": skipped,
    }
    plan_path = paths.state / "plans" / f"archive-{run_id}.json"
    atomic_json(plan_path, plan)
    return plan_path, plan


def _zstd_binary() -> str:
    binary = shutil.which("zstd")
    if binary is None:
        for candidate in ("/opt/homebrew/bin/zstd", "/usr/local/bin/zstd"):
            if Path(candidate).is_file():
                return candidate
        raise RuntimeError("zstd is required")
    return binary


def _verify_zstd(binary: str, object_path: Path, raw_hash: str) -> None:
    subprocess.run([binary, "-q", "-t", str(object_path)], check=True)
    process = subprocess.Popen([binary, "-q", "-d", "--stdout", str(object_path)], stdout=subprocess.PIPE)
    assert process.stdout is not None
    with process.stdout:
        decoded_hash = sha256_stream(process.stdout)
    status = process.wait()
    if status != 0:
        raise RuntimeError(f"zstd decode failed with status {status}")
    if decoded_hash != raw_hash:
        raise RuntimeError("archive raw SHA-256 mismatch")


def _ensure_object(paths: AppPaths, source: Path, raw_hash: str, zstd: str) -> tuple[Path, str]:
    target = paths.archive / "objects/sha256" / raw_hash[:2] / f"{raw_hash}.zst"
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.exists():
        _verify_zstd(zstd, target, raw_hash)
        return target, sha256_file(target)

    fd, raw_tmp = tempfile.mkstemp(prefix=f".{raw_hash}.", suffix=".part", dir=target.parent)
    os.close(fd)
    tmp = Path(raw_tmp)
    try:
        tmp.chmod(0o600)
        subprocess.run(
            [zstd, "-q", "-6", "--check", "-T0", "-f", str(source), "-o", str(tmp)],
            check=True,
        )
        with tmp.open("rb") as handle:
            os.fsync(handle.fileno())
        _verify_zstd(zstd, tmp, raw_hash)
        compressed_hash = sha256_file(tmp)
        os.replace(tmp, target)
        target.chmod(0o600)
        fsync_dir(target.parent)
        return target, compressed_hash
    finally:
        tmp.unlink(missing_ok=True)


def _manifest_key(session: dict[str, Any]) -> str:
    import hashlib

    seed = f"{session['provider']}\0{session['source_root']}\0{session['session_id']}".encode()
    return hashlib.sha256(seed).hexdigest()[:20]


def apply_archive_plan(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    paths.ensure_private()
    plan = load_json(plan_path)
    if plan.get("schema_version") != SCHEMA_VERSION or plan.get("kind") != "archive-plan":
        raise ValueError("unsupported archive plan")
    if utc_now() > parse_timestamp(plan["expires_at"]):
        raise RuntimeError("archive plan expired")

    zstd = _zstd_binary()
    opened = open_file_paths()
    quarantine_run = paths.state / "quarantine" / plan["run_id"]
    manifests: list[str] = []
    raw_bytes = 0
    compressed_bytes = 0

    for session_number, session in enumerate(plan["sessions"], start=1):
        sources = [Path(member["path"]) for member in session["files"]]
        if any_open(sources, opened):
            raise RuntimeError(f"session became active: {session['session_id']}")
        for source, member in zip(sources, session["files"], strict=True):
            if not identity_matches(source, member):
                raise RuntimeError(f"source changed since plan: {source}")

        key = _manifest_key(session)
        manifest_path = paths.archive / "manifests" / session["provider"] / f"{key}.json"
        archived_members: list[dict[str, Any]] = []
        for source, member in zip(sources, session["files"], strict=True):
            raw_hash = sha256_file(source)
            if not identity_matches(source, member):
                raise RuntimeError(f"source changed while hashing: {source}")
            object_path, compressed_hash = _ensure_object(paths, source, raw_hash, zstd)
            archived_members.append(
                {
                    **member,
                    "raw_sha256": raw_hash,
                    "compressed_sha256": compressed_hash,
                    "object": str(object_path.relative_to(paths.archive)),
                }
            )
            raw_bytes += member["size"]
            compressed_bytes += object_path.stat().st_size

        manifest = {
            "schema_version": SCHEMA_VERSION,
            "kind": "session-archive",
            "archive_id": key,
            "provider": session["provider"],
            "session_id": session["session_id"],
            "source_root": session["source_root"],
            "last_activity": session["last_activity"],
            "archived_at": iso_utc(utc_now()),
            "files": archived_members,
        }
        quarantine = quarantine_run / key
        restore_record = quarantine / "_restore.json"
        staged_manifest = quarantine / "_manifest.json"
        atomic_json(staged_manifest, manifest)
        atomic_json(
            restore_record,
            {
                "schema_version": SCHEMA_VERSION,
                "source_root": session["source_root"],
                "manifest": str(manifest_path),
                "files": [member["relative"] for member in archived_members],
            },
        )
        moved: list[tuple[Path, Path]] = []
        try:
            for source, member in zip(sources, archived_members, strict=True):
                if not identity_matches(source, member):
                    raise RuntimeError(f"source changed before quarantine: {source}")
                destination = quarantine / "files" / member["relative"]
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.replace(source, destination)
                moved.append((source, destination))
            for _, destination in moved:
                if sha256_file(destination) != next(
                    member["raw_sha256"] for member in archived_members if member["relative"] == str(destination.relative_to(quarantine / "files"))
                ):
                    raise RuntimeError("quarantined source hash mismatch")
            atomic_json(manifest_path, manifest)
            shutil.rmtree(quarantine)
            manifests.append(str(manifest_path))
            if session_number % 500 == 0:
                print(
                    f"archive progress: {session_number}/{len(plan['sessions'])} sessions committed",
                    file=sys.stderr,
                    flush=True,
                )
        except Exception:
            for source, destination in reversed(moved):
                if destination.exists() and not source.exists():
                    source.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(destination, source)
            raise

    if quarantine_run.exists() and not any(quarantine_run.iterdir()):
        quarantine_run.rmdir()
    return {
        "sessions": len(manifests),
        "raw_bytes": raw_bytes,
        "compressed_bytes": compressed_bytes,
        "reclaimed_bytes": raw_bytes - compressed_bytes,
        "manifest_count": len(manifests),
    }


def iter_manifests(paths: AppPaths) -> Iterator[Path]:
    root = paths.archive / "manifests"
    if root.is_dir():
        yield from sorted(root.rglob("*.json"))


def verify_manifest(paths: AppPaths, manifest_path: Path) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    if manifest.get("kind") != "session-archive":
        raise ValueError(f"unsupported manifest: {manifest_path}")
    zstd = _zstd_binary()
    for member in manifest["files"]:
        object_path = paths.archive / member["object"]
        if sha256_file(object_path) != member["compressed_sha256"]:
            raise RuntimeError(f"compressed SHA-256 mismatch: {object_path}")
        _verify_zstd(zstd, object_path, member["raw_sha256"])
    return manifest


def verify_all(paths: AppPaths) -> dict[str, int]:
    manifests = 0
    files = 0
    for manifest_path in iter_manifests(paths):
        manifest = verify_manifest(paths, manifest_path)
        manifests += 1
        files += len(manifest["files"])
    return {"manifests": manifests, "files": files}


def resolve_manifest(paths: AppPaths, reference: str) -> Path:
    direct = Path(reference).expanduser()
    if direct.is_file():
        return direct
    matches = [path for path in iter_manifests(paths) if reference in path.stem]
    if len(matches) != 1:
        raise ValueError(f"manifest reference matched {len(matches)} entries: {reference}")
    return matches[0]


def restore_manifest(paths: AppPaths, reference: str, destination: Path | None = None) -> dict[str, Any]:
    manifest_path = resolve_manifest(paths, reference)
    manifest = verify_manifest(paths, manifest_path)
    root = destination.expanduser().resolve() if destination else Path(manifest["source_root"])
    zstd = _zstd_binary()
    restored = 0
    for member in manifest["files"]:
        target = root / member["relative"]
        if target.exists() or target.is_symlink():
            raise FileExistsError(f"restore destination exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, raw_tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".restore", dir=target.parent)
        os.close(fd)
        tmp = Path(raw_tmp)
        try:
            subprocess.run(
                [zstd, "-q", "-d", "-f", str(paths.archive / member["object"]), "-o", str(tmp)],
                check=True,
            )
            if sha256_file(tmp) != member["raw_sha256"]:
                raise RuntimeError(f"restored SHA-256 mismatch: {target}")
            tmp.chmod(member["mode"])
            os.utime(tmp, ns=(member["mtime_ns"], member["mtime_ns"]))
            os.replace(tmp, target)
            fsync_dir(target.parent)
            restored += 1
        finally:
            tmp.unlink(missing_ok=True)
    return {"archive_id": manifest["archive_id"], "files": restored, "destination": str(root)}


def recover_quarantine(paths: AppPaths) -> dict[str, int]:
    root = paths.state / "quarantine"
    restored = 0
    conflicts = 0
    if not root.is_dir():
        return {"restored": 0, "conflicts": 0}
    for record in sorted(root.rglob("_restore.json")):
        payload = load_json(record)
        source_root = Path(payload["source_root"])
        files_root = record.parent / "files"
        record_conflicts = 0
        for relative in payload["files"]:
            source = source_root / relative
            quarantined = files_root / relative
            if not quarantined.exists():
                continue
            if source.exists() or source.is_symlink():
                conflicts += 1
                record_conflicts += 1
                continue
            source.parent.mkdir(parents=True, exist_ok=True)
            os.replace(quarantined, source)
            restored += 1
        remaining = [path for path in files_root.rglob("*") if path.is_file()] if files_root.exists() else []
        if not remaining and record_conflicts == 0:
            record.unlink(missing_ok=True)
            (record.parent / "_manifest.json").unlink(missing_ok=True)
            for directory in (files_root, record.parent, record.parent.parent):
                try:
                    directory.rmdir()
                except OSError:
                    pass
    return {"restored": restored, "conflicts": conflicts}
