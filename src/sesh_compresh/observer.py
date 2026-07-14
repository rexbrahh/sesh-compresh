from __future__ import annotations

import json
import os
import re
import sqlite3
import stat as stat_module
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator, Mapping

from .archive import (
    SourceChangedError,
    _zstd_binary,
    archive_planned_session,
    iter_manifests,
    validate_planned_session,
)
from .common import (
    SCHEMA_VERSION,
    AppPaths,
    any_open,
    app_lock,
    atomic_json,
    directory_identity_matches,
    identity_matches,
    iso_utc,
    load_json,
    open_file_paths_for,
    parse_timestamp,
    prune_expired_plans,
    regular_directory_stat,
    regular_file_stat,
    safe_cas_object_path,
    safe_cas_root,
    safe_cas_shard,
    utc_now,
)


OBSERVER_PROVIDER = "claude-observer"
DEFAULT_GRACE_SECONDS = 60 * 60
DEFAULT_ARCHIVE_TTL_DAYS = 7
DEFAULT_ARCHIVE_CAP_BYTES = 5 * 1024**3
SESSION_ID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
CAS_NAME_PATTERN = re.compile(r"^[0-9a-f]{64}\.zst$")


def _setting_record(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"settings path is not a regular file: {path}")
    try:
        raw = load_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"cannot read settings: {path}: {exc}") from exc
    env = raw.get("env")
    if env is None:
        return raw
    if not isinstance(env, dict):
        raise ValueError(f"settings env must be an object: {path}")
    return env


def _configured_path(value: Any, *, home: Path, key: str) -> Path | None:
    if value is None:
        return None
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty path string")
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = home / candidate
    return candidate.resolve()


@dataclass(frozen=True)
class ClaudeMemPaths:
    claude_config: Path
    data: Path

    @classmethod
    def discover(
        cls,
        app_paths: AppPaths,
        *,
        claude_config: Path | None = None,
        data: Path | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> "ClaudeMemPaths":
        """Resolve roots using the same precedence as claude-mem."""

        env = os.environ if environ is None else environ
        home = app_paths.home
        default_data = (home / ".claude-mem").resolve()
        direct_data = (
            _configured_path(data, home=home, key="claude-mem data directory")
            if data is not None
            else _configured_path(env.get("CLAUDE_MEM_DATA_DIR"), home=home, key="CLAUDE_MEM_DATA_DIR")
        )
        direct_config = (
            _configured_path(claude_config, home=home, key="Claude config directory")
            if claude_config is not None
            else _configured_path(env.get("CLAUDE_CONFIG_DIR"), home=home, key="CLAUDE_CONFIG_DIR")
        )

        default_settings: dict[str, Any] = {}
        if direct_data is None:
            default_settings = _setting_record(default_data / "settings.json")
        data_path = direct_data or _configured_path(
            default_settings.get("CLAUDE_MEM_DATA_DIR"),
            home=home,
            key="settings CLAUDE_MEM_DATA_DIR",
        ) or default_data

        # claude-mem reads CLAUDE_CONFIG_DIR only from the process environment;
        # its settings file is a data-directory fallback alone.
        config_path = direct_config or (home / ".claude").resolve()
        return cls(claude_config=config_path, data=data_path)

    @property
    def database(self) -> Path:
        return self.data / "claude-mem.db"

    @property
    def corpora(self) -> Path:
        return self.data / "corpora"

    @property
    def observer_cwd(self) -> Path:
        return (self.data / "observer-sessions").resolve()

    @property
    def observer_project(self) -> Path:
        return self.claude_config / "projects" / sanitize_claude_project_path(str(self.observer_cwd))


def _base36(value: int) -> str:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    if value == 0:
        return "0"
    digits = []
    while value:
        value, remainder = divmod(value, 36)
        digits.append(alphabet[remainder])
    return "".join(reversed(digits))


def _sdk_string_hash(value: str) -> int:
    """Match the signed 32-bit JavaScript hash used by the Agent SDK."""

    encoded = value.encode("utf-16-le", errors="surrogatepass")
    result = 0
    for offset in range(0, len(encoded), 2):
        code_unit = int.from_bytes(encoded[offset : offset + 2], "little")
        result = ((result * 31) + code_unit) & 0xFFFFFFFF
    if result & 0x80000000:
        result -= 0x100000000
    return result


def sanitize_claude_project_path(value: str) -> str:
    """Match Claude Agent SDK project-directory sanitization."""

    encoded = value.encode("utf-16-le", errors="surrogatepass")
    code_units = (
        int.from_bytes(encoded[offset : offset + 2], "little")
        for offset in range(0, len(encoded), 2)
    )
    sanitized = "".join(
        chr(code_unit)
        if 48 <= code_unit <= 57 or 65 <= code_unit <= 90 or 97 <= code_unit <= 122
        else "-"
        for code_unit in code_units
    )
    if len(sanitized) <= 200:
        return sanitized
    return f"{sanitized[:200]}-{_base36(abs(_sdk_string_hash(value)))}"


def normalize_session_id(value: str) -> str | None:
    normalized = value.strip().lower()
    return normalized if SESSION_ID_PATTERN.fullmatch(normalized) else None


def _read_database_references(database: Path) -> set[str]:
    if database.is_symlink() or not database.is_file():
        raise RuntimeError(f"claude-mem database is missing or unsafe: {database}")
    uri = f"{database.as_uri()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            connection.execute("PRAGMA query_only = ON")
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(sdk_sessions)")
                if len(row) >= 2
            }
            if "memory_session_id" not in columns:
                raise RuntimeError("claude-mem database has no sdk_sessions.memory_session_id column")
            references: set[str] = set()
            for (value,) in connection.execute(
                "SELECT memory_session_id FROM sdk_sessions WHERE memory_session_id IS NOT NULL"
            ):
                if not isinstance(value, str) or not value.strip():
                    raise RuntimeError("claude-mem database contains an invalid memory_session_id")
                references.add(value.strip().lower())
            return references
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise RuntimeError(f"cannot read claude-mem references: {database}: {exc}") from exc


def _iter_corpus_files(corpora: Path) -> Iterator[Path]:
    if not corpora.exists():
        return
    if corpora.is_symlink() or not corpora.is_dir():
        raise RuntimeError(f"claude-mem corpora path is unsafe: {corpora}")
    for candidate in sorted(corpora.rglob("*.corpus.json")):
        if candidate.is_symlink() or not candidate.is_file():
            raise RuntimeError(f"corpus is not a regular file: {candidate}")
        yield candidate


def _read_corpus_references(corpora: Path) -> set[str]:
    references: set[str] = set()
    for corpus in _iter_corpus_files(corpora):
        try:
            payload = load_json(corpus)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError(f"malformed claude-mem corpus: {corpus}: {exc}") from exc
        value = payload.get("session_id")
        if value is None:
            continue
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(f"malformed claude-mem corpus session_id: {corpus}")
        references.add(value.strip().lower())
    return references


def read_keep_set(runtime: ClaudeMemPaths) -> tuple[set[str], dict[str, int]]:
    database = _read_database_references(runtime.database)
    corpora = _read_corpus_references(runtime.corpora)
    return database | corpora, {
        "database": len(database),
        "corpora": len(corpora),
        "union": len(database | corpora),
    }


def session_is_referenced(runtime: ClaudeMemPaths, session_id: str) -> bool:
    """Fresh targeted reference read used at the final mutation boundary."""

    if runtime.database.is_symlink() or not runtime.database.is_file():
        raise RuntimeError(f"claude-mem database is missing or unsafe: {runtime.database}")
    uri = f"{runtime.database.as_uri()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            connection.execute("PRAGMA query_only = ON")
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(sdk_sessions)")
                if len(row) >= 2
            }
            if "memory_session_id" not in columns:
                raise RuntimeError(
                    "claude-mem database has no sdk_sessions.memory_session_id column"
                )
            row = connection.execute(
                "SELECT 1 FROM sdk_sessions "
                "WHERE memory_session_id = ? OR memory_session_id = ? LIMIT 1",
                (session_id, session_id.upper()),
            ).fetchone()
            if row is not None:
                return True
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise RuntimeError(
            f"cannot read claude-mem reference: {runtime.database}: {exc}"
        ) from exc

    for corpus in _iter_corpus_files(runtime.corpora):
        try:
            payload = load_json(corpus)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError(f"malformed claude-mem corpus: {corpus}: {exc}") from exc
        value = payload.get("session_id")
        if value is None:
            continue
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(f"malformed claude-mem corpus session_id: {corpus}")
        if value.strip().lower() == session_id:
            return True
    return False


def _validate_grace(grace_seconds: int) -> None:
    if grace_seconds < 0:
        raise ValueError("observer grace must be non-negative")


def _safe_directory_identity(path: Path) -> dict[str, int]:
    """Validate a directory and every ancestor without following symlinks."""

    current = path
    while True:
        try:
            info = current.lstat()
        except OSError as exc:
            raise RuntimeError(f"observer directory ancestor is unavailable: {current}: {exc}") from exc
        if stat_module.S_ISLNK(info.st_mode) or not stat_module.S_ISDIR(info.st_mode):
            raise RuntimeError(f"observer directory ancestor is unsafe: {current}")
        if current.parent == current:
            break
        current = current.parent
    observer = path.stat(follow_symlinks=False)
    return {"device": observer.st_dev, "inode": observer.st_ino}


def _validate_directory_identity(path: Path, expected: dict[str, Any]) -> None:
    current = _safe_directory_identity(path)
    if any(current[key] != expected.get(key) for key in ("device", "inode")):
        raise RuntimeError("observer project directory identity drift")


def _scan_companion_bundle(
    observer: Path,
    session_stem: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    companion = observer / session_stem
    if not companion.exists() and not companion.is_symlink():
        return [], []
    if companion.is_symlink() or not companion.is_dir():
        raise ValueError(f"observer companion is not a safe directory: {companion}")

    files: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = []

    def visit(directory: Path) -> None:
        directories.append(
            {
                "path": str(directory),
                "relative": str(directory.relative_to(observer)),
                **regular_directory_stat(directory),
            }
        )
        with os.scandir(directory) as entries:
            children = sorted(entries, key=lambda entry: entry.name)
        for entry in children:
            child = Path(entry.path)
            info = entry.stat(follow_symlinks=False)
            if stat_module.S_ISLNK(info.st_mode):
                raise ValueError(f"observer companion contains a symlink: {child}")
            if stat_module.S_ISDIR(info.st_mode):
                visit(child)
            elif stat_module.S_ISREG(info.st_mode):
                files.append(
                    {
                        "path": str(child),
                        "relative": str(child.relative_to(observer)),
                        **regular_file_stat(child),
                    }
                )
            else:
                raise ValueError(f"observer companion contains a special file: {child}")

    visit(companion)
    return files, directories


def create_observer_gc_plan(
    paths: AppPaths,
    runtime: ClaudeMemPaths,
    *,
    grace_seconds: int = DEFAULT_GRACE_SECONDS,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any]]:
    paths.ensure_private()
    _validate_grace(grace_seconds)
    current = (now or utc_now()).astimezone(UTC)
    keep, reference_counts = read_keep_set(runtime)
    observer = runtime.observer_project
    candidates: list[dict[str, Any]] = []
    eligible: list[dict[str, Any]] = []
    protected = Counter()
    logical_bytes = 0
    observer_identity: dict[str, int] | None = None

    if observer.exists() and (observer.is_symlink() or not observer.is_dir()):
        raise RuntimeError(f"observer project path is unsafe: {observer}")
    if observer.is_dir():
        observer_identity = _safe_directory_identity(observer)
        cutoff_ns = int((current - timedelta(seconds=grace_seconds)).timestamp() * 1_000_000_000)
        for source in sorted(observer.glob("*.jsonl")):
            try:
                stat = regular_file_stat(source)
            except (OSError, ValueError):
                protected["unsafe"] += 1
                continue
            session_id = normalize_session_id(source.stem)
            if session_id is None:
                protected["non_uuid_name"] += 1
                continue
            if session_id in keep:
                protected["referenced"] += 1
                continue
            try:
                companion_files, directories = _scan_companion_bundle(observer, source.stem)
            except (OSError, ValueError):
                protected["unsafe_bundle"] += 1
                continue
            files = [
                {
                    "path": str(source),
                    "relative": source.name,
                    **stat,
                },
                *companion_files,
            ]
            latest_mtime_ns = max(
                item["mtime_ns"] for item in [*files, *directories]
            )
            if latest_mtime_ns > cutoff_ns:
                protected["recent"] += 1
                continue
            activity = datetime.fromtimestamp(latest_mtime_ns / 1_000_000_000, tz=UTC)
            eligible.append(
                {
                    "provider": OBSERVER_PROVIDER,
                    "session_id": session_id,
                    "source_root": str(observer),
                    "last_activity": iso_utc(activity),
                    "files": files,
                    "directories": directories,
                }
            )

        open_candidates = [
            Path(item["path"])
            for session in eligible
            for item in [*session["files"], *session["directories"]]
        ]
        opened = open_file_paths_for(open_candidates)
        for session in eligible:
            bundle_paths = [
                Path(item["path"])
                for item in [*session["files"], *session["directories"]]
            ]
            if any_open(bundle_paths, opened):
                protected["open"] += 1
                continue
            logical_bytes += sum(item["size"] for item in session["files"])
            candidates.append(session)

    run_id = current.strftime("%Y%m%dT%H%M%S.%fZ")
    plan = {
        "schema_version": SCHEMA_VERSION,
        "kind": "observer-gc-plan",
        "run_id": run_id,
        "created_at": iso_utc(current),
        "expires_at": iso_utc(current + timedelta(hours=2)),
        "claude_config_dir": str(runtime.claude_config),
        "claude_mem_data_dir": str(runtime.data),
        "observer_project": str(observer),
        "observer_project_identity": observer_identity,
        "grace_seconds": grace_seconds,
        "reference_counts": reference_counts,
        "logical_bytes": logical_bytes,
        "candidates": candidates,
        "protected": dict(sorted(protected.items())),
    }
    plan_path = paths.state / "plans" / f"observer-gc-{run_id}.json"
    atomic_json(plan_path, plan)
    prune_expired_plans(paths)
    return plan_path, plan


def _validate_observer_plan(plan: dict[str, Any], runtime: ClaudeMemPaths) -> None:
    if plan.get("schema_version") != SCHEMA_VERSION or plan.get("kind") != "observer-gc-plan":
        raise ValueError("unsupported observer GC plan")
    if not isinstance(plan.get("run_id"), str) or not isinstance(plan.get("expires_at"), str):
        raise ValueError("observer GC plan metadata is invalid")
    if utc_now() > parse_timestamp(plan["expires_at"]):
        raise RuntimeError("observer GC plan expired")
    expected = {
        "claude_config_dir": str(runtime.claude_config),
        "claude_mem_data_dir": str(runtime.data),
        "observer_project": str(runtime.observer_project),
    }
    for key, value in expected.items():
        if plan.get(key) != value:
            raise RuntimeError(f"observer GC plan {key} does not match the active runtime")
    grace_seconds = plan.get("grace_seconds")
    if not isinstance(grace_seconds, int):
        raise ValueError("observer GC plan grace is invalid")
    _validate_grace(grace_seconds)
    candidates = plan.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("observer GC plan candidates must be a list")
    identity = plan.get("observer_project_identity")
    if candidates and not isinstance(identity, dict):
        raise ValueError("observer GC plan has candidates without a directory identity")
    if candidates and any(not isinstance(identity.get(key), int) for key in ("device", "inode")):
        raise ValueError("observer GC plan directory identity is invalid")
    seen: set[str] = set()
    for session in candidates:
        if not isinstance(session, dict):
            raise ValueError("observer GC candidate must be an object")
        source, _ = _candidate_source(session, runtime.observer_project)
        session_id = session["session_id"]
        if session_id in seen:
            raise ValueError(f"observer GC plan has duplicate session: {session_id}")
        seen.add(session_id)
        companion = runtime.observer_project / source.stem
        companion_files = [Path(member["path"]) for member in session["files"][1:]]
        companion_directories = {
            Path(member["path"]) for member in session.get("directories", [])
        }
        for path in companion_files:
            if path == companion or not path.is_relative_to(companion):
                raise ValueError("observer companion file escaped its exact sibling directory")
        for path in companion_directories:
            if not path.is_relative_to(companion):
                raise ValueError("observer companion directory escaped its exact sibling directory")
        if companion_files or companion_directories:
            if companion not in companion_directories:
                raise ValueError("observer companion plan is missing its root directory")
            for path in [*companion_files, *companion_directories]:
                parent = path.parent
                while parent != companion.parent:
                    if parent not in companion_directories:
                        raise ValueError("observer companion plan is missing a parent directory")
                    if parent == companion:
                        break
                    parent = parent.parent


def _candidate_source(session: dict[str, Any], observer: Path) -> tuple[Path, dict[str, Any]]:
    validate_planned_session(session)
    if session.get("provider") != OBSERVER_PROVIDER or session.get("source_root") != str(observer):
        raise ValueError("observer GC candidate escaped its provider or source root")
    files = session.get("files")
    if not isinstance(files, list) or not files or not isinstance(files[0], dict):
        raise ValueError("observer GC candidate must contain a primary file")
    member = files[0]
    source = Path(member["path"])
    if source.parent != observer or source.suffix != ".jsonl" or member.get("relative") != source.name:
        raise ValueError("observer GC candidate escaped the observer project")
    normalized_stem = normalize_session_id(source.stem)
    if normalized_stem is None or session.get("session_id") != normalized_stem:
        raise ValueError("observer GC candidate session id does not match its filename")
    return source, member


def _assert_bundle_identity(session: dict[str, Any], observer: Path) -> None:
    source, primary = _candidate_source(session, observer)
    if not identity_matches(source, primary):
        raise CandidateProtected("identity drift")
    try:
        actual_files, actual_directories = _scan_companion_bundle(observer, source.stem)
    except (OSError, ValueError) as exc:
        raise CandidateProtected(f"unsafe bundle: {exc}") from exc
    planned_files = {item["path"]: item for item in session["files"][1:]}
    planned_directories = {item["path"]: item for item in session.get("directories", [])}
    if set(planned_files) != {item["path"] for item in actual_files}:
        raise CandidateProtected("companion file set drift")
    if set(planned_directories) != {item["path"] for item in actual_directories}:
        raise CandidateProtected("companion directory set drift")
    if any(
        not identity_matches(Path(path), member)
        for path, member in planned_files.items()
    ):
        raise CandidateProtected("companion file identity drift")
    if any(
        not directory_identity_matches(Path(path), member)
        for path, member in planned_directories.items()
    ):
        raise CandidateProtected("companion directory identity drift")


class CandidateProtected(RuntimeError):
    """A single planned transcript acquired a preservation condition."""


def _candidate_paths(session: dict[str, Any]) -> list[Path]:
    return [
        Path(item["path"])
        for item in [*session["files"], *session.get("directories", [])]
    ]


def _assert_candidate_age_and_identity(
    runtime: ClaudeMemPaths,
    plan: dict[str, Any],
    session: dict[str, Any],
) -> None:
    expected_root = plan["observer_project_identity"]
    _validate_directory_identity(runtime.observer_project, expected_root)
    _assert_bundle_identity(session, runtime.observer_project)
    cutoff_ns = int(
        (utc_now() - timedelta(seconds=plan["grace_seconds"])).timestamp()
        * 1_000_000_000
    )
    mtimes = [
        item["mtime_ns"]
        for item in [*session["files"], *session.get("directories", [])]
    ]
    if max(mtimes) > cutoff_ns:
        raise CandidateProtected("recent")


def _assert_candidate_cached(
    runtime: ClaudeMemPaths,
    plan: dict[str, Any],
    session: dict[str, Any],
    keep: set[str],
    opened: set[Path],
) -> None:
    _assert_candidate_age_and_identity(runtime, plan, session)
    if session["session_id"] in keep:
        raise CandidateProtected("newly referenced")
    if any_open(_candidate_paths(session), opened):
        raise CandidateProtected("open")


def _assert_candidate_final(
    runtime: ClaudeMemPaths,
    plan: dict[str, Any],
    session: dict[str, Any],
) -> None:
    _assert_candidate_age_and_identity(runtime, plan, session)
    opened = open_file_paths_for(_candidate_paths(session))
    if any_open(_candidate_paths(session), opened):
        raise CandidateProtected("open")
    # Keep this authoritative targeted read last: archive_planned_session calls
    # us directly before its first os.replace.
    if session_is_referenced(runtime, session["session_id"]):
        raise CandidateProtected("newly referenced")


def _apply_observer_gc_plan_locked(
    paths: AppPaths,
    runtime: ClaudeMemPaths,
    plan_path: Path,
) -> dict[str, Any]:
    paths.ensure_private()
    plan = load_json(plan_path)
    _validate_observer_plan(plan, runtime)

    zstd = _zstd_binary()
    quarantine_run = paths.state / "quarantine" / plan["run_id"]
    archived: list[str] = []
    skipped: list[dict[str, str]] = []
    raw_bytes = 0
    compressed_bytes = 0
    keep, reference_counts = read_keep_set(runtime)
    opened = open_file_paths_for(
        path for session in plan["candidates"] for path in _candidate_paths(session)
    )

    for session in plan["candidates"]:
        session_id = str(session.get("session_id", "<unknown>"))
        try:
            _assert_candidate_cached(runtime, plan, session, keep, opened)

            def before_move() -> None:
                _assert_candidate_final(runtime, plan, session)

            result = archive_planned_session(
                paths,
                session,
                zstd=zstd,
                quarantine_run=quarantine_run,
                before_move=before_move,
            )
            raw_bytes += result["raw_bytes"]
            compressed_bytes += result["compressed_bytes"]
            archived.append(result["manifest"])
        except (CandidateProtected, SourceChangedError, FileNotFoundError) as exc:
            skipped.append({"session_id": session_id, "reason": str(exc) or exc.__class__.__name__})

    if quarantine_run.exists() and not any(quarantine_run.iterdir()):
        quarantine_run.rmdir()
    return {
        "archived": len(archived),
        "manifests": archived,
        "raw_bytes": raw_bytes,
        "compressed_bytes": compressed_bytes,
        "reclaimed_bytes": raw_bytes - compressed_bytes,
        "skipped": skipped,
        "reference_counts": reference_counts,
    }


def apply_observer_gc_plan(
    paths: AppPaths,
    runtime: ClaudeMemPaths,
    plan_path: Path,
) -> dict[str, Any]:
    with app_lock(paths):
        return _apply_observer_gc_plan_locked(paths, runtime, plan_path)


def _object_path(paths: AppPaths, value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("archive manifest has an invalid object path")
    return safe_cas_object_path(paths.archive, value)


def _manifest_record(paths: AppPaths, manifest_path: Path) -> dict[str, Any]:
    stat = regular_file_stat(manifest_path)
    manifest = load_json(manifest_path)
    if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("kind") != "session-archive":
        raise ValueError(f"unsupported archive manifest: {manifest_path}")
    provider = manifest.get("provider")
    if not isinstance(provider, str) or not provider:
        raise ValueError(f"archive manifest has no provider: {manifest_path}")
    manifests_root = paths.archive / "manifests"
    try:
        relative_manifest = manifest_path.relative_to(manifests_root)
    except ValueError as exc:
        raise ValueError(f"archive manifest escaped its root: {manifest_path}") from exc
    if len(relative_manifest.parts) < 2 or relative_manifest.parts[0] != provider:
        raise ValueError(f"archive manifest provider path mismatch: {manifest_path}")
    archived_at = manifest.get("archived_at")
    if not isinstance(archived_at, str):
        raise ValueError(f"archive manifest has no archived_at: {manifest_path}")
    parsed_at = parse_timestamp(archived_at)
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError(f"archive manifest has no files: {manifest_path}")
    objects: set[str] = set()
    for member in files:
        if not isinstance(member, dict):
            raise ValueError(f"archive manifest has an invalid member: {manifest_path}")
        object_path = _object_path(paths, member.get("object"))
        if object_path.is_symlink() or not object_path.is_file():
            raise ValueError(f"archive object is missing or unsafe: {object_path}")
        objects.add(str(object_path.relative_to(paths.archive)))
    return {
        "path": str(manifest_path),
        "provider": provider,
        "archived_at": iso_utc(parsed_at),
        "archived_at_value": parsed_at,
        "objects": sorted(objects),
        **stat,
    }


def _all_manifest_records(paths: AppPaths) -> list[dict[str, Any]]:
    records = []
    for manifest_path in iter_manifests(paths):
        try:
            records.append(_manifest_record(paths, manifest_path))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError(f"cannot evaluate archive reachability: {exc}") from exc
    return records


def _object_sizes(paths: AppPaths, records: list[dict[str, Any]]) -> dict[str, int]:
    objects = {value for record in records for value in record["objects"]}
    return {
        value: safe_cas_object_path(paths.archive, value).stat(follow_symlinks=False).st_size
        for value in objects
    }


def _identity_pinned_orphan_objects(paths: AppPaths, reachable: set[str]) -> list[str]:
    root = paths.archive / "objects" / "sha256"
    if not root.exists() and not root.is_symlink():
        return []
    root, _ = safe_cas_root(paths.archive)
    candidates = []
    for shard_entry in sorted(root.iterdir()):
        if shard_entry.is_symlink() or not shard_entry.is_dir():
            raise RuntimeError(f"archive CAS shard is unsafe: {shard_entry}")
        try:
            shard, _ = safe_cas_shard(paths.archive, shard_entry.name)
        except ValueError as exc:
            raise RuntimeError(f"archive CAS shard is unsafe: {shard_entry}: {exc}") from exc
        for path in sorted(shard.iterdir()):
            relative = str(path.relative_to(paths.archive))
            if relative in reachable:
                continue
            if not CAS_NAME_PATTERN.fullmatch(path.name) or path.parent.name != path.name[:2]:
                continue
            try:
                safe_cas_object_path(paths.archive, relative)
            except ValueError as exc:
                raise RuntimeError(f"archive CAS object is unsafe: {path}: {exc}") from exc
            candidates.append(relative)
    return candidates


def _create_observer_expiry_plan_locked(
    paths: AppPaths,
    *,
    ttl_days: int,
    cap_bytes: int,
    current: datetime,
) -> tuple[Path, dict[str, Any]]:
    records = _all_manifest_records(paths)
    sizes = _object_sizes(paths, records)
    observer = [record for record in records if record["provider"] == OBSERVER_PROVIDER]
    selected: dict[str, set[str]] = {}
    cutoff = current - timedelta(days=ttl_days)

    for record in observer:
        if record["archived_at_value"] <= cutoff:
            selected.setdefault(record["path"], set()).add("ttl")

    remaining = [record for record in observer if record["path"] not in selected]
    remaining_counts = Counter(
        value for record in remaining for value in record["objects"]
    )
    remaining_bytes = sum(sizes[value] for value in remaining_counts)
    ordered_remaining = sorted(
        remaining,
        key=lambda record: (record["archived_at_value"], record["path"]),
    )
    for oldest in ordered_remaining:
        if remaining_bytes <= cap_bytes:
            break
        selected.setdefault(oldest["path"], set()).add("cap")
        for value in oldest["objects"]:
            remaining_counts[value] -= 1
            if remaining_counts[value] == 0:
                remaining_bytes -= sizes[value]
                del remaining_counts[value]
    remaining = [record for record in observer if record["path"] not in selected]

    selected_records = [record for record in observer if record["path"] in selected]
    selected_paths = set(selected)
    reachable_after = {
        value
        for record in records
        if record["path"] not in selected_paths
        for value in record["objects"]
    }
    candidate_objects = sorted(
        {
            value
            for record in selected_records
            for value in record["objects"]
            if value not in reachable_after
        }
        | set(_identity_pinned_orphan_objects(paths, reachable_after))
    )
    cas_candidates = []
    for value in candidate_objects:
        object_path = _object_path(paths, value)
        cas_candidates.append({"path": str(object_path), "relative": value, **regular_file_stat(object_path)})

    run_id = current.strftime("%Y%m%dT%H%M%S.%fZ")
    manifest_entries = [
        {
            key: value
            for key, value in record.items()
            if key not in {"archived_at_value", "provider"}
        }
        | {"reasons": sorted(selected[record["path"]])}
        for record in selected_records
    ]
    plan = {
        "schema_version": SCHEMA_VERSION,
        "kind": "observer-expiry-plan",
        "run_id": run_id,
        "created_at": iso_utc(current),
        "expires_at": iso_utc(current + timedelta(hours=2)),
        "provider": OBSERVER_PROVIDER,
        "ttl_days": ttl_days,
        "cap_bytes": cap_bytes,
        "observer_bytes_before": sum(
            sizes[value] for value in {value for record in observer for value in record["objects"]}
        ),
        "observer_bytes_after": remaining_bytes,
        "manifests": manifest_entries,
        "cas_candidates": cas_candidates,
    }
    plan_path = paths.state / "plans" / f"observer-expiry-{run_id}.json"
    atomic_json(plan_path, plan)
    return plan_path, plan


def create_observer_expiry_plan(
    paths: AppPaths,
    *,
    ttl_days: int = DEFAULT_ARCHIVE_TTL_DAYS,
    cap_bytes: int = DEFAULT_ARCHIVE_CAP_BYTES,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any]]:
    paths.ensure_private()
    if ttl_days < 0:
        raise ValueError("observer archive TTL must be non-negative")
    if cap_bytes < 0:
        raise ValueError("observer archive cap must be non-negative")
    current = (now or utc_now()).astimezone(UTC)
    with app_lock(paths):
        result = _create_observer_expiry_plan_locked(
            paths,
            ttl_days=ttl_days,
            cap_bytes=cap_bytes,
            current=current,
        )
    prune_expired_plans(paths)
    return result


def _validate_expiry_plan_structure(paths: AppPaths, plan: dict[str, Any]) -> None:
    if plan.get("schema_version") != SCHEMA_VERSION or plan.get("kind") != "observer-expiry-plan":
        raise ValueError("unsupported observer archive expiry plan")
    if plan.get("provider") != OBSERVER_PROVIDER:
        raise ValueError("observer archive expiry plan has an unsupported provider")
    if not isinstance(plan.get("run_id"), str) or not isinstance(plan.get("expires_at"), str):
        raise ValueError("observer archive expiry metadata is invalid")
    if not isinstance(plan.get("ttl_days"), int) or not isinstance(plan.get("cap_bytes"), int):
        raise ValueError("observer archive expiry policy is invalid")
    manifests = plan.get("manifests")
    cas_candidates = plan.get("cas_candidates")
    if not isinstance(manifests, list) or not isinstance(cas_candidates, list):
        raise ValueError("observer archive expiry entries must be lists")
    manifest_root = paths.archive / "manifests" / OBSERVER_PROVIDER
    seen: set[Path] = set()
    for item in manifests:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("observer archive expiry manifest entry is invalid")
        path = Path(item["path"])
        if path.parent != manifest_root or path.suffix != ".json" or path in seen:
            raise ValueError("observer archive expiry manifest path is invalid")
        seen.add(path)
        if any(not isinstance(item.get(key), int) for key in ("device", "inode", "size", "mtime_ns")):
            raise ValueError("observer archive expiry manifest identity is invalid")
    seen.clear()
    for item in cas_candidates:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("relative"), str)
        ):
            raise ValueError("observer archive expiry CAS entry is invalid")
        path = Path(item["path"])
        relative = Path(item["relative"])
        expected = paths.archive / relative
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or len(relative.parts) != 4
            or relative.parts[:2] != ("objects", "sha256")
            or path != expected
            or path in seen
        ):
            raise ValueError("observer archive expiry CAS path is invalid")
        seen.add(path)
        if any(not isinstance(item.get(key), int) for key in ("device", "inode", "size", "mtime_ns")):
            raise ValueError("observer archive expiry CAS identity is invalid")
        canonical = _object_path(paths, item["relative"])
        if canonical != path:
            raise ValueError("observer archive expiry CAS path is invalid")


def _apply_observer_expiry_plan_locked(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    plan = load_json(plan_path)
    _validate_expiry_plan_structure(paths, plan)
    if utc_now() > parse_timestamp(plan["expires_at"]):
        raise RuntimeError("observer archive expiry plan expired")

    # Validate the complete manifest graph before changing it.  A malformed
    # unrelated provider could otherwise make a shared CAS object appear dead.
    records = _all_manifest_records(paths)
    by_path = {record["path"]: record for record in records}
    reference_counts = Counter(value for record in records for value in record["objects"])
    removed: list[str] = []
    skipped: list[dict[str, str]] = []
    for item in plan["manifests"]:
        path = Path(item["path"])
        current = by_path.get(str(path))
        if current is None or current["provider"] != OBSERVER_PROVIDER:
            skipped.append({"path": str(path), "reason": "missing or provider drift"})
            continue
        if not identity_matches(path, item):
            skipped.append({"path": str(path), "reason": "identity drift"})
            continue
        try:
            path.unlink()
            removed.append(str(path))
            for value in current["objects"]:
                reference_counts[value] -= 1
                if reference_counts[value] == 0:
                    del reference_counts[value]
        except OSError as exc:
            skipped.append({"path": str(path), "reason": f"{exc.__class__.__name__}: {exc}"})

    objects_removed: list[str] = []
    for item in plan["cas_candidates"]:
        path = Path(item["path"])
        relative = item["relative"]
        try:
            expected = _object_path(paths, relative)
        except ValueError as exc:
            skipped.append({"path": str(path), "reason": str(exc)})
            continue
        if path != expected:
            skipped.append({"path": str(path), "reason": "CAS path drift"})
            continue
        # This O(1) reachability check is immediate and authoritative for all
        # cooperating publishers because the complete operation holds app_lock.
        if reference_counts.get(relative, 0) > 0:
            skipped.append({"path": str(path), "reason": "still reachable"})
            continue
        if not identity_matches(path, item):
            skipped.append({"path": str(path), "reason": "CAS identity drift"})
            continue
        try:
            path.unlink()
            objects_removed.append(str(path))
        except OSError as exc:
            skipped.append({"path": str(path), "reason": f"{exc.__class__.__name__}: {exc}"})

    for directory in sorted(
        {Path(path).parent for path in removed + objects_removed},
        key=lambda value: len(value.parts),
        reverse=True,
    ):
        try:
            directory.rmdir()
        except OSError:
            pass
    return {
        "manifests_removed": len(removed),
        "objects_removed": len(objects_removed),
        "removed": removed,
        "skipped": skipped,
    }


def apply_observer_expiry_plan(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    with app_lock(paths):
        return _apply_observer_expiry_plan_locked(paths, plan_path)
