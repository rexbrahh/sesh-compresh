from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat as stat_module
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator, Mapping

from .archive import (
    TRAINABLE_PROVIDERS,
    SourceChangedError,
    _archive_metrics,
    _archive_planned_session_locked,
    _cas_inventory,
    _chunk_object_relative,
    _manifest_key,
    _manifest_session_key,
    _manifest_version,
    _refresh_latest_indexes,
    _regular_directory_chain_exists,
    _scan_session_bundle,
    _zstd_binary,
    iter_manifests,
    load_provider_dictionary,
    validate_manifest,
    validate_planned_session,
)
from .common import (
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    AppPaths,
    CasObjectKind,
    _prune_expired_plans_locked,
    any_open,
    app_lock,
    atomic_json,
    cas_object_name_details,
    directory_identity_matches,
    fsync_dir,
    identity_matches,
    iso_utc,
    load_json,
    new_run_id,
    open_file_paths_for,
    parse_timestamp,
    prune_expired_plans,
    regular_file_stat,
    safe_cas_object_path,
    safe_cas_root,
    safe_cas_shard,
    utc_now,
)
from .history import record_history_after_success
from .encryption import encryption_config


OBSERVER_PROVIDER = "claude-observer"
DEFAULT_GRACE_SECONDS = 60 * 60
DEFAULT_ARCHIVE_TTL_DAYS = 7
DEFAULT_ARCHIVE_CAP_BYTES = 5 * 1024**3
SESSION_ID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_HOLD_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_SESSION_KEY_PATTERN = re.compile(r"^[0-9a-f]{20}$")
_HOLD_STATE_KEYS = {"schema_version", "kind", "holds"}
_LIVE_HOLD_KEYS = {
    "hold_id",
    "kind",
    "provider",
    "session_id",
    "reason",
    "created_at",
}
_ARCHIVE_HOLD_KEYS = _LIVE_HOLD_KEYS | {
    "session_key",
    "version",
    "archive_id",
    "manifest",
}


def _expiry_plan_digest(plan: dict[str, Any]) -> str:
    encoded = json.dumps(
        plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _validate_expiry_policy(ttl_days: Any, cap_bytes: Any) -> None:
    if (
        type(ttl_days) is not int
        or type(cap_bytes) is not int
        or ttl_days < 0
        or cap_bytes < 0
    ):
        raise ValueError("archive expiry policy must be non-negative integers")


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
            else _configured_path(
                env.get("CLAUDE_MEM_DATA_DIR"), home=home, key="CLAUDE_MEM_DATA_DIR"
            )
        )
        direct_config = (
            _configured_path(claude_config, home=home, key="Claude config directory")
            if claude_config is not None
            else _configured_path(
                env.get("CLAUDE_CONFIG_DIR"), home=home, key="CLAUDE_CONFIG_DIR"
            )
        )

        default_settings: dict[str, Any] = {}
        if direct_data is None:
            default_settings = _setting_record(default_data / "settings.json")
        data_path = (
            direct_data
            or _configured_path(
                default_settings.get("CLAUDE_MEM_DATA_DIR"),
                home=home,
                key="settings CLAUDE_MEM_DATA_DIR",
            )
            or default_data
        )

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
        return (
            self.claude_config
            / "projects"
            / sanitize_claude_project_path(str(self.observer_cwd))
        )


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


def _hold_id(kind: str, provider: str, identity: str) -> str:
    return hashlib.sha256(f"{kind}\0{provider}\0{identity}".encode()).hexdigest()[:32]


def _hold_reason(reason: Any) -> str:
    if (
        type(reason) is not str
        or not reason
        or reason != reason.strip()
        or "\0" in reason
        or len(reason) > 1000
    ):
        raise ValueError("retention hold reason must be 1 to 1000 trimmed characters")
    return reason


def _validate_hold_record(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError("retention hold must be an object")
    kind = record.get("kind")
    expected_keys = (
        _LIVE_HOLD_KEYS
        if kind == "live-session"
        else _ARCHIVE_HOLD_KEYS
        if kind == "archive-version"
        else None
    )
    if expected_keys is None or set(record) != expected_keys:
        raise ValueError("retention hold shape is invalid")
    for key in ("hold_id", "provider", "session_id", "reason", "created_at"):
        if type(record.get(key)) is not str:
            raise ValueError("retention hold field type is invalid")
    if not _HOLD_ID_PATTERN.fullmatch(record["hold_id"]):
        raise ValueError("retention hold id is invalid")
    if not record["session_id"] or "\0" in record["session_id"]:
        raise ValueError("retention hold session id is invalid")
    _hold_reason(record["reason"])
    try:
        parse_timestamp(record["created_at"])
    except ValueError as exc:
        raise ValueError("retention hold timestamp is invalid") from exc

    if kind == "live-session":
        session_id = normalize_session_id(record["session_id"])
        if (
            record["provider"] != OBSERVER_PROVIDER
            or session_id != record["session_id"]
        ):
            raise ValueError("live-session hold identity is invalid")
        identity = session_id
    else:
        provider = record["provider"]
        if provider not in {*TRAINABLE_PROVIDERS, OBSERVER_PROVIDER}:
            raise ValueError("archive-version hold provider is invalid")
        for key in ("session_key", "archive_id", "manifest"):
            if (
                type(record.get(key)) is not str
                or not record[key]
                or "\0" in record[key]
            ):
                raise ValueError("archive-version hold identity is invalid")
        if (
            not _SESSION_KEY_PATTERN.fullmatch(record["session_key"])
            or type(record.get("version")) is not int
            or record["version"] < 0
        ):
            raise ValueError("archive-version hold identity is invalid")
        archive_id = record["archive_id"]
        version_match = re.fullmatch(
            rf"{record['session_key']}-v(?P<version>[0-9]{{16}})-[0-9a-f]{{32}}",
            archive_id,
        )
        if (archive_id == record["session_key"] and record["version"] != 0) or (
            archive_id != record["session_key"]
            and (
                version_match is None
                or int(version_match.group("version")) != record["version"]
            )
        ):
            raise ValueError("archive-version hold identity is invalid")
        relative = Path(record["manifest"])
        if relative.parts != (
            "manifests",
            provider,
            f"{record['archive_id']}.json",
        ):
            raise ValueError("archive-version hold manifest path is invalid")
        identity = archive_id
    if record["hold_id"] != _hold_id(kind, record["provider"], identity):
        raise ValueError("retention hold id does not match its identity")
    return record


def _hold_state_path(paths: AppPaths) -> Path:
    return paths.state / "holds.json"


def _load_holds_locked(paths: AppPaths) -> list[dict[str, Any]]:
    path = _hold_state_path(paths)
    if not path.exists() and not path.is_symlink():
        return []
    info = path.lstat()
    if (
        not stat_module.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or (os.name != "nt" and stat_module.S_IMODE(info.st_mode) != 0o600)
        or (os.name != "nt" and hasattr(os, "getuid") and info.st_uid != os.getuid())
    ):
        raise ValueError(f"retention hold state is not a private regular file: {path}")
    state = load_json(path)
    if (
        set(state) != _HOLD_STATE_KEYS
        or type(state.get("schema_version")) is not int
        or state["schema_version"] not in SUPPORTED_SCHEMA_VERSIONS
        or state.get("kind") != "retention-holds"
        or type(state.get("holds")) is not list
    ):
        raise ValueError("retention hold state is invalid")
    holds = [_validate_hold_record(record) for record in state["holds"]]
    ids = [record["hold_id"] for record in holds]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ValueError("retention hold state order or identity is invalid")
    return holds


def _write_holds_locked(paths: AppPaths, holds: list[dict[str, Any]]) -> None:
    atomic_json(
        _hold_state_path(paths),
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "retention-holds",
            "holds": sorted(holds, key=lambda record: record["hold_id"]),
        },
    )


def list_holds(paths: AppPaths) -> list[dict[str, Any]]:
    """Return the validated local retention holds."""

    with app_lock(paths):
        return [dict(record) for record in _load_holds_locked(paths)]


def pin_live_session(
    paths: AppPaths,
    runtime: ClaudeMemPaths,
    session_id: str,
    reason: str,
) -> dict[str, Any]:
    """Protect one current observer session from observer cleanup."""

    normalized = normalize_session_id(session_id) if type(session_id) is str else None
    if normalized is None:
        raise ValueError("live-session hold session id is invalid")
    reason = _hold_reason(reason)
    with app_lock(paths):
        _safe_directory_identity(runtime.observer_project)
        regular_file_stat(runtime.observer_project / f"{normalized}.jsonl")
        holds = _load_holds_locked(paths)
        hold_id = _hold_id("live-session", OBSERVER_PROVIDER, normalized)
        prior = next((record for record in holds if record["hold_id"] == hold_id), None)
        record = {
            "hold_id": hold_id,
            "kind": "live-session",
            "provider": OBSERVER_PROVIDER,
            "session_id": normalized,
            "reason": reason,
            "created_at": prior["created_at"] if prior else iso_utc(utc_now()),
        }
        holds = [item for item in holds if item["hold_id"] != hold_id]
        holds.append(record)
        _write_holds_locked(paths, holds)
        return dict(record)


def pin_archive_version(
    paths: AppPaths, manifest_path: Path, reason: str
) -> dict[str, Any]:
    """Protect one exact immutable archive manifest and its reachable objects."""

    if not isinstance(manifest_path, Path):
        raise ValueError("archive-version hold manifest path is invalid")
    reason = _hold_reason(reason)
    with app_lock(paths):
        record = _manifest_record(paths, manifest_path)
        manifest = validate_manifest(manifest_path)
        session_key = record["session_key"]
        archive_id = manifest["archive_id"]
        if session_key is None or manifest_path != (
            paths.archive / "manifests" / manifest["provider"] / f"{archive_id}.json"
        ):
            raise ValueError("archive-version hold manifest identity is invalid")
        hold_id = _hold_id("archive-version", manifest["provider"], archive_id)
        holds = _load_holds_locked(paths)
        prior = next((item for item in holds if item["hold_id"] == hold_id), None)
        hold = {
            "hold_id": hold_id,
            "kind": "archive-version",
            "provider": manifest["provider"],
            "session_id": manifest["session_id"],
            "session_key": session_key,
            "version": _manifest_version(manifest),
            "archive_id": archive_id,
            "manifest": str(manifest_path.relative_to(paths.archive)),
            "reason": reason,
            "created_at": prior["created_at"] if prior else iso_utc(utc_now()),
        }
        holds = [item for item in holds if item["hold_id"] != hold_id]
        holds.append(hold)
        _write_holds_locked(paths, holds)
        return dict(hold)


def remove_hold(paths: AppPaths, hold_id: str) -> dict[str, Any]:
    """Remove one validated local hold by its stable id."""

    if type(hold_id) is not str or not _HOLD_ID_PATTERN.fullmatch(hold_id):
        raise ValueError("retention hold id is invalid")
    with app_lock(paths):
        holds = _load_holds_locked(paths)
        removed = next(
            (record for record in holds if record["hold_id"] == hold_id), None
        )
        if removed is None:
            raise ValueError(f"retention hold does not exist: {hold_id}")
        _write_holds_locked(
            paths, [record for record in holds if record["hold_id"] != hold_id]
        )
        return dict(removed)


def _live_hold_ids(holds: list[dict[str, Any]]) -> set[str]:
    return {
        record["session_id"] for record in holds if record["kind"] == "live-session"
    }


def _held_archive_paths(paths: AppPaths, holds: list[dict[str, Any]]) -> set[str]:
    held = set()
    for record in holds:
        if record["kind"] != "archive-version":
            continue
        path = paths.archive / record["manifest"]
        if not path.exists() and not path.is_symlink():
            continue
        manifest_record = _manifest_record(paths, path)
        manifest = validate_manifest(path)
        if (
            manifest_record["session_key"] != record["session_key"]
            or manifest["provider"] != record["provider"]
            or manifest["session_id"] != record["session_id"]
            or manifest["archive_id"] != record["archive_id"]
            or _manifest_version(manifest) != record["version"]
        ):
            raise ValueError("archive-version hold target identity is invalid")
        held.add(str(path))
    return held


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
                raise RuntimeError(
                    "claude-mem database has no sdk_sessions.memory_session_id column"
                )
            references: set[str] = set()
            for (value,) in connection.execute(
                "SELECT memory_session_id FROM sdk_sessions WHERE memory_session_id IS NOT NULL"
            ):
                if not isinstance(value, str) or not value.strip():
                    raise RuntimeError(
                        "claude-mem database contains an invalid memory_session_id"
                    )
                references.add(value.strip().lower())
            return references
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise RuntimeError(
            f"cannot read claude-mem references: {database}: {exc}"
        ) from exc


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
        raise RuntimeError(
            f"claude-mem database is missing or unsafe: {runtime.database}"
        )
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
                "SELECT 1 FROM sdk_sessions WHERE LOWER(memory_session_id) = ? LIMIT 1",
                (session_id,),
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
            raise RuntimeError(
                f"observer directory ancestor is unavailable: {current}: {exc}"
            ) from exc
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
    held_sessions = _live_hold_ids(list_holds(paths))
    observer = runtime.observer_project
    candidates: list[dict[str, Any]] = []
    eligible: list[dict[str, Any]] = []
    protected = Counter()
    logical_bytes = 0
    observer_identity: dict[str, int] | None = None

    if _regular_directory_chain_exists(observer):
        observer_identity = _safe_directory_identity(observer)
        cutoff_ns = int(
            (current - timedelta(seconds=grace_seconds)).timestamp() * 1_000_000_000
        )
        for source in sorted(observer.glob("*.jsonl")):
            try:
                regular_file_stat(source)
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
            if session_id in held_sessions:
                protected["held"] += 1
                continue
            try:
                scanned_files, directories = _scan_session_bundle(observer, source)
            except (OSError, ValueError):
                protected["unsafe_bundle"] += 1
                continue
            files = scanned_files
            latest_mtime_ns = max(item["mtime_ns"] for item in [*files, *directories])
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

    run_id = new_run_id(current)
    plan = {
        "schema_version": SCHEMA_VERSION,
        "kind": "observer-gc-plan",
        "run_id": run_id,
        "created_at": iso_utc(current),
        "expires_at": iso_utc(max(current, utc_now()) + timedelta(hours=2)),
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
    prune_expired_plans(paths)
    atomic_json(plan_path, plan, replace=False)
    return plan_path, plan


def _validate_observer_plan(plan: dict[str, Any], runtime: ClaudeMemPaths) -> None:
    if (
        plan.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS
        or plan.get("kind") != "observer-gc-plan"
    ):
        raise ValueError("unsupported observer GC plan")
    if not isinstance(plan.get("run_id"), str) or not isinstance(
        plan.get("expires_at"), str
    ):
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
            raise RuntimeError(
                f"observer GC plan {key} does not match the active runtime"
            )
    grace_seconds = plan.get("grace_seconds")
    if not isinstance(grace_seconds, int):
        raise ValueError("observer GC plan grace is invalid")
    _validate_grace(grace_seconds)
    candidates = plan.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("observer GC plan candidates must be a list")
    identity = plan.get("observer_project_identity")
    if candidates:
        if not isinstance(identity, dict):
            raise ValueError(
                "observer GC plan has candidates without a directory identity"
            )
        if any(not isinstance(identity.get(key), int) for key in ("device", "inode")):
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
                raise ValueError(
                    "observer companion file escaped its exact sibling directory"
                )
        for path in companion_directories:
            if not path.is_relative_to(companion):
                raise ValueError(
                    "observer companion directory escaped its exact sibling directory"
                )
        if companion_files or companion_directories:
            if companion not in companion_directories:
                raise ValueError(
                    "observer companion plan is missing its root directory"
                )
            for path in [*companion_files, *companion_directories]:
                parent = path.parent
                while parent != companion.parent:
                    if parent not in companion_directories:
                        raise ValueError(
                            "observer companion plan is missing a parent directory"
                        )
                    if parent == companion:
                        break
                    parent = parent.parent


def _candidate_source(
    session: dict[str, Any], observer: Path
) -> tuple[Path, dict[str, Any]]:
    validate_planned_session(session)
    if session.get("provider") != OBSERVER_PROVIDER or session.get(
        "source_root"
    ) != str(observer):
        raise ValueError("observer GC candidate escaped its provider or source root")
    files = session.get("files")
    if not isinstance(files, list) or not files or not isinstance(files[0], dict):
        raise ValueError("observer GC candidate must contain a primary file")
    member = files[0]
    source = Path(member["path"])
    if (
        source.parent != observer
        or source.suffix != ".jsonl"
        or member.get("relative") != source.name
    ):
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
        scanned_files, actual_directories = _scan_session_bundle(observer, source)
        actual_files = scanned_files[1:]
    except (OSError, ValueError) as exc:
        raise CandidateProtected(f"unsafe bundle: {exc}") from exc
    planned_files = {item["path"]: item for item in session["files"][1:]}
    planned_directories = {
        item["path"]: item for item in session.get("directories", [])
    }
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
    held: set[str],
    opened: set[Path],
) -> None:
    _assert_candidate_age_and_identity(runtime, plan, session)
    if session["session_id"] in keep:
        raise CandidateProtected("newly referenced")
    if session["session_id"] in held:
        raise CandidateProtected("held")
    if any_open(_candidate_paths(session), opened):
        raise CandidateProtected("open")


def _assert_candidate_final(
    paths: AppPaths,
    runtime: ClaudeMemPaths,
    plan: dict[str, Any],
    session: dict[str, Any],
) -> None:
    _assert_candidate_age_and_identity(runtime, plan, session)
    opened = open_file_paths_for(_candidate_paths(session))
    if any_open(_candidate_paths(session), opened):
        raise CandidateProtected("open")
    if session["session_id"] in _live_hold_ids(_load_holds_locked(paths)):
        raise CandidateProtected("held")
    # Keep this authoritative targeted read last: the archive transaction calls
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
    held = _live_hold_ids(_load_holds_locked(paths))

    zstd = _zstd_binary()
    quarantine_run = paths.state / "quarantine" / plan["run_id"]
    dictionary = load_provider_dictionary(paths, OBSERVER_PROVIDER)
    archived: list[str] = []
    skipped: list[dict[str, str]] = []
    results: list[dict[str, Any]] = []
    history_sources: dict[str, int] = {}
    history_cas_objects: dict[str, int] = {}
    cas_before = _cas_inventory(paths)
    free_bytes_before = shutil.disk_usage(paths.archive).free
    keep, reference_counts = read_keep_set(runtime)
    opened = open_file_paths_for(
        path for session in plan["candidates"] for path in _candidate_paths(session)
    )

    for session in plan["candidates"]:
        session_id = str(session.get("session_id", "<unknown>"))
        try:
            _assert_candidate_cached(runtime, plan, session, keep, held, opened)

            def before_move() -> None:
                _assert_candidate_final(paths, runtime, plan, session)

            result = _archive_planned_session_locked(
                paths,
                session,
                zstd=zstd,
                quarantine_run=quarantine_run,
                before_move=before_move,
                dictionary=dictionary,
            )
            results.append(result)
            archived.append(result["manifest"])
            history_sources[
                f"{session['provider']}\0{_manifest_key(session)}"
            ] = result["raw_bytes"]
            for item in result["_cas_objects"]:
                relative = item["path"]
                history_cas_objects[relative] = safe_cas_object_path(
                    paths.archive,
                    relative,
                    kind="zstd",
                    content_validation=encryption_config(paths) is None,
                ).stat(follow_symlinks=False).st_size
            for relative in result["_dictionary_objects"]:
                history_cas_objects[relative] = safe_cas_object_path(
                    paths.archive, relative, kind="dictionary"
                ).stat(follow_symlinks=False).st_size
        except (CandidateProtected, SourceChangedError, FileNotFoundError) as exc:
            skipped.append(
                {"session_id": session_id, "reason": str(exc) or exc.__class__.__name__}
            )

    if quarantine_run.exists() and not any(quarantine_run.iterdir()):
        quarantine_run.rmdir()
    return {
        "archived": len(archived),
        "manifests": archived,
        **_archive_metrics(paths, results, cas_before, free_bytes_before),
        "skipped": skipped,
        "reference_counts": reference_counts,
        "_history_sources": history_sources,
        "_history_cas_objects": history_cas_objects,
    }


def apply_observer_gc_plan(
    paths: AppPaths,
    runtime: ClaudeMemPaths,
    plan_path: Path,
) -> dict[str, Any]:
    with app_lock(paths):
        result = _apply_observer_gc_plan_locked(paths, runtime, plan_path)
        sources = result.pop("_history_sources")
        cas_objects = result.pop("_history_cas_objects")
        if result["archived"] == 0:
            return result
        return record_history_after_success(
            paths,
            result,
            operation="observer-gc",
            provider=OBSERVER_PROVIDER,
            logical_archived_bytes=result["logical_raw_bytes"],
            physical_allocated_bytes_delta=result["cas_allocated_bytes_change"],
            observed_free_bytes_delta=result["filesystem_free_bytes_change"],
            cas_objects=cas_objects,
            sources=sources,
        )


def _object_path(paths: AppPaths, value: Any, *, kind: CasObjectKind) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("archive manifest has an invalid object path")
    return safe_cas_object_path(
        paths.archive,
        value,
        kind=kind,
        content_validation=(kind != "zstd" or encryption_config(paths) is None),
    )


def _manifest_record(paths: AppPaths, manifest_path: Path) -> dict[str, Any]:
    stat = regular_file_stat(manifest_path)
    manifest = validate_manifest(manifest_path)
    provider = manifest["provider"]
    manifests_root = paths.archive / "manifests"
    try:
        relative_manifest = manifest_path.relative_to(manifests_root)
    except ValueError as exc:
        raise ValueError(f"archive manifest escaped its root: {manifest_path}") from exc
    if len(relative_manifest.parts) < 2 or relative_manifest.parts[0] != provider:
        raise ValueError(f"archive manifest provider path mismatch: {manifest_path}")
    parsed_at = parse_timestamp(manifest["archived_at"])
    files = manifest["files"]
    try:
        session_key = _manifest_session_key(manifest)
    except ValueError:
        session_key = None
    objects: set[str] = set()
    for member in files:
        chunks = member.get("chunks")
        if chunks is not None:
            for chunk in chunks:
                chunk_path = _object_path(
                    paths,
                    _chunk_object_relative(chunk.get("sha256")),
                    kind="zstd",
                )
                objects.add(str(chunk_path.relative_to(paths.archive)))
        else:
            object_path = _object_path(paths, member.get("object"), kind="zstd")
            objects.add(str(object_path.relative_to(paths.archive)))
        dictionary = member.get("dictionary")
        if dictionary is not None:
            dictionary_path = _object_path(paths, dictionary, kind="dictionary")
            objects.add(str(dictionary_path.relative_to(paths.archive)))
    return {
        "path": str(manifest_path),
        "provider": provider,
        "session_key": session_key,
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
        value: safe_cas_object_path(
            paths.archive,
            value,
            kind=cas_object_name_details(Path(value).name)[0],
            content_validation=(
                cas_object_name_details(Path(value).name)[0] != "zstd"
                or encryption_config(paths) is None
            ),
        )
        .stat(follow_symlinks=False)
        .st_size
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
            raise RuntimeError(
                f"archive CAS shard is unsafe: {shard_entry}: {exc}"
            ) from exc
        for path in sorted(shard.iterdir()):
            relative = str(path.relative_to(paths.archive))
            if relative in reachable:
                continue
            details = cas_object_name_details(path.name)
            if details is None:
                continue
            # Writers and this sweep share the app lock, so a recognized
            # compression temp is provably a crash remnant, never in flight.
            try:
                safe_cas_object_path(
                    paths.archive,
                    relative,
                    kind=details[0],
                    content_validation=(
                        details[0] != "zstd" or encryption_config(paths) is None
                    ),
                )
            except ValueError as exc:
                raise RuntimeError(
                    f"archive CAS object is unsafe: {path}: {exc}"
                ) from exc
            candidates.append(relative)
    return candidates


def _active_dictionary_objects(paths: AppPaths) -> set[str]:
    active = set()
    for provider in (*TRAINABLE_PROVIDERS, OBSERVER_PROVIDER):
        dictionary = load_provider_dictionary(paths, provider, warn=False)
        if dictionary is not None:
            active.add(str(dictionary.relative_to(paths.archive)))
    return active


def _build_expiry_plan_locked(
    paths: AppPaths,
    *,
    provider: str,
    kind: str,
    prefix: str,
    ttl_days: int,
    cap_bytes: int,
    current: datetime,
) -> tuple[Path, dict[str, Any]]:
    records = _all_manifest_records(paths)
    held_paths = _held_archive_paths(paths, _load_holds_locked(paths))
    sizes = _object_sizes(paths, records)
    selected_provider = [record for record in records if record["provider"] == provider]
    selected: dict[str, set[str]] = {}
    cutoff = current - timedelta(days=ttl_days)

    for record in selected_provider:
        if record["path"] not in held_paths and record["archived_at_value"] <= cutoff:
            selected.setdefault(record["path"], set()).add("ttl")

    remaining = [
        record for record in selected_provider if record["path"] not in selected
    ]
    remaining_counts = Counter(
        value for record in remaining for value in record["objects"]
    )
    remaining_bytes = sum(sizes[value] for value in remaining_counts)
    ordered_remaining = sorted(
        (record for record in remaining if record["path"] not in held_paths),
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
    selected_records = [
        record for record in selected_provider if record["path"] in selected
    ]
    selected_paths = set(selected)
    reachable_after = {
        value
        for record in records
        if record["path"] not in selected_paths
        for value in record["objects"]
    } | _active_dictionary_objects(paths)
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
        details = cas_object_name_details(Path(value).name)
        if details is None:
            raise ValueError(f"archive CAS object name is invalid: {value}")
        object_path = _object_path(paths, value, kind=details[0])
        cas_candidates.append(
            {
                "path": str(object_path),
                "relative": value,
                **regular_file_stat(object_path),
            }
        )

    run_id = new_run_id(current)
    manifest_entries = [
        {
            key: value
            for key, value in record.items()
            if key not in {"archived_at_value", "provider"}
        }
        | {"reasons": sorted(selected[record["path"]])}
        for record in selected_records
    ]
    bytes_before = sum(
        sizes[value]
        for value in {
            value for record in selected_provider for value in record["objects"]
        }
    )
    plan = {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "run_id": run_id,
        "created_at": iso_utc(current),
        "expires_at": iso_utc(max(current, utc_now()) + timedelta(hours=2)),
        "provider": provider,
        "ttl_days": ttl_days,
        "cap_bytes": cap_bytes,
        "archive_bytes_before": bytes_before,
        "archive_bytes_after": remaining_bytes,
        "observer_bytes_before": bytes_before,
        "observer_bytes_after": remaining_bytes,
        "manifests": manifest_entries,
        "cas_candidates": cas_candidates,
    }
    if records != _all_manifest_records(paths):
        raise RuntimeError("archive manifests changed during expiry planning")
    digest = _expiry_plan_digest(plan)
    plan_path = paths.state / "plans" / f"{prefix}-{run_id}-{digest}.json"
    return plan_path, plan


def create_observer_expiry_plan(
    paths: AppPaths,
    *,
    ttl_days: int = DEFAULT_ARCHIVE_TTL_DAYS,
    cap_bytes: int = DEFAULT_ARCHIVE_CAP_BYTES,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any]]:
    paths.ensure_private()
    _validate_expiry_policy(ttl_days, cap_bytes)
    current = (now or utc_now()).astimezone(UTC)
    with app_lock(paths):
        plan_path, plan = _build_expiry_plan_locked(
            paths,
            provider=OBSERVER_PROVIDER,
            kind="observer-expiry-plan",
            prefix="observer-expiry",
            ttl_days=ttl_days,
            cap_bytes=cap_bytes,
            current=current,
        )
        _prune_expired_plans_locked(paths, keep=32)
        atomic_json(plan_path, plan, replace=False)
    return plan_path, plan


def create_archive_expiry_plan(
    paths: AppPaths,
    provider: str,
    *,
    ttl_days: int = DEFAULT_ARCHIVE_TTL_DAYS,
    cap_bytes: int = DEFAULT_ARCHIVE_CAP_BYTES,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any]]:
    paths.ensure_private()
    if provider not in TRAINABLE_PROVIDERS:
        raise ValueError(f"unsupported archive expiry provider: {provider}")
    _validate_expiry_policy(ttl_days, cap_bytes)
    current = (now or utc_now()).astimezone(UTC)
    with app_lock(paths):
        plan_path, plan = _build_expiry_plan_locked(
            paths,
            provider=provider,
            kind="archive-expiry-plan",
            prefix=f"archive-expiry-{provider}",
            ttl_days=ttl_days,
            cap_bytes=cap_bytes,
            current=current,
        )
        _prune_expired_plans_locked(paths, keep=32)
        atomic_json(plan_path, plan, replace=False)
    return plan_path, plan


def _validate_expiry_plan_structure(paths: AppPaths, plan: dict[str, Any]) -> None:
    kind = plan.get("kind")
    provider = plan.get("provider")
    valid_provider = (
        kind == "observer-expiry-plan" and provider == OBSERVER_PROVIDER
    ) or (kind == "archive-expiry-plan" and provider in TRAINABLE_PROVIDERS)
    if (
        type(plan.get("schema_version")) is not int
        or plan["schema_version"] not in SUPPORTED_SCHEMA_VERSIONS
        or not valid_provider
    ):
        raise ValueError("unsupported archive expiry plan")
    if (
        type(plan.get("run_id")) is not str
        or type(plan.get("created_at")) is not str
        or type(plan.get("expires_at")) is not str
    ):
        raise ValueError("observer archive expiry metadata is invalid")
    try:
        created_at = parse_timestamp(plan["created_at"])
        expires_at = parse_timestamp(plan["expires_at"])
    except (TypeError, ValueError) as exc:
        raise ValueError("observer archive expiry timestamps are invalid") from exc
    if created_at > expires_at:
        raise ValueError("observer archive expiry timestamps are reversed")
    _validate_expiry_policy(plan.get("ttl_days"), plan.get("cap_bytes"))
    manifests = plan.get("manifests")
    cas_candidates = plan.get("cas_candidates")
    if not isinstance(manifests, list) or not isinstance(cas_candidates, list):
        raise ValueError("observer archive expiry entries must be lists")
    manifest_root = paths.archive / "manifests" / provider
    seen: set[Path] = set()
    for item in manifests:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("observer archive expiry manifest entry is invalid")
        path = Path(item["path"])
        if path.parent != manifest_root or path.suffix != ".json" or path in seen:
            raise ValueError("observer archive expiry manifest path is invalid")
        seen.add(path)
        reasons = item.get("reasons")
        if (
            type(reasons) is not list
            or not reasons
            or any(type(reason) is not str for reason in reasons)
            or reasons != sorted(set(reasons))
            or not set(reasons) <= {"cap", "ttl"}
        ):
            raise ValueError("observer archive expiry reasons are invalid")
        session_key = item.get("session_key")
        if session_key is not None and (
            not isinstance(session_key, str)
            or not re.fullmatch(r"[0-9a-f]{20}", session_key)
        ):
            raise ValueError("observer archive expiry session key is invalid")
        if any(
            type(item.get(key)) is not int
            for key in ("device", "inode", "size", "mtime_ns")
        ):
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
        if any(
            type(item.get(key)) is not int
            for key in ("device", "inode", "size", "mtime_ns")
        ):
            raise ValueError("observer archive expiry CAS identity is invalid")
        details = cas_object_name_details(relative.name)
        if details is None:
            raise ValueError("observer archive expiry CAS path is invalid")
        canonical = _object_path(paths, item["relative"], kind=details[0])
        if canonical != path:
            raise ValueError("observer archive expiry CAS path is invalid")


def _apply_expiry_plan_locked(
    paths: AppPaths, plan_path: Path, *, expected_kind: str
) -> dict[str, Any]:
    if plan_path.parent != paths.state / "plans":
        raise ValueError("archive expiry plan escaped the plans root")
    regular_file_stat(plan_path)
    plan = load_json(plan_path)
    _validate_expiry_plan_structure(paths, plan)
    if plan["kind"] != expected_kind:
        raise ValueError(f"unsupported expiry plan kind: {plan['kind']}")
    if utc_now() > parse_timestamp(plan["expires_at"]):
        raise RuntimeError("observer archive expiry plan expired")

    prefix = (
        "observer-expiry"
        if expected_kind == "observer-expiry-plan"
        else f"archive-expiry-{plan['provider']}"
    )
    digest = _expiry_plan_digest(plan)
    if plan_path.name != f"{prefix}-{plan['run_id']}-{digest}.json":
        raise ValueError("archive expiry plan name does not match its identity")
    _, current_plan = _build_expiry_plan_locked(
        paths,
        provider=plan["provider"],
        kind=expected_kind,
        prefix=prefix,
        ttl_days=plan["ttl_days"],
        cap_bytes=plan["cap_bytes"],
        current=parse_timestamp(plan["created_at"]),
    )
    planned_selection = {
        (item["path"], tuple(item["reasons"])) for item in plan["manifests"]
    }
    current_selection = {
        (item["path"], tuple(item["reasons"])) for item in current_plan["manifests"]
    }
    if planned_selection != current_selection:
        raise RuntimeError("archive expiry eligibility changed after planning")

    for parent in {Path(item["path"]).parent for item in plan["manifests"]}:
        fsync_dir(parent)
    # Validate the complete manifest graph before changing it.  A malformed
    # unrelated provider could otherwise make a shared CAS object appear dead.
    records = _all_manifest_records(paths)
    by_path = {record["path"]: record for record in records}
    logical_bytes_by_path = {
        record["path"]: sum(
            item["size"] for item in validate_manifest(Path(record["path"]))["files"]
        )
        for record in records
    }
    reference_counts = Counter(
        value for record in records for value in record["objects"]
    )
    reference_counts.update(_active_dictionary_objects(paths))
    removed: list[str] = []
    free_bytes_before = shutil.disk_usage(paths.archive).free
    skipped: list[dict[str, str]] = []
    for item in plan["manifests"]:
        path = Path(item["path"])
        current = by_path.get(str(path))
        if current is None or current["provider"] != plan["provider"]:
            skipped.append({"path": str(path), "reason": "missing or provider drift"})
            continue
        if not identity_matches(path, item):
            skipped.append({"path": str(path), "reason": "identity drift"})
            continue
        try:
            path.unlink()
        except OSError as exc:
            skipped.append(
                {"path": str(path), "reason": f"{exc.__class__.__name__}: {exc}"}
            )
            continue
        fsync_dir(path.parent)
        removed.append(str(path))
        for value in current["objects"]:
            reference_counts[value] -= 1
            if reference_counts[value] == 0:
                del reference_counts[value]

    _refresh_latest_indexes(
        paths,
        plan["provider"],
        {
            item["session_key"]
            for item in plan["manifests"]
            if item["session_key"] is not None
        },
    )

    objects_removed: list[str] = []
    removed_allocated_bytes = 0
    for item in plan["cas_candidates"]:
        path = Path(item["path"])
        relative = item["relative"]
        try:
            details = cas_object_name_details(Path(relative).name)
            if details is None:
                raise ValueError("observer archive expiry CAS path is invalid")
            expected = _object_path(paths, relative, kind=details[0])
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
        info = path.stat(follow_symlinks=False)
        try:
            path.unlink()
        except OSError as exc:
            skipped.append(
                {"path": str(path), "reason": f"{exc.__class__.__name__}: {exc}"}
            )
            continue
        fsync_dir(path.parent)
        objects_removed.append(str(path))
        removed_allocated_bytes += info.st_blocks * 512

    for directory in sorted(
        {Path(path).parent for path in removed + objects_removed},
        key=lambda value: len(value.parts),
        reverse=True,
    ):
        try:
            directory.rmdir()
        except OSError:
            pass
    logical_reclaimed_bytes = sum(logical_bytes_by_path[path] for path in removed)
    return {
        "manifests_removed": len(removed),
        "objects_removed": len(objects_removed),
        "logical_reclaimed_bytes": logical_reclaimed_bytes,
        "physical_allocated_bytes_change": -removed_allocated_bytes,
        "filesystem_free_bytes_change": (
            shutil.disk_usage(paths.archive).free - free_bytes_before
        ),
        "removed": removed,
        "skipped": skipped,
        "_history_provider": plan["provider"],
    }


def _apply_observer_expiry_plan_locked(
    paths: AppPaths, plan_path: Path
) -> dict[str, Any]:
    return _apply_expiry_plan_locked(
        paths, plan_path, expected_kind="observer-expiry-plan"
    )


def apply_observer_expiry_plan(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    with app_lock(paths):
        result = _apply_observer_expiry_plan_locked(paths, plan_path)
        return _record_expiry_history(paths, result, operation="observer-expiry")


def apply_archive_expiry_plan(paths: AppPaths, plan_path: Path) -> dict[str, Any]:
    with app_lock(paths):
        result = _apply_expiry_plan_locked(
            paths, plan_path, expected_kind="archive-expiry-plan"
        )
        return _record_expiry_history(paths, result, operation="archive-expiry")


def _record_expiry_history(
    paths: AppPaths, result: dict[str, Any], *, operation: str
) -> dict[str, Any]:
    provider = result.pop("_history_provider", None)
    if provider is None or (
        result.get("manifests_removed", 0) == 0
        and result.get("objects_removed", 0) == 0
    ):
        return result
    return record_history_after_success(
        paths,
        result,
        operation=operation,
        provider=provider,
        logical_reclaimed_bytes_delta=result["logical_reclaimed_bytes"],
        physical_allocated_bytes_delta=result["physical_allocated_bytes_change"],
        observed_free_bytes_delta=result["filesystem_free_bytes_change"],
    )
