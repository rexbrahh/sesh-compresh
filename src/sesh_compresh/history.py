from __future__ import annotations

import hashlib
import json
import errno
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from .common import (
    AppPaths,
    app_lock,
    atomic_json,
    ensure_private_subdirectory,
    iso_utc,
    new_run_id,
    parse_timestamp,
    utc_now,
    validate_run_id,
)


HISTORY_SCHEMA_VERSION = 1
HISTORY_OPERATIONS = frozenset(
    {
        "archive-apply",
        "archive-direct",
        "archive-expiry",
        "clean-apply",
        "clean-expiry",
        "clean-undo",
        "dictionary-train",
        "observer-expiry",
        "observer-gc",
        "archive-repack",
    }
)
_EVENT_KEYS = {
    "schema_version",
    "kind",
    "event_id",
    "recorded_at",
    "operation",
    "provider",
    "logical_archived_bytes",
    "logical_reclaimed_bytes_delta",
    "physical_allocated_bytes_delta",
    "observed_free_bytes_delta",
    "cas_objects",
    "sources",
}
_HASH = re.compile(r"^[0-9a-f]{64}$")
_PROVIDER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_HISTORY_KIND = "maintenance-history"
_MAX_EVENT_BYTES = 1024 * 1024
_ARCHIVE_OPERATIONS = {"archive-apply", "archive-direct", "observer-gc"}
_RECORD_ERRORS = (OSError, UnicodeError, ValueError, RuntimeError)


def _private_history_root(paths: AppPaths) -> Path:
    paths.ensure_private()
    return ensure_private_subdirectory(paths.state, "history")


def _opaque_id(domain: str, value: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"history {domain} identity is invalid")
    encoded = f"sesh-compresh {domain} v1\0{value}".encode()
    return hashlib.sha256(encoded).hexdigest()


def source_id(value: str) -> str:
    """Return a stable opaque identifier without storing the source value."""

    return _opaque_id("source", value)


def cas_id(value: str) -> str:
    """Return a stable opaque identifier without storing the CAS path."""

    return _opaque_id("cas", value)


def _hashed_sizes(domain: str, values: Mapping[str, int]) -> list[dict[str, Any]]:
    merged: dict[str, int] = {}
    for identity, size in values.items():
        if type(identity) is not str or not identity or type(size) is not int or size < 0:
            raise ValueError(f"history {domain} entry is invalid")
        opaque = _opaque_id(domain, identity)
        previous = merged.setdefault(opaque, size)
        if previous != size:
            raise ValueError(f"history {domain} identity has conflicting sizes")
    return [
        {"id": opaque, "bytes": size}
        for opaque, size in sorted(merged.items())
    ]


def append_history_event(
    paths: AppPaths,
    *,
    operation: str,
    provider: str | None = None,
    logical_archived_bytes: int = 0,
    logical_reclaimed_bytes_delta: int = 0,
    physical_allocated_bytes_delta: int = 0,
    observed_free_bytes_delta: int = 0,
    cas_objects: Mapping[str, int] | None = None,
    sources: Mapping[str, int] | None = None,
) -> Path:
    """Append one immutable event.

    Call this after a primitive mutation succeeds. The function does not take
    the application lock, so callers that already hold it cannot deadlock.
    """

    if operation not in HISTORY_OPERATIONS:
        raise ValueError(f"unsupported history operation: {operation}")
    if provider is not None and (
        type(provider) is not str or _PROVIDER.fullmatch(provider) is None
    ):
        raise ValueError("history provider is invalid")
    metrics = {
        "logical_archived_bytes": logical_archived_bytes,
        "logical_reclaimed_bytes_delta": logical_reclaimed_bytes_delta,
        "physical_allocated_bytes_delta": physical_allocated_bytes_delta,
        "observed_free_bytes_delta": observed_free_bytes_delta,
    }
    if any(type(value) is not int for value in metrics.values()):
        raise ValueError("history metrics must be integers")
    if logical_archived_bytes < 0:
        raise ValueError("history logical archived bytes must be non-negative")

    current = utc_now()
    event_id = new_run_id(current)
    event = {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "kind": _HISTORY_KIND,
        "event_id": event_id,
        "recorded_at": iso_utc(current),
        "operation": operation,
        "provider": provider,
        **metrics,
        "cas_objects": _hashed_sizes("cas", cas_objects or {}),
        "sources": _hashed_sizes("source", sources or {}),
    }
    root = _private_history_root(paths)
    path = root / f"{event_id}.json"
    atomic_json(path, event, replace=False)
    return path


def record_history_after_success(
    paths: AppPaths, result: dict[str, Any], **event: Any
) -> dict[str, Any]:
    """Record a completed primitive operation without changing its outcome."""

    try:
        append_history_event(paths, **event)
    except _RECORD_ERRORS:
        return {
            **result,
            "history_recorded": False,
            "history_warning": "maintenance history append failed",
        }
    return result


def _validate_sized_ids(value: Any, *, label: str) -> list[dict[str, Any]]:
    if type(value) is not list:
        raise ValueError(f"history {label} entries must be a list")
    previous = ""
    for item in value:
        if (
            type(item) is not dict
            or set(item) != {"id", "bytes"}
            or type(item.get("id")) is not str
            or _HASH.fullmatch(item["id"]) is None
            or type(item.get("bytes")) is not int
            or item["bytes"] < 0
            or item["id"] <= previous
        ):
            raise ValueError(f"history {label} entry is invalid")
        previous = item["id"]
    return value


def _validate_event(path: Path, event: dict[str, Any]) -> dict[str, Any]:
    if set(event) != _EVENT_KEYS:
        raise ValueError(f"history event shape is invalid: {path}")
    if (
        type(event["schema_version"]) is not int
        or event["schema_version"] != HISTORY_SCHEMA_VERSION
        or event["kind"] != _HISTORY_KIND
        or type(event["event_id"]) is not str
        or path.name != f"{event['event_id']}.json"
    ):
        raise ValueError(f"history event identity is invalid: {path}")
    validate_run_id(event["event_id"])
    if type(event["recorded_at"]) is not str:
        raise ValueError(f"history event timestamp is invalid: {path}")
    try:
        recorded_at = parse_timestamp(event["recorded_at"])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"history event timestamp is invalid: {path}") from exc
    if iso_utc(recorded_at) != event["recorded_at"]:
        raise ValueError(f"history event timestamp is not canonical UTC: {path}")
    event_time = datetime.strptime(
        event["event_id"].split("-", 1)[0], "%Y%m%dT%H%M%S.%fZ"
    ).replace(tzinfo=UTC)
    if event_time != recorded_at:
        raise ValueError(f"history event identity timestamp does not match: {path}")
    if event["operation"] not in HISTORY_OPERATIONS:
        raise ValueError(f"history event operation is invalid: {path}")
    provider = event["provider"]
    if provider is not None and (
        type(provider) is not str or _PROVIDER.fullmatch(provider) is None
    ):
        raise ValueError(f"history event provider is invalid: {path}")
    metric_names = (
        "logical_archived_bytes",
        "logical_reclaimed_bytes_delta",
        "physical_allocated_bytes_delta",
        "observed_free_bytes_delta",
    )
    if any(type(event[name]) is not int for name in metric_names):
        raise ValueError(f"history event metrics are invalid: {path}")
    if event["logical_archived_bytes"] < 0:
        raise ValueError(f"history event archived bytes are invalid: {path}")
    _validate_sized_ids(event["cas_objects"], label="CAS")
    _validate_sized_ids(event["sources"], label="source")
    return event


def _history_events_locked(paths: AppPaths) -> list[dict[str, Any]]:
    root = _private_history_root(paths)
    events = []
    with os.scandir(root) as entries:
        ordered = sorted(entries, key=lambda entry: entry.name)
    for entry in ordered:
        path = Path(entry.path)
        entry_info = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(entry_info.st_mode) or not stat.S_ISREG(entry_info.st_mode):
            raise ValueError(f"history entry is unsafe: {path}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ValueError(f"history entry is unsafe: {path}") from exc
            raise
        try:
            info = os.fstat(fd)
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or (info.st_dev, info.st_ino)
                != (entry_info.st_dev, entry_info.st_ino)
                or path.suffix != ".json"
                or info.st_size > _MAX_EVENT_BYTES
                or info.st_nlink != 1
                or (os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o600)
                or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            ):
                raise ValueError(f"history entry is unsafe: {path}")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                encoded = handle.read(_MAX_EVENT_BYTES + 1)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        if (
            len(encoded) != info.st_size
            or any(
                getattr(after, name) != getattr(info, name)
                for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns")
            )
        ):
            raise RuntimeError(f"history event changed while reading: {path}")
        try:
            value = json.loads(encoded.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"history event JSON is invalid: {path}") from exc
        if type(value) is not dict:
            raise ValueError(f"history event is not an object: {path}")
        events.append(_validate_event(path, value))
    return events


def _merge_identity_sizes(
    target: dict[str, int], entries: Iterable[dict[str, Any]], *, label: str
) -> None:
    for item in entries:
        previous = target.setdefault(item["id"], item["bytes"])
        if previous != item["bytes"]:
            raise ValueError(f"history {label} identity has conflicting sizes")


def history_summary(paths: AppPaths, *, top: int = 10) -> dict[str, Any]:
    if type(top) is not int or top < 0 or top > 1000:
        raise ValueError("history top count must be an integer from 0 through 1000")
    with app_lock(paths):
        events = _history_events_locked(paths)

    cas: dict[str, int] = {}
    source_initial: dict[tuple[str | None, str], int] = {}
    active_sources: dict[tuple[str | None, str], int] = {}
    trends: dict[tuple[str | None, str], dict[str, Any]] = {}
    totals = {
        "logical_archived_bytes": 0,
        "logical_reclaimed_bytes_delta": 0,
        "physical_allocated_bytes_delta": 0,
        "observed_free_bytes_delta": 0,
    }
    for event in events:
        _merge_identity_sizes(cas, event["cas_objects"], label="CAS")
        if event["operation"] in _ARCHIVE_OPERATIONS:
            for source in event["sources"]:
                source_key = (event["provider"], source["id"])
                source_initial.setdefault(source_key, source["bytes"])
                active_sources[source_key] = source["bytes"]
        date = event["recorded_at"][:10]
        key = (event["provider"], date)
        bucket = trends.setdefault(
            key,
            {
                "provider": event["provider"],
                "date": date,
                "events": 0,
                **{name: 0 for name in totals},
            },
        )
        bucket["events"] += 1
        for name in totals:
            totals[name] += event[name]
            bucket[name] += event[name]

    growth = []
    for (provider, opaque), latest in active_sources.items():
        growth.append(
            {
                "provider": provider,
                "source_id": opaque,
                "growth_bytes": latest - source_initial[(provider, opaque)],
                "latest_logical_bytes": latest,
            }
        )
    growth.sort(
        key=lambda item: (
            -item["growth_bytes"],
            str(item["provider"]),
            item["source_id"],
        )
    )
    unique_cas_bytes = sum(cas.values())
    latest_sources = sum(active_sources.values())
    return {
        "events": len(events),
        **totals,
        "unique_source_logical_bytes": latest_sources,
        "unique_cas_bytes": unique_cas_bytes,
        "unique_bytes_saved": latest_sources - unique_cas_bytes,
        "provider_utc_trends": [
            trends[key]
            for key in sorted(trends, key=lambda item: (item[1], item[0] or ""))
        ],
        "top_growth_sources": growth[:top],
    }
