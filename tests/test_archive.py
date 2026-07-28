from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import sesh_compresh.archive as archive_module
import sesh_compresh.common as common_module
from sesh_compresh.archive import (
    CHUNK_TARGET_BYTES,
    _chunk_records,
    _zstd_binary,
    apply_archive_plan,
    archive_planned_session,
    archive_stats,
    create_archive_plan,
    iter_manifests,
    load_provider_dictionary,
    recover_quarantine,
    restore_manifest,
    train_dictionary,
    verify_all,
)
from sesh_compresh.common import (
    AppPaths,
    atomic_json,
    regular_directory_stat,
    regular_file_stat,
    sha256_file,
    utc_now,
)
from sesh_compresh.observer import ClaudeMemPaths


class ArchiveRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.paths = AppPaths.discover(self.home)
        self.project = self.home / ".claude/projects/-fixture-project"
        self.project.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_session(self, name: str, timestamp: str = "2020-01-01T00:00:00Z") -> Path:
        path = self.project / f"{name}.jsonl"
        records = [
            {"type": "user", "timestamp": timestamp, "content": "repeat " * 5000},
            {"type": "assistant", "timestamp": timestamp, "content": "answer " * 5000},
            {"type": "summary", "sessionId": name},
        ]
        path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
        os.chmod(path, 0o640)
        return path

    def test_verified_round_trip_and_collision_refusal(self) -> None:
        source = self.write_session("session-a")
        original_hash = sha256_file(source)
        original_mode = source.stat().st_mode & 0o777
        original_mtime = source.stat().st_mtime_ns
        plan_path, plan = create_archive_plan(self.paths, utc_now())
        self.assertEqual(1, len(plan["sessions"]))

        result = apply_archive_plan(self.paths, plan_path)
        self.assertEqual(1, result["sessions"])
        self.assertEqual(1, result["manifest_count"])
        self.assertFalse(source.exists())
        self.assertEqual({"manifests": 1, "files": 1}, verify_all(self.paths))

        manifest = next(iter_manifests(self.paths))
        destination = self.home / "restore-canary"
        restored = restore_manifest(self.paths, str(manifest), destination)
        restored_path = destination / source.relative_to(self.project)
        self.assertEqual(1, restored["files"])
        self.assertEqual(original_hash, sha256_file(restored_path))
        self.assertEqual(original_mode, restored_path.stat().st_mode & 0o777)
        self.assertEqual(original_mtime, restored_path.stat().st_mtime_ns)
        with self.assertRaises(FileExistsError):
            restore_manifest(self.paths, str(manifest), destination)

    def test_recent_and_malformed_sessions_are_preserved(self) -> None:
        recent = self.write_session("recent", "2026-07-11T00:00:00Z")
        malformed = self.project / "bad.jsonl"
        malformed.write_text('{"timestamp":"2020-01-01T00:00:00Z"}\nnot-json\n', encoding="utf-8")
        _, plan = create_archive_plan(self.paths, datetime(2026, 7, 12, tzinfo=UTC))
        self.assertEqual([], plan["sessions"])
        self.assertTrue(recent.exists())
        self.assertTrue(malformed.exists())
        self.assertGreaterEqual(plan["skipped"].get("recent", 0), 1)

    def test_generic_archive_excludes_observer_sessions(self) -> None:
        observer = ClaudeMemPaths.discover(self.paths, environ={}).observer_project
        observer.mkdir(parents=True)
        source = observer / "12345678-1234-1234-1234-123456789abc.jsonl"
        source.write_text('{"timestamp":"2020-01-01T00:00:00Z"}\n', encoding="utf-8")

        _, plan = create_archive_plan(self.paths, utc_now())

        self.assertEqual([], plan["sessions"])
        self.assertTrue(source.exists())

    def test_malformed_later_plan_entry_causes_zero_mutation(self) -> None:
        first = self.write_session("session-first")
        second = self.write_session("session-second")
        plan_path, plan = create_archive_plan(self.paths, utc_now())
        plan["sessions"][1]["files"][0]["size"] = "invalid"
        atomic_json(plan_path, plan)

        with self.assertRaisesRegex(ValueError, "identity is invalid"):
            apply_archive_plan(self.paths, plan_path)

        self.assertTrue(first.exists())
        self.assertTrue(second.exists())
        self.assertEqual([], list((self.paths.archive / "manifests").rglob("*.json")))

    def test_recover_restores_quarantined_source(self) -> None:
        original_root = self.home / "source"
        relative = Path("nested/session.jsonl")
        quarantined = self.paths.state / "quarantine/run/item/files" / relative
        quarantined.parent.mkdir(parents=True)
        quarantined.write_text("payload", encoding="utf-8")
        atomic_json(
            self.paths.state / "quarantine/run/item/_restore.json",
            {
                "schema_version": 1,
                "source_root": str(original_root),
                "manifest": "unused",
                "files": [str(relative)],
            },
        )
        result = recover_quarantine(self.paths)
        self.assertEqual({"restored": 1, "conflicts": 0}, result)
        self.assertEqual("payload", (original_root / relative).read_text())

    def test_same_stem_codex_rollouts_get_distinct_manifests(self) -> None:
        root = self.home / ".codex/sessions"
        sources = []
        for day in ("2024/01/02", "2024/02/03"):
            directory = root / day
            directory.mkdir(parents=True)
            source = directory / "rollout-duplicate.jsonl"
            source.write_text(
                json.dumps(
                    {"type": "user", "timestamp": "2020-01-01T00:00:00Z", "content": day}
                )
                + "\n",
                encoding="utf-8",
            )
            sources.append(source)

        plan_path, plan = create_archive_plan(self.paths, utc_now())
        self.assertEqual(2, len(plan["sessions"]))
        result = apply_archive_plan(self.paths, plan_path)

        self.assertEqual(2, result["sessions"])
        self.assertEqual(2, len(list(iter_manifests(self.paths))))
        self.assertEqual({"manifests": 2, "files": 2}, verify_all(self.paths))
        for source in sources:
            self.assertFalse(source.exists())

    def test_manifest_records_zstd_version_and_empty_directories(self) -> None:
        self.write_session("versioned")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        apply_archive_plan(self.paths, plan_path)

        manifest = json.loads(next(iter_manifests(self.paths)).read_text(encoding="utf-8"))
        self.assertIsInstance(manifest["zstd_version"], str)
        self.assertTrue(manifest["zstd_version"])
        self.assertEqual([], manifest["directories"])

    def test_restore_recreates_bundle_directories_with_metadata(self) -> None:
        source = self.write_session("bundled")
        companion = self.project / "bundled"
        nested = companion / "notes"
        empty = nested / "empty"
        empty.mkdir(parents=True)
        fixed_mtime_ns = 1_600_000_000_123_456_789
        for directory in (companion, nested, empty):
            os.chmod(directory, 0o750)
            os.utime(directory, ns=(fixed_mtime_ns, fixed_mtime_ns))

        def directory_entry(path: Path) -> dict:
            return {
                "path": str(path),
                "relative": str(path.relative_to(self.project)),
                **regular_directory_stat(path),
            }

        session = {
            "provider": "claude",
            "session_id": f"{self.project.name}:bundled",
            "source_root": str(self.project),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {
                    "path": str(source),
                    "relative": source.name,
                    **regular_file_stat(source),
                }
            ],
            "directories": [directory_entry(path) for path in (companion, nested, empty)],
        }
        self.paths.ensure_private()
        result = archive_planned_session(
            self.paths,
            session,
            zstd=_zstd_binary(),
            quarantine_run=self.paths.state / "quarantine" / "bundle-test",
        )
        self.assertFalse(source.exists())
        self.assertFalse(companion.exists())
        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual(3, len(manifest["directories"]))

        destination = self.home / "restore-bundle"
        restored = restore_manifest(self.paths, result["manifest"], destination)

        self.assertEqual(1, restored["files"])
        self.assertEqual(3, restored["directories"])
        restored_dir = destination / "bundled"
        self.assertTrue((restored_dir / "notes/empty").is_dir())
        self.assertEqual(0o750, restored_dir.stat().st_mode & 0o777)
        self.assertEqual(fixed_mtime_ns, restored_dir.stat().st_mtime_ns)
        self.assertEqual(fixed_mtime_ns, (restored_dir / "notes/empty").stat().st_mtime_ns)

    def test_apply_fails_closed_when_lsof_is_unavailable(self) -> None:
        source = self.write_session("liveness")
        plan_path, _ = create_archive_plan(self.paths, utc_now())

        with mock.patch.object(common_module, "_lsof_binary", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "lsof was not found"):
                apply_archive_plan(self.paths, plan_path)

        self.assertTrue(source.exists())

    def archive_session(self, session: dict, run: str) -> dict:
        self.paths.ensure_private()
        return archive_planned_session(
            self.paths,
            session,
            zstd=_zstd_binary(),
            quarantine_run=self.paths.state / "quarantine" / run,
        )

    def bundle_session(self, name: str) -> dict:
        source = self.write_session(name)
        companion = self.project / name
        companion.mkdir()
        member = companion / "note.txt"
        member.write_text("companion", encoding="utf-8")
        return {
            "provider": "claude",
            "session_id": f"{self.project.name}:{name}",
            "source_root": str(self.project),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {"path": str(source), "relative": source.name, **regular_file_stat(source)},
                {
                    "path": str(member),
                    "relative": f"{name}/note.txt",
                    **regular_file_stat(member),
                },
            ],
            "directories": [
                {
                    "path": str(companion),
                    "relative": name,
                    **regular_directory_stat(companion),
                }
            ],
        }

    def test_restore_rejects_escaping_member_relative(self) -> None:
        self.write_session("escape")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        apply_archive_plan(self.paths, plan_path)
        manifest_path = next(iter_manifests(self.paths))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"][0]["relative"] = "../escape.jsonl"
        atomic_json(manifest_path, manifest)

        with self.assertRaisesRegex(ValueError, "escaped its root"):
            restore_manifest(self.paths, str(manifest_path), self.home / "restore-escape")

    def test_restore_preflights_collisions(self) -> None:
        result = self.archive_session(self.bundle_session("preflight"), "preflight-test")
        destination = self.home / "restore-preflight"
        blocking = destination / "preflight"
        blocking.mkdir(parents=True)
        (blocking / "note.txt").write_text("occupied", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            restore_manifest(self.paths, result["manifest"], destination)

        self.assertFalse((destination / "preflight.jsonl").exists())
        self.assertEqual("occupied", (blocking / "note.txt").read_text(encoding="utf-8"))

    def test_corrupt_dedup_object_is_repaired_from_source(self) -> None:
        payload = "".join(
            json.dumps({"type": "user", "timestamp": "2020-01-01T00:00:00Z", "content": "x" * 5000})
            + "\n"
            for _ in range(3)
        )
        (self.project / "dup-a.jsonl").write_text(payload, encoding="utf-8")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        apply_archive_plan(self.paths, plan_path)

        manifest = json.loads(next(iter_manifests(self.paths)).read_text(encoding="utf-8"))
        object_path = self.paths.archive / manifest["files"][0]["object"]
        object_path.write_bytes(b"corrupt")

        (self.project / "dup-b.jsonl").write_text(payload, encoding="utf-8")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        result = apply_archive_plan(self.paths, plan_path)

        self.assertEqual(1, result["sessions"])
        self.assertEqual({"manifests": 2, "files": 2}, verify_all(self.paths))
        self.assertEqual(1, len(list(object_path.parent.glob("*.corrupt-*"))))
        self.assertFalse((self.project / "dup-b.jsonl").exists())

    def test_recover_recreates_bundle_directories(self) -> None:
        original_root = self.home / "source"
        relative = Path("nested/session.jsonl")
        quarantined = self.paths.state / "quarantine/run/item/files" / relative
        quarantined.parent.mkdir(parents=True)
        quarantined.write_text("payload", encoding="utf-8")
        atomic_json(
            self.paths.state / "quarantine/run/item/_restore.json",
            {
                "schema_version": 1,
                "source_root": str(original_root),
                "manifest": "unused",
                "files": [str(relative)],
                "directories": ["bundle/empty"],
            },
        )
        result = recover_quarantine(self.paths)
        self.assertEqual({"restored": 1, "conflicts": 0}, result)
        self.assertTrue((original_root / "bundle/empty").is_dir())

    def test_apply_aborts_when_quarantine_device_differs(self) -> None:
        source = self.write_session("device")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        real_stat = os.stat
        resolved_project = self.project.resolve()

        def fake_stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if Path(path) == resolved_project:
                fields = tuple(result)[:10]
                return os.stat_result((fields[0], fields[1], fields[2] + 1) + fields[3:10])
            return result

        with mock.patch.object(archive_module.os, "stat", side_effect=fake_stat):
            with self.assertRaisesRegex(RuntimeError, "quarantine device differs"):
                apply_archive_plan(self.paths, plan_path)

        self.assertTrue(source.exists())
        self.assertEqual([], list(iter_manifests(self.paths)))

    def test_compression_effort_adapts_to_member_size(self) -> None:
        sizes = (32 * 1024, 2 * 1024**2, 9 * 1024**2)
        run_calls: list[list[str]] = []
        popen_calls: list[list[str]] = []
        real_run = archive_module.subprocess.run
        real_popen = archive_module.subprocess.Popen

        def tracking_run(args, *run_args, **run_kwargs):
            run_calls.append([str(value) for value in args])
            return real_run(args, *run_args, **run_kwargs)

        def tracking_popen(args, *popen_args, **popen_kwargs):
            popen_calls.append([str(value) for value in args])
            return real_popen(args, *popen_args, **popen_kwargs)

        def single_member_session(name: str, size: int) -> dict:
            source = self.project / f"{name}.jsonl"
            prefix = '{"timestamp":"2020-01-01T00:00:00Z","content":"'
            source.write_text(prefix + "x" * (size - len(prefix) - 3) + '"}\n', encoding="utf-8")
            return {
                "provider": "claude",
                "session_id": f"{self.project.name}:{name}",
                "source_root": str(self.project),
                "last_activity": "2020-01-01T00:00:00Z",
                "files": [
                    {"path": str(source), "relative": source.name, **regular_file_stat(source)}
                ],
            }

        with (
            mock.patch.object(archive_module.subprocess, "run", side_effect=tracking_run),
            mock.patch.object(archive_module.subprocess, "Popen", side_effect=tracking_popen),
        ):
            results = [
                self.archive_session(single_member_session(f"tier-{index}", size), f"tier-{index}")
                for index, size in enumerate(sizes)
            ]

        # The sub-1 MiB member takes the whole-file path; larger members are
        # chunked and compressed through stdin with per-chunk effort.
        whole_file = [call for call in run_calls if "-o" in call and "--version" not in call]
        self.assertEqual(1, len(whole_file))
        self.assertIn("-6", whole_file[0])
        chunked = [
            call
            for call in popen_calls
            if all(flag not in call for flag in ("-d", "-t", "-o", "--version", "--train"))
        ]
        self.assertEqual(2, len(chunked))
        self.assertIn("-12", chunked[0])
        self.assertIn("-19", chunked[1])
        self.assertIn("--long=27", chunked[1])
        self.assertEqual({"manifests": 3, "files": 3}, verify_all(self.paths))

        destination = self.home / "restore-tier"
        restore_manifest(self.paths, results[2]["manifest"], destination)
        self.assertEqual(sizes[2], (destination / "tier-2.jsonl").stat().st_size)

    def test_companion_uses_primary_as_compression_reference(self) -> None:
        blocks = b"".join(
            hashlib.sha256(f"block-{index}".encode()).digest() for index in range(2048)
        )
        primary = self.project / "ref-bundle.jsonl"
        primary.write_bytes(blocks)
        companion_dir = self.project / "ref-bundle"
        companion_dir.mkdir()
        companion = companion_dir / "copy.bin"
        companion_bytes = blocks + b"unique-suffix"
        companion.write_bytes(companion_bytes)
        session = {
            "provider": "claude",
            "session_id": f"{self.project.name}:ref-bundle",
            "source_root": str(self.project),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {"path": str(primary), "relative": primary.name, **regular_file_stat(primary)},
                {
                    "path": str(companion),
                    "relative": "ref-bundle/copy.bin",
                    **regular_file_stat(companion),
                },
            ],
            "directories": [
                {
                    "path": str(companion_dir),
                    "relative": "ref-bundle",
                    **regular_directory_stat(companion_dir),
                }
            ],
        }

        result = self.archive_session(session, "ref-bundle-run")

        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        entry = manifest["files"][1]
        self.assertEqual("ref-bundle.jsonl", entry["reference"])
        referenced_size = (self.paths.archive / entry["object"]).stat().st_size
        standalone_size = (self.paths.archive / manifest["files"][0]["object"]).stat().st_size
        self.assertLess(referenced_size, standalone_size // 4)

        destination = self.home / "restore-ref"
        restore_manifest(self.paths, result["manifest"], destination)
        self.assertEqual(
            hashlib.sha256(companion_bytes).hexdigest(),
            sha256_file(destination / "ref-bundle/copy.bin"),
        )
        self.assertEqual(
            hashlib.sha256(blocks).hexdigest(),
            sha256_file(destination / "ref-bundle.jsonl"),
        )

    def test_dedup_reuses_existing_object_recipe(self) -> None:
        payload = b"".join(
            hashlib.sha256(f"solo-{index}".encode()).digest() for index in range(64)
        )
        solo = self.project / "solo.jsonl"
        solo.write_bytes(payload)
        self.archive_session(
            {
                "provider": "claude",
                "session_id": f"{self.project.name}:solo",
                "source_root": str(self.project),
                "last_activity": "2020-01-01T00:00:00Z",
                "files": [
                    {"path": str(solo), "relative": solo.name, **regular_file_stat(solo)}
                ],
            },
            "solo-run",
        )

        primary = self.project / "pair.jsonl"
        primary.write_bytes(b"distinct primary " * 100)
        companion_dir = self.project / "pair"
        companion_dir.mkdir()
        companion = companion_dir / "dup.bin"
        companion.write_bytes(payload)
        pair = {
            "provider": "claude",
            "session_id": f"{self.project.name}:pair",
            "source_root": str(self.project),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {"path": str(primary), "relative": primary.name, **regular_file_stat(primary)},
                {
                    "path": str(companion),
                    "relative": "pair/dup.bin",
                    **regular_file_stat(companion),
                },
            ],
            "directories": [
                {
                    "path": str(companion_dir),
                    "relative": "pair",
                    **regular_directory_stat(companion_dir),
                }
            ],
        }

        result = self.archive_session(pair, "pair-run")

        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        self.assertNotIn("reference", manifest["files"][1])
        self.assertEqual({"manifests": 2, "files": 3}, verify_all(self.paths))
        destination = self.home / "restore-pair"
        restore_manifest(self.paths, result["manifest"], destination)
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            sha256_file(destination / "pair/dup.bin"),
        )

    def write_template_corpus(self, count: int) -> None:
        for index in range(count):
            lines = "".join(
                json.dumps(
                    {
                        "type": "user",
                        "timestamp": "2020-01-01T00:00:00Z",
                        "sessionId": "abcdef01-2345-6789-abcd-ef0123456789",
                        "cwd": "/Users/fixture/project",
                        "gitBranch": "main",
                        "content": f"shared vocabulary block {(index + record) % 7} "
                        + "common phrasing " * 50,
                        "requestId": f"req-{index * 100 + record:04d}",
                    }
                )
                + "\n"
                for record in range(6)
            )
            (self.project / f"corpus-{index:03d}.jsonl").write_text(lines, encoding="utf-8")

    def test_dictionary_training_and_round_trip(self) -> None:
        self.write_template_corpus(48)
        pointer = train_dictionary(self.paths, "claude", max_dict_bytes=4096)

        self.assertEqual("compression-dictionary", pointer["kind"])
        dictionary_path = self.paths.archive / pointer["object"]
        self.assertTrue(dictionary_path.is_file())
        self.assertEqual(pointer["raw_sha256"], sha256_file(dictionary_path))
        self.assertEqual(dictionary_path, load_provider_dictionary(self.paths, "claude"))

        target = self.project / "dict-target.jsonl"
        target.write_text(
            json.dumps(
                {
                    "type": "user",
                    "timestamp": "2020-01-01T00:00:00Z",
                    "sessionId": "abcdef01-2345-6789-abcd-ef0123456789",
                    "cwd": "/Users/fixture/project",
                    "gitBranch": "main",
                    "content": "shared vocabulary block 3 " + "common phrasing " * 200,
                    "requestId": "req-9999",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        target_bytes = target.read_bytes()
        with tempfile.TemporaryDirectory() as scratch:
            standalone = Path(scratch) / "standalone.zst"
            subprocess.run(
                [_zstd_binary(), "-q", "-6", "-f", str(target), "-o", str(standalone)],
                check=True,
            )
            standalone_size = standalone.stat().st_size

        result = archive_planned_session(
            self.paths,
            {
                "provider": "claude",
                "session_id": f"{self.project.name}:dict-target",
                "source_root": str(self.project),
                "last_activity": "2020-01-01T00:00:00Z",
                "files": [
                    {"path": str(target), "relative": target.name, **regular_file_stat(target)}
                ],
            },
            zstd=_zstd_binary(),
            quarantine_run=self.paths.state / "quarantine" / "dict-run",
            dictionary=load_provider_dictionary(self.paths, "claude"),
        )

        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        entry = manifest["files"][0]
        self.assertEqual(pointer["object"], entry["dictionary"])
        dictionary_size = (self.paths.archive / entry["object"]).stat().st_size
        self.assertLess(dictionary_size, standalone_size)

        self.assertEqual({"manifests": 1, "files": 1}, verify_all(self.paths))
        destination = self.home / "restore-dict"
        restore_manifest(self.paths, result["manifest"], destination)
        self.assertEqual(
            hashlib.sha256(target_bytes).hexdigest(),
            sha256_file(destination / "dict-target.jsonl"),
        )

    def test_dangling_dictionary_pointer_falls_back(self) -> None:
        digest = "a" * 64
        atomic_json(
            self.paths.archive / "dictionaries" / "claude.json",
            {
                "schema_version": 1,
                "kind": "compression-dictionary",
                "provider": "claude",
                "object": f"objects/sha256/{digest[:2]}/{digest}.dict",
                "raw_sha256": digest,
            },
        )

        self.assertIsNone(load_provider_dictionary(self.paths, "claude", warn=False))
        result = self.archive_session(
            {
                "provider": "claude",
                "session_id": f"{self.project.name}:fallback",
                "source_root": str(self.project),
                "last_activity": "2020-01-01T00:00:00Z",
                "files": [
                    {
                        "path": str(source := self.write_session("fallback")),
                        "relative": source.name,
                        **regular_file_stat(source),
                    }
                ],
            },
            "fallback-run",
        )
        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        self.assertNotIn("dictionary", manifest["files"][0])

    def plain_session(self, name: str, source: Path) -> dict:
        return {
            "provider": "claude",
            "session_id": f"{self.project.name}:{name}",
            "source_root": str(self.project),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [{"path": str(source), "relative": source.name, **regular_file_stat(source)}],
        }

    def write_large_session(self, name: str, size: int) -> Path:
        path = self.project / f"{name}.jsonl"
        record = (
            json.dumps({"type": "user", "timestamp": "2020-01-01T00:00:00Z", "content": "chunky " * 1000})
            + "\n"
        )
        path.write_text(record * (size // len(record) + 1), encoding="utf-8")
        os.chmod(path, 0o640)
        return path

    def test_chunk_boundaries(self) -> None:
        source = self.project / "boundaries.jsonl"
        line = b"x" * 1023 + b"\n"
        source.write_bytes(line * (CHUNK_TARGET_BYTES // 1024))
        chunks = list(_chunk_records(source))
        self.assertEqual(1, len(chunks))
        self.assertEqual(CHUNK_TARGET_BYTES, len(chunks[0]))

        source.write_bytes(b"y" * (CHUNK_TARGET_BYTES + 500) + b"\n" + b"small\n")
        chunks = list(_chunk_records(source))
        self.assertEqual(2, len(chunks))
        self.assertEqual(CHUNK_TARGET_BYTES + 501, len(chunks[0]))
        self.assertEqual(b"small\n", chunks[1])

    def test_chunked_round_trip(self) -> None:
        source = self.write_large_session("chunked", 2_600_000)
        original_hash = sha256_file(source)
        original_mode = source.stat().st_mode & 0o777
        original_mtime = source.stat().st_mtime_ns

        result = self.archive_session(self.plain_session("chunked", source), "chunk-run")

        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual(2, manifest["schema_version"])
        entry = manifest["files"][0]
        self.assertNotIn("object", entry)
        self.assertEqual(3, len(entry["chunks"]))
        self.assertEqual({"manifests": 1, "files": 1}, verify_all(self.paths))

        destination = self.home / "restore-chunked"
        restore_manifest(self.paths, result["manifest"], destination)
        restored = destination / "chunked.jsonl"
        self.assertEqual(original_hash, sha256_file(restored))
        self.assertEqual(original_mode, restored.stat().st_mode & 0o777)
        self.assertEqual(original_mtime, restored.stat().st_mtime_ns)

    def test_chunked_sessions_share_prefix_objects(self) -> None:
        first = self.write_large_session("chunk-a", 2_600_000)
        content = first.read_bytes()
        result_a = self.archive_session(self.plain_session("chunk-a", first), "chunk-a-run")

        second = self.project / "chunk-b.jsonl"
        second.write_bytes(content + b'{"timestamp":"2020-01-02T00:00:00Z"}\n')
        result_b = self.archive_session(self.plain_session("chunk-b", second), "chunk-b-run")

        chunks_a = [
            chunk["sha256"]
            for chunk in json.loads(Path(result_a["manifest"]).read_text())["files"][0]["chunks"]
        ]
        entry_b = json.loads(Path(result_b["manifest"]).read_text())["files"][0]["chunks"]
        chunks_b = [chunk["sha256"] for chunk in entry_b]
        self.assertEqual(chunks_a[:2], chunks_b[:2])
        self.assertNotEqual(chunks_a[2], chunks_b[2])
        self.assertEqual(3, len(entry_b))
        self.assertEqual({"manifests": 2, "files": 2}, verify_all(self.paths))

        destination = self.home / "restore-chunk-b"
        restore_manifest(self.paths, result_b["manifest"], destination)
        self.assertEqual(
            hashlib.sha256(content + b'{"timestamp":"2020-01-02T00:00:00Z"}\n').hexdigest(),
            sha256_file(destination / "chunk-b.jsonl"),
        )

    def test_chunked_primary_serves_as_companion_reference(self) -> None:
        primary = self.write_large_session("bigref", 1_500_000)
        primary_bytes = primary.read_bytes()
        companion_dir = self.project / "bigref"
        companion_dir.mkdir()
        companion = companion_dir / "copy.jsonl"
        companion_bytes = primary_bytes + b'{"extra":true}\n'
        companion.write_bytes(companion_bytes)
        session = {
            "provider": "claude",
            "session_id": f"{self.project.name}:bigref",
            "source_root": str(self.project),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {"path": str(primary), "relative": primary.name, **regular_file_stat(primary)},
                {
                    "path": str(companion),
                    "relative": "bigref/copy.jsonl",
                    **regular_file_stat(companion),
                },
            ],
            "directories": [
                {
                    "path": str(companion_dir),
                    "relative": "bigref",
                    **regular_directory_stat(companion_dir),
                }
            ],
        }

        result = self.archive_session(session, "bigref-run")

        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        self.assertIn("chunks", manifest["files"][0])
        self.assertEqual("bigref.jsonl", manifest["files"][1]["reference"])
        self.assertEqual({"manifests": 1, "files": 2}, verify_all(self.paths))

        destination = self.home / "restore-bigref"
        restore_manifest(self.paths, result["manifest"], destination)
        self.assertEqual(
            hashlib.sha256(primary_bytes).hexdigest(),
            sha256_file(destination / "bigref.jsonl"),
        )
        self.assertEqual(
            hashlib.sha256(companion_bytes).hexdigest(),
            sha256_file(destination / "bigref/copy.jsonl"),
        )

    def test_archive_stats_aggregates_manifest_graph(self) -> None:
        self.write_session("stats-a")
        self.archive_session(self.bundle_session("stats-b"), "stats-run")
        plan_path, _ = create_archive_plan(self.paths, utc_now())
        apply_archive_plan(self.paths, plan_path)

        stats = archive_stats(self.paths)

        self.assertEqual(2, stats["manifests"])
        self.assertEqual(3, stats["objects"])
        claude = stats["providers"]["claude"]
        self.assertEqual(2, claude["manifests"])
        self.assertEqual(3, claude["files"])
        self.assertGreater(claude["companion_raw_bytes"], 0)
        self.assertEqual(claude["files"], sum(claude["size_histogram"].values()))
        self.assertGreater(stats["ratio"], 1)


if __name__ == "__main__":
    unittest.main()
