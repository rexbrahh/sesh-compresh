from __future__ import annotations

import errno
import hashlib
import subprocess
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import sesh_compresh.extract as extract_module
import sesh_compresh.observer as observer_module
from sesh_compresh.archive import CHUNK_TARGET_BYTES, _zstd_binary
from sesh_compresh.common import (
    AppPaths,
    atomic_json,
    ensure_safe_cas_shard,
    sha256_file,
)
from sesh_compresh.extract import extract_member_range, extract_member_tail


class ExtractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name).resolve()
        self.paths = AppPaths.discover(self.home)
        self.paths.ensure_private()
        self.zstd = _zstd_binary()
        self.source_root = self.home / "source"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def frame(self, data: bytes, relative: str) -> Path:
        path = self.paths.archive / relative
        ensure_safe_cas_shard(self.paths.archive, path.parent.name)
        with path.open("wb") as output:
            subprocess.run(
                [self.zstd, "-q", "-c"], input=data, stdout=output, check=True
            )
        return path

    def member_base(self, name: str, data: bytes) -> dict:
        return {
            "path": str(self.source_root / name),
            "relative": name,
            "device": 1,
            "inode": 2,
            "size": len(data),
            "mtime_ns": 3,
            "mode": 0o600,
            "raw_sha256": hashlib.sha256(data).hexdigest(),
        }

    def write_manifest(self, name: str, members: list[dict]) -> Path:
        path = self.paths.archive / "manifests/claude" / f"{name}.json"
        atomic_json(
            path,
            {
                "schema_version": 2,
                "kind": "session-archive",
                "archive_id": name,
                "provider": "claude",
                "session_id": name,
                "source_root": str(self.source_root),
                "last_activity": "2020-01-01T00:00:00Z",
                "archived_at": "2020-01-02T00:00:00Z",
                "zstd_version": "fixture",
                "files": members,
                "directories": [],
            },
        )
        return path

    def chunk_manifest(self, name: str, chunks: list[bytes]) -> tuple[Path, str]:
        records = []
        for data in chunks:
            digest = hashlib.sha256(data).hexdigest()
            relative = f"objects/sha256/{digest[:2]}/{digest}.zst"
            self.frame(data, relative)
            records.append({"sha256": digest, "size": len(data)})
        member_name = f"{name}.jsonl"
        member = {**self.member_base(member_name, b"".join(chunks)), "chunks": records}
        return self.write_manifest(name, [member]), member_name

    def whole_member(self, name: str, data: bytes) -> dict:
        member = self.member_base(name, data)
        raw = member["raw_sha256"]
        scratch = self.home / f"{name}.zst"
        with scratch.open("wb") as output:
            subprocess.run(
                [self.zstd, "-q", "-c"], input=data, stdout=output, check=True
            )
        compressed = sha256_file(scratch)
        relative = f"objects/sha256/{raw[:2]}/{raw}.{compressed}.zst"
        target = (
            ensure_safe_cas_shard(self.paths.archive, raw[:2]) / Path(relative).name
        )
        scratch.replace(target)
        return {
            **member,
            "compressed_sha256": compressed,
            "object": relative,
        }

    def test_chunk_range_decodes_only_intersecting_frames(self) -> None:
        chunks = [bytes([65 + index]) * (100 + index) for index in range(4)]
        manifest, member = self.chunk_manifest("seek", chunks)
        start = len(chunks[0]) + 17
        length = len(chunks[1]) - 17 + 23
        destination = self.home / "range.bin"
        calls = []
        real_popen = subprocess.Popen

        def tracking_popen(args, *positional, **keywords):
            calls.append(Path(args[-1]).name)
            return real_popen(args, *positional, **keywords)

        with mock.patch.object(
            extract_module.subprocess, "Popen", side_effect=tracking_popen
        ):
            result = extract_member_range(
                self.paths, manifest, member, start, length, destination
            )

        expected = b"".join(chunks)[start : start + length]
        self.assertEqual(expected, destination.read_bytes())
        self.assertEqual(2, result["decoded_frames"])
        self.assertEqual(4, result["total_frames"])
        selected = [hashlib.sha256(data).hexdigest() + ".zst" for data in chunks[1:3]]
        self.assertEqual(selected, calls)

    def test_selected_chunk_size_and_hash_are_verified(self) -> None:
        original = b"expected" * 31
        manifest, member = self.chunk_manifest("integrity", [b"prefix", original])
        digest = hashlib.sha256(original).hexdigest()
        relative = f"objects/sha256/{digest[:2]}/{digest}.zst"
        target = self.paths.archive / relative
        start = len(b"prefix")

        for label, replacement, message in (
            ("size", b"short", "size mismatch"),
            ("hash", b"x" * len(original), "SHA-256 mismatch"),
        ):
            with self.subTest(label=label):
                self.frame(replacement, relative)
                destination = self.home / f"{label}.bin"
                with self.assertRaisesRegex(RuntimeError, message):
                    extract_member_range(
                        self.paths,
                        manifest,
                        member,
                        start,
                        len(original),
                        destination,
                    )
                self.assertFalse(destination.exists())
                self.assertEqual(
                    [], list(destination.parent.glob(f".{destination.name}.*.part"))
                )
        self.assertTrue(target.is_file())

    def test_small_whole_file_supports_bounded_range(self) -> None:
        data = b"0123456789" * 100
        member = self.whole_member("whole.jsonl", data)
        manifest = self.write_manifest("whole", [member])
        destination = self.home / "whole-range.bin"

        result = extract_member_range(
            self.paths, manifest, "whole.jsonl", 91, 117, destination
        )

        self.assertEqual(data[91:208], destination.read_bytes())
        self.assertEqual(1, result["decoded_frames"])
        self.assertEqual(1, result["total_frames"])

    def test_tail_selection_uses_exact_member_size(self) -> None:
        chunks = [b"first chunk", b"second chunk", b"last chunk"]
        manifest, member = self.chunk_manifest("tail", chunks)
        destination = self.home / "tail.bin"

        result = extract_member_tail(
            self.paths, manifest, member, len(chunks[-1]) + 3, destination
        )

        self.assertEqual(b"unk" + chunks[-1], destination.read_bytes())
        self.assertEqual(2, result["decoded_frames"])

        empty = self.home / "empty-tail.bin"
        with mock.patch.object(extract_module.subprocess, "Popen") as popen:
            empty_result = extract_member_tail(self.paths, manifest, member, 0, empty)
        popen.assert_not_called()
        self.assertEqual(b"", empty.read_bytes())
        self.assertEqual(0, empty_result["decoded_frames"])

        with self.assertRaisesRegex(ValueError, "tail is outside"):
            extract_member_tail(
                self.paths,
                manifest,
                member,
                sum(map(len, chunks)) + 1,
                self.home / "invalid-tail.bin",
            )

    def test_exact_member_bounds_and_nonseekable_forms_are_rejected(self) -> None:
        data = b"small whole member"
        member = self.whole_member("exact.jsonl", data)
        manifest = self.write_manifest("exact", [member])
        destination = self.home / "invalid.bin"

        cases = (
            ("EXACT.jsonl", 0, 1, "matched 0"),
            ("exact.jsonl", True, 1, "bounds must be integers"),
            ("exact.jsonl", 0, False, "bounds must be integers"),
            ("exact.jsonl", -1, 1, "outside"),
            ("exact.jsonl", 0, -1, "outside"),
            ("exact.jsonl", len(data), 1, "outside"),
        )
        for selected, start, length, message in cases:
            with self.subTest(selected=selected, start=start, length=length):
                with self.assertRaisesRegex(ValueError, message):
                    extract_member_range(
                        self.paths, manifest, selected, start, length, destination
                    )
        self.assertFalse(destination.exists())

        large = self.whole_member("large.jsonl", b"l" * (CHUNK_TARGET_BYTES + 1))
        large_manifest = self.write_manifest("large", [large])
        with self.assertRaisesRegex(ValueError, "large whole-file"):
            extract_member_range(
                self.paths, large_manifest, "large.jsonl", 0, 1, destination
            )

        primary = self.whole_member("primary.jsonl", b"primary")
        referenced = {
            **self.whole_member("child.bin", b"child"),
            "reference": "primary.jsonl",
        }
        reference_manifest = self.write_manifest("reference", [primary, referenced])
        with self.assertRaisesRegex(ValueError, "not seekable"):
            extract_member_range(
                self.paths, reference_manifest, "child.bin", 0, 1, destination
            )

        empty = self.home / "empty.bin"
        with mock.patch.object(extract_module.subprocess, "Popen") as popen:
            result = extract_member_range(
                self.paths,
                reference_manifest,
                "child.bin",
                len(b"child"),
                0,
                empty,
            )
        popen.assert_not_called()
        self.assertEqual(b"", empty.read_bytes())
        self.assertEqual(0, result["decoded_frames"])

    def test_output_publication_never_overwrites(self) -> None:
        data = b"atomic output"
        member = self.whole_member("atomic.jsonl", data)
        manifest = self.write_manifest("atomic", [member])
        existing = self.home / "existing.bin"
        existing.write_bytes(b"keep")

        with mock.patch.object(extract_module.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(FileExistsError, "destination exists"):
                extract_member_range(
                    self.paths, manifest, "atomic.jsonl", 0, 3, existing
                )
        popen.assert_not_called()
        self.assertEqual(b"keep", existing.read_bytes())

        raced = self.home / "raced.bin"
        real_link = extract_module._OS_LINK

        def racing_link(source, destination, **kwargs):
            raced.write_bytes(b"racer")
            return real_link(source, destination, **kwargs)

        with mock.patch.object(extract_module, "_OS_LINK", side_effect=racing_link):
            with self.assertRaises(FileExistsError):
                extract_member_range(self.paths, manifest, "atomic.jsonl", 0, 3, raced)
        self.assertEqual(b"racer", raced.read_bytes())
        self.assertEqual([], list(raced.parent.glob(f".{raced.name}.*.part")))

    def test_parent_swap_during_publication_cannot_redirect_output(self) -> None:
        data = b"descriptor anchored output"
        member = self.whole_member("swap.jsonl", data)
        manifest = self.write_manifest("swap", [member])
        output_parent = self.home / "output"
        output_parent.mkdir()
        displaced = self.home / "displaced-output"
        destination = output_parent / "range.bin"
        real_link = extract_module._OS_LINK

        def swapping_link(source, target, **kwargs):
            output_parent.rename(displaced)
            output_parent.mkdir()
            (output_parent / "sentinel").write_bytes(b"attacker")
            return real_link(source, target, **kwargs)

        with mock.patch.object(extract_module, "_OS_LINK", side_effect=swapping_link):
            with self.assertRaisesRegex(RuntimeError, "parent changed during"):
                extract_member_range(
                    self.paths, manifest, "swap.jsonl", 0, len(data), destination
                )

        self.assertFalse(destination.exists())
        self.assertFalse((displaced / destination.name).exists())
        self.assertEqual(b"attacker", (output_parent / "sentinel").read_bytes())
        self.assertEqual([], list(displaced.glob(f".{destination.name}.*.part")))

    def test_extraction_excludes_concurrent_expiry(self) -> None:
        data = b"locked extraction"
        member = self.whole_member("locked.jsonl", data)
        manifest = self.write_manifest("locked", [member])
        destination = self.home / "locked.bin"
        lock = threading.Lock()
        decode_entered = threading.Event()
        release_decode = threading.Event()
        expiry_attempted = threading.Event()
        expiry_entered = threading.Event()
        failures = []
        real_decode = extract_module._decode_frame_range

        @contextmanager
        def shared_lock(paths):
            self.assertIs(paths, self.paths)
            with lock:
                yield

        def blocked_decode(*args, **kwargs):
            decode_entered.set()
            if not release_decode.wait(2):
                raise RuntimeError("test did not release extraction")
            return real_decode(*args, **kwargs)

        def expire_locked(paths, plan_path):
            expiry_entered.set()
            return {"objects_removed": 0}

        def run_extract() -> None:
            try:
                extract_member_range(
                    self.paths, manifest, "locked.jsonl", 0, len(data), destination
                )
            except BaseException as error:
                failures.append(error)

        def run_expiry() -> None:
            try:
                expiry_attempted.set()
                observer_module.apply_observer_expiry_plan(
                    self.paths, self.paths.state / "expiry.json"
                )
            except BaseException as error:
                failures.append(error)

        with (
            mock.patch.object(extract_module, "app_lock", shared_lock),
            mock.patch.object(observer_module, "app_lock", shared_lock),
            mock.patch.object(
                extract_module, "_decode_frame_range", side_effect=blocked_decode
            ),
            mock.patch.object(
                observer_module,
                "_apply_observer_expiry_plan_locked",
                side_effect=expire_locked,
            ),
        ):
            extraction = threading.Thread(target=run_extract)
            extraction.start()
            self.assertTrue(decode_entered.wait(1))
            expiry = threading.Thread(target=run_expiry)
            expiry.start()
            self.assertTrue(expiry_attempted.wait(1))
            self.assertFalse(expiry_entered.wait(0.1))
            release_decode.set()
            extraction.join(2)
            expiry.join(2)

        self.assertFalse(extraction.is_alive())
        self.assertFalse(expiry.is_alive())
        self.assertEqual([], failures)
        self.assertTrue(expiry_entered.is_set())
        self.assertEqual(data, destination.read_bytes())

    def test_failed_decode_durably_cleans_temporary_output(self) -> None:
        data = b"cleanup durability"
        member = self.whole_member("cleanup.jsonl", data)
        manifest = self.write_manifest("cleanup", [member])
        destination = self.home / "cleanup.bin"
        syncs = []

        def fail_cleanup_sync(parent_fd):
            self.assertEqual(
                [], list(destination.parent.glob(f".{destination.name}.*.part"))
            )
            syncs.append(parent_fd)
            raise OSError(errno.EIO, "cleanup directory fsync failed")

        with (
            mock.patch.object(
                extract_module,
                "_decode_frame_range",
                side_effect=RuntimeError("decode failed"),
            ),
            mock.patch.object(
                extract_module, "_sync_parent", side_effect=fail_cleanup_sync
            ),
        ):
            with self.assertRaisesRegex(OSError, "cleanup directory fsync failed"):
                extract_member_range(
                    self.paths, manifest, "cleanup.jsonl", 0, len(data), destination
                )

        self.assertEqual(1, len(syncs))
        self.assertFalse(destination.exists())
        self.assertEqual(
            [], list(destination.parent.glob(f".{destination.name}.*.part"))
        )


if __name__ == "__main__":
    unittest.main()
