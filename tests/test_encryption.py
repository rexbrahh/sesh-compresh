from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import sesh_compresh.encryption as encryption_module
from sesh_compresh.archive import (
    _zstd_binary,
    archive_stats,
    archive_planned_session,
    restore_manifest,
    verify_manifest,
)

from sesh_compresh.common import AppPaths, regular_file_stat
from sesh_compresh.encryption import (
    cas_plaintext_sha256,
    enable_archive_encryption,
    encryption_status,
    encrypt_cas_payload,
    materialize_cas_payload,
    require_archive_identity,
    restore_archive_key,
)


IDENTITY = "AGE-SECRET-KEY-1" + "A" * 58
RECIPIENT = "age1" + "q" * 58


class FakeStore:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get(self, service: str, account: str) -> str | None:
        return self.values.get((service, account))

    def set(self, service: str, account: str, secret: str) -> None:
        self.values[(service, account)] = secret


class FakeAge:
    prefix = b"age-encrypted\0"

    def generate_identity(self) -> tuple[str, str]:
        return IDENTITY, RECIPIENT

    def recipient_for_identity(self, identity: str) -> str:
        if identity != IDENTITY:
            return "age1" + "z" * 58
        return RECIPIENT

    def encrypt_file(
        self, source: Path, destination: Path, recipient: str
    ) -> None:
        if recipient != RECIPIENT:
            raise RuntimeError("wrong recipient")
        destination.write_bytes(self.prefix + source.read_bytes()[::-1])

    def decrypt_file(
        self, source: Path, destination: Path, identity: str
    ) -> None:
        payload = source.read_bytes()
        if identity != IDENTITY or not payload.startswith(self.prefix):
            raise RuntimeError("age authentication failed")
        destination.write_bytes(payload[len(self.prefix) :][::-1])

    def encrypt_recovery_file(
        self, identity: str, destination: Path
    ) -> None:
        destination.write_bytes(b"passphrase-age\0" + identity.encode("ascii"))

    def decrypt_recovery_file(self, source: Path) -> str:
        prefix = b"passphrase-age\0"
        payload = source.read_bytes()
        if not payload.startswith(prefix):
            raise RuntimeError("bad recovery passphrase")
        return payload[len(prefix) :].decode("ascii")


class EncryptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.paths = AppPaths.discover(self.root / "home")
        self.store = FakeStore()
        self.age = FakeAge()
        self.recovery = self.root / "recovery.age"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def enable(self) -> dict[str, object]:
        return enable_archive_encryption(
            self.paths,
            self.recovery,
            store=self.store,
            runner=self.age,
        )

    def session(self, name: str, files: list[Path]) -> dict:
        root = files[0].parent
        return {
            "provider": "claude",
            "session_id": f"encrypted:{name}",
            "source_root": str(root),
            "last_activity": "2020-01-01T00:00:00Z",
            "files": [
                {
                    "path": str(path),
                    "relative": str(path.relative_to(root)),
                    **regular_file_stat(path),
                }
                for path in files
            ],
            "directories": [],
        }

    def archive(self, name: str, files: list[Path]) -> dict:
        return archive_planned_session(
            self.paths,
            self.session(name, files),
            zstd=_zstd_binary(),
            quarantine_run=self.paths.state / "quarantine" / f"run-{name}",
        )

    def integration(self):
        return mock.patch.multiple(
            encryption_module,
            _secure_secret_store=mock.Mock(return_value=self.store),
            _age_runner=mock.Mock(return_value=self.age),
        )

    def test_enable_requires_empty_archive_and_writes_no_secret_config(self) -> None:
        self.paths.ensure_private()
        occupied = self.paths.archive / "manifests" / "existing"
        occupied.mkdir()
        with self.assertRaisesRegex(RuntimeError, "empty manifest"):
            self.enable()
        self.assertFalse(self.recovery.exists())
        occupied.rmdir()

        result = self.enable()

        self.assertTrue(result["enabled"])
        self.assertEqual(0o600, self.recovery.stat().st_mode & 0o777)
        config = (self.paths.archive / "encryption.json").read_text()
        self.assertNotIn("AGE-SECRET", config)
        self.assertTrue(
            encryption_status(
                self.paths, store=self.store, runner=self.age
            )["key_available"]
        )

    def test_encrypted_payload_materializes_and_authenticates_plaintext(self) -> None:
        self.enable()
        plain = self.root / "frame.zst"
        envelope = self.root / "object.zst"
        payload = b"zstd frame bytes"
        plain.write_bytes(payload)
        encrypt_cas_payload(
            self.paths, plain, envelope, store=self.store, runner=self.age
        )
        self.assertNotEqual(payload, envelope.read_bytes())
        digest = hashlib.sha256(payload).hexdigest()

        with materialize_cas_payload(
            self.paths,
            envelope,
            expected_sha256=digest,
            store=self.store,
            runner=self.age,
        ) as materialized:
            self.assertEqual(payload, materialized.read_bytes())
        self.assertEqual(
            digest,
            cas_plaintext_sha256(
                self.paths, envelope, store=self.store, runner=self.age
            ),
        )

        envelope.write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "authentication"):
            with materialize_cas_payload(
                self.paths, envelope, store=self.store, runner=self.age
            ):
                pass

    def test_missing_key_fails_and_recovery_restores_exact_archive_key(self) -> None:
        enabled = self.enable()
        self.store.values.clear()
        with self.assertRaisesRegex(RuntimeError, "key is unavailable"):
            require_archive_identity(self.paths, store=self.store, runner=self.age)
        self.assertFalse(
            encryption_status(
                self.paths, store=self.store, runner=self.age
            )["key_available"]
        )

        restored = restore_archive_key(
            self.paths,
            self.recovery,
            store=self.store,
            runner=self.age,
        )

        self.assertEqual(enabled["key_id"], restored["key_id"])
        self.assertIsNotNone(
            require_archive_identity(
                self.paths, store=self.store, runner=self.age
            )
        )

    def test_recovery_rejects_a_key_for_another_archive(self) -> None:
        self.enable()
        wrong = self.root / "wrong.age"
        wrong.write_bytes(b"passphrase-age\0" + ("AGE-SECRET-KEY-1" + "C" * 58).encode())
        before = dict(self.store.values)

        with self.assertRaisesRegex(RuntimeError, "does not match"):
            restore_archive_key(
                self.paths, wrong, store=self.store, runner=self.age
            )

        self.assertEqual(before, self.store.values)

    def test_enable_resumes_after_config_publication_failure(self) -> None:
        real_atomic = encryption_module.atomic_json
        failed = False

        def fail_config(path: Path, payload: dict, *, replace: bool = True) -> None:
            nonlocal failed
            if path.name == "encryption.json" and not failed:
                failed = True
                raise OSError("injected config fsync failure")
            real_atomic(path, payload, replace=replace)

        with mock.patch.object(
            encryption_module, "atomic_json", side_effect=fail_config
        ):
            with self.assertRaisesRegex(OSError, "config fsync"):
                self.enable()

        self.assertTrue(self.recovery.exists())
        self.assertTrue((self.paths.state / "encryption-enable.json").exists())
        self.assertFalse((self.paths.archive / "encryption.json").exists())

        result = self.enable()

        self.assertTrue(result["enabled"])
        self.assertFalse((self.paths.state / "encryption-enable.json").exists())
        self.assertFalse(
            (self.paths.state / "encryption-enable-recovery.age").exists()
        )

    def test_enable_rejects_replaced_recovery_without_removing_foreign(self) -> None:
        real_link = encryption_module.os.link
        foreign = b"foreign recovery replacement"

        def replace_after_link(source: Path, target: Path, **kwargs) -> None:
            real_link(source, target, **kwargs)
            Path(target).unlink()
            Path(target).write_bytes(foreign)

        with mock.patch.object(
            encryption_module.os, "link", side_effect=replace_after_link
        ):
            with self.assertRaisesRegex(RuntimeError, "publication changed"):
                self.enable()

        self.assertEqual(foreign, self.recovery.read_bytes())
        self.assertFalse((self.paths.archive / "encryption.json").exists())
        self.assertTrue((self.paths.state / "encryption-enable.json").exists())

    def test_positive_priority_unknown_keyring_backend_is_rejected(self) -> None:
        Backend = type(
            "Keyring",
            (),
            {"__module__": "keyrings.alt.file", "priority": 10},
        )
        module = types.SimpleNamespace(get_keyring=lambda: Backend())
        with mock.patch.dict(sys.modules, {"keyring": module}):
            with self.assertRaisesRegex(RuntimeError, "secure keyring"):
                encryption_module._secure_secret_store()

    def test_enable_rejects_pending_portable_import_staging(self) -> None:
        self.paths.ensure_private()
        staged = self.paths.state / "portable-imports" / "pending"
        staged.mkdir(parents=True)

        with self.assertRaisesRegex(RuntimeError, "portable-import"):
            self.enable()

        self.assertFalse(self.recovery.exists())

    def test_recovery_publication_uses_a_destination_filesystem_temp(self) -> None:
        real_link = encryption_module.os.link
        sources: list[Path] = []

        def require_destination_temp(source: Path, target: Path, **kwargs) -> None:
            sources.append(Path(source))
            self.assertEqual(Path(source).parent, Path(target).parent)
            real_link(source, target, **kwargs)

        with mock.patch.object(
            encryption_module.os, "link", side_effect=require_destination_temp
        ):
            self.enable()

        self.assertTrue(sources)
        self.assertTrue(self.recovery.exists())

    def test_resume_rejects_wrong_existing_keychain_value(self) -> None:
        real_atomic = encryption_module.atomic_json

        def fail_config(path: Path, payload: dict, *, replace: bool = True) -> None:
            if path.name == "encryption.json":
                raise OSError("injected config failure")
            real_atomic(path, payload, replace=replace)

        with mock.patch.object(
            encryption_module, "atomic_json", side_effect=fail_config
        ):
            with self.assertRaises(OSError):
                self.enable()
        key = next(iter(self.store.values))
        self.store.values[key] = "AGE-SECRET-KEY-1" + "C" * 58

        with self.assertRaisesRegex(RuntimeError, "does not match"):
            self.enable()

        self.assertFalse((self.paths.archive / "encryption.json").exists())

    def test_resume_rejects_unsafe_or_noncanonical_enable_intent(self) -> None:
        real_atomic = encryption_module.atomic_json

        def fail_config(path: Path, payload: dict, *, replace: bool = True) -> None:
            if path.name == "encryption.json":
                raise OSError("injected config failure")
            real_atomic(path, payload, replace=replace)

        with mock.patch.object(
            encryption_module, "atomic_json", side_effect=fail_config
        ):
            with self.assertRaises(OSError):
                self.enable()
        intent = self.paths.state / "encryption-enable.json"
        before = dict(self.store.values)
        intent.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "intent is unsafe"):
            self.enable()
        self.assertEqual(before, self.store.values)
        self.assertFalse((self.paths.archive / "encryption.json").exists())

        intent.chmod(0o600)
        payload = json.loads(intent.read_text())
        payload["created_at"] = "2026-01-01T00:00:00+00:00"
        intent.write_text(json.dumps(payload))
        intent.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "timestamp"):
            self.enable()
        self.assertEqual(before, self.store.values)
        self.assertFalse((self.paths.archive / "encryption.json").exists())

    def test_encrypted_whole_chunk_reference_verify_restore_and_extract(self) -> None:
        from sesh_compresh.extract import extract_member_tail

        with self.integration():
            self.enable()
            small_root = self.root / "small"
            small_root.mkdir()
            small = small_root / "small.jsonl"
            small_bytes = b'{"encrypted":"whole"}\n' * 20
            small.write_bytes(small_bytes)
            small_result = self.archive("whole", [small])
            small_manifest = Path(small_result["manifest"])
            small_payload = next(
                (self.paths.archive / "objects/sha256").glob("*/*.zst")
            ).read_bytes()
            self.assertTrue(small_payload.startswith(self.age.prefix))
            verify_manifest(self.paths, small_manifest)
            self.assertEqual(1, archive_stats(self.paths)["manifests"])
            small_restore = self.root / "small-restore"
            restore_manifest(self.paths, str(small_manifest), small_restore)
            self.assertEqual(small_bytes, (small_restore / small.name).read_bytes())

            large_root = self.root / "large"
            large_root.mkdir()
            primary = large_root / "primary.jsonl"
            line = b'{"encrypted":"chunked reference data"}\n'
            primary_bytes = line * (1_200_000 // len(line) + 1)
            primary.write_bytes(primary_bytes)
            companion = large_root / "companion.jsonl"
            companion_bytes = primary_bytes + b'{"companion":true}\n'
            companion.write_bytes(companion_bytes)
            result = self.archive("chunk-reference", [primary, companion])
            manifest = Path(result["manifest"])
            verify_manifest(self.paths, manifest)
            restored = self.root / "large-restore"
            restore_manifest(self.paths, str(manifest), restored)
            self.assertEqual(primary_bytes, (restored / primary.name).read_bytes())
            self.assertEqual(
                companion_bytes, (restored / companion.name).read_bytes()
            )
            tail = self.root.resolve() / "tail.jsonl"
            extract_member_tail(
                self.paths, manifest, primary.name, len(line), tail
            )
            self.assertEqual(line, tail.read_bytes())
            from sesh_compresh.observer import (
                apply_archive_expiry_plan,
                create_archive_expiry_plan,
            )

            expiry_path, expiry = create_archive_expiry_plan(
                self.paths, "claude", ttl_days=0, cap_bytes=1024**3
            )
            self.assertEqual(2, len(expiry["manifests"]))
            expired = apply_archive_expiry_plan(self.paths, expiry_path)
            self.assertEqual(2, expired["manifests_removed"])
            self.assertEqual(0, archive_stats(self.paths)["manifests"])

    def test_missing_key_and_tampered_envelope_fail_without_source_move(self) -> None:
        with self.integration():
            self.enable()
            source_root = self.root / "missing-key"
            source_root.mkdir()
            source = source_root / "session.jsonl"
            source.write_bytes(b'{"source":"must remain"}\n')
            before_objects = list(
                (self.paths.archive / "objects/sha256").glob("*/*")
            )
            self.store.values.clear()

            with self.assertRaisesRegex(RuntimeError, "key is unavailable"):
                self.archive("missing-key", [source])

            self.assertTrue(source.exists())
            self.assertEqual(
                before_objects,
                list((self.paths.archive / "objects/sha256").glob("*/*")),
            )

            restore_archive_key(
                self.paths,
                self.recovery,
                store=self.store,
                runner=self.age,
            )
            result = self.archive("tamper", [source])
            manifest = Path(result["manifest"])
            payload = json.loads(manifest.read_text())
            object_path = self.paths.archive / payload["files"][0]["object"]
            object_path.write_bytes(b"tampered age envelope")

            with self.assertRaisesRegex(RuntimeError, "authentication"):
                verify_manifest(self.paths, manifest)

    def test_portable_export_and_import_reject_encrypted_roots(self) -> None:
        from sesh_compresh.portable import (
            create_portable_import_plan,
            export_portable_archive,
        )

        with self.integration():
            self.enable()
            artifact = self.root / "portable.zip"
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                export_portable_archive(
                    self.paths, ["missing-manifest"], artifact
                )
            artifact.write_bytes(b"not inspected")
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                create_portable_import_plan(self.paths, artifact)


if __name__ == "__main__":
    unittest.main()
