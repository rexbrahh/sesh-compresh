from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Protocol

from .common import (
    SCHEMA_VERSION,
    AppPaths,
    app_lock,
    atomic_json,
    ensure_private_subdirectory,
    fsync_dir,
    iso_utc,
    load_json,
    regular_file_stat,
    utc_now,
)


_CONFIG_KEYS = {
    "schema_version",
    "kind",
    "algorithm",
    "recipient",
    "key_id",
    "created_at",
}
_ENABLE_INTENT_KEYS = {
    "schema_version",
    "kind",
    "recipient",
    "key_id",
    "created_at",
    "recovery_file",
    "recovery_sha256",
}
_AGE_RECIPIENT = re.compile(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}")
_AGE_IDENTITY = re.compile(r"AGE-SECRET-KEY-1[023456789ACDEFGHJKLMNPQRSTUVWXYZ]{58}")
_KEYRING_SERVICE = "sesh-compresh.archive.age"


class SecretStore(Protocol):
    def get(self, service: str, account: str) -> str | None: ...

    def set(self, service: str, account: str, secret: str) -> None: ...


class AgeRunner(Protocol):
    def generate_identity(self) -> tuple[str, str]: ...

    def recipient_for_identity(self, identity: str) -> str: ...

    def encrypt_file(self, source: Path, destination: Path, recipient: str) -> None: ...

    def decrypt_file(self, source: Path, destination: Path, identity: str) -> None: ...

    def encrypt_recovery_file(
        self, identity: str, destination: Path
    ) -> None: ...

    def decrypt_recovery_file(self, source: Path) -> str: ...


class _KeyringSecretStore:
    def __init__(self, backend: object) -> None:
        self._backend = backend

    def get(self, service: str, account: str) -> str | None:
        return self._backend.get_password(service, account)  # type: ignore[attr-defined, no-any-return]

    def set(self, service: str, account: str, secret: str) -> None:
        self._backend.set_password(service, account, secret)  # type: ignore[attr-defined]


def _secure_secret_store() -> SecretStore:
    try:
        import keyring
    except ImportError as exc:
        raise RuntimeError(
            "archive encryption requires the keyring optional dependency"
        ) from exc
    backend = keyring.get_keyring()
    module = type(backend).__module__.casefold()
    name = type(backend).__name__.casefold()
    try:
        priority = float(backend.priority)
    except (AttributeError, TypeError, ValueError) as exc:
        raise RuntimeError("archive encryption keyring backend is unavailable") from exc
    allowed = (
        (module == "keyring.backends.macos" and name == "keyring")
        or (module == "keyring.backends.secretservice" and name == "keyring")
        or (module == "keyring.backends.kwallet" and "keyring" in name)
        or (module == "keyring.backends.windows" and name in {"winvaultkeyring", "keyring"})
    )
    if priority <= 0 or not allowed:
        raise RuntimeError("archive encryption requires a secure keyring backend")
    return _KeyringSecretStore(backend)


class SubprocessAgeRunner:
    def __init__(self) -> None:
        self.age = self._tool("age")
        self.age_keygen = self._tool("age-keygen")

    @staticmethod
    def _tool(name: str) -> str:
        executable = shutil.which(name)
        if executable is None:
            raise RuntimeError(f"archive encryption requires {name}")
        return executable

    @staticmethod
    def _write_identity(path: Path, identity: str) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(identity)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def generate_identity(self) -> tuple[str, str]:
        with tempfile.TemporaryDirectory(prefix="sesh-compresh-age-key.") as raw:
            identity_path = Path(raw) / "identity.txt"
            result = subprocess.run(
                [self.age_keygen, "-o", str(identity_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            identity = identity_path.read_text(encoding="ascii").strip()
            recipient = self.recipient_for_identity(identity)
            if result.stderr and "Public key:" not in result.stderr:
                raise RuntimeError("age-keygen returned unexpected output")
            return identity, recipient

    def recipient_for_identity(self, identity: str) -> str:
        _validate_identity(identity)
        with tempfile.TemporaryDirectory(prefix="sesh-compresh-age-key.") as raw:
            identity_path = Path(raw) / "identity.txt"
            self._write_identity(identity_path, identity)
            result = subprocess.run(
                [self.age_keygen, "-y", str(identity_path)],
                capture_output=True,
                text=True,
                check=True,
            )
        recipient = result.stdout.strip()
        _validate_recipient(recipient)
        return recipient

    def encrypt_file(self, source: Path, destination: Path, recipient: str) -> None:
        _validate_recipient(recipient)
        subprocess.run(
            [
                self.age,
                "--encrypt",
                "--recipient",
                recipient,
                "--output",
                str(destination),
                str(source),
            ],
            check=True,
        )

    def decrypt_file(self, source: Path, destination: Path, identity: str) -> None:
        _validate_identity(identity)
        with tempfile.TemporaryDirectory(prefix="sesh-compresh-age-key.") as raw:
            identity_path = Path(raw) / "identity.txt"
            self._write_identity(identity_path, identity)
            subprocess.run(
                [
                    self.age,
                    "--decrypt",
                    "--identity",
                    str(identity_path),
                    "--output",
                    str(destination),
                    str(source),
                ],
                check=True,
            )

    def encrypt_recovery_file(self, identity: str, destination: Path) -> None:
        """Ask age for a passphrase on its controlling terminal."""

        _validate_identity(identity)
        with tempfile.TemporaryDirectory(prefix="sesh-compresh-age-key.") as raw:
            identity_path = Path(raw) / "identity.txt"
            self._write_identity(identity_path, identity)
            subprocess.run(
                [
                    self.age,
                    "--passphrase",
                    "--output",
                    str(destination),
                    str(identity_path),
                ],
                check=True,
            )

    def decrypt_recovery_file(self, source: Path) -> str:
        with tempfile.TemporaryDirectory(prefix="sesh-compresh-age-key.") as raw:
            identity_path = Path(raw) / "identity.txt"
            subprocess.run(
                [
                    self.age,
                    "--decrypt",
                    "--output",
                    str(identity_path),
                    str(source),
                ],
                check=True,
            )
            identity = identity_path.read_text(encoding="ascii").strip()
        _validate_identity(identity)
        return identity


def _validate_recipient(recipient: str) -> str:
    if not isinstance(recipient, str) or _AGE_RECIPIENT.fullmatch(recipient) is None:
        raise ValueError("archive encryption recipient is invalid")
    return recipient


def _validate_identity(identity: str) -> str:
    if not isinstance(identity, str) or _AGE_IDENTITY.fullmatch(identity) is None:
        raise ValueError("archive encryption identity is invalid")
    return identity


def _config_path(paths: AppPaths) -> Path:
    return paths.archive / "encryption.json"


def _enable_intent_path(paths: AppPaths) -> Path:
    return paths.state / "encryption-enable.json"


def _enable_recovery_stage(paths: AppPaths) -> Path:
    return paths.state / "encryption-enable-recovery.age"


def _key_id(recipient: str) -> str:
    return hashlib.sha256(recipient.encode("ascii")).hexdigest()


def encryption_config(paths: AppPaths) -> dict[str, object] | None:
    path = _config_path(paths)
    if not path.exists() and not path.is_symlink():
        return None
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or (os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o600)
        or (
            os.name != "nt"
            and hasattr(os, "getuid")
            and info.st_uid != os.getuid()
        )
    ):
        raise ValueError(f"archive encryption config is unsafe: {path}")
    config = load_json(path)
    if (
        set(config) != _CONFIG_KEYS
        or type(config.get("schema_version")) is not int
        or config["schema_version"] != SCHEMA_VERSION
        or config.get("kind") != "archive-encryption"
        or config.get("algorithm") != "age-x25519"
        or not isinstance(config.get("recipient"), str)
        or not isinstance(config.get("key_id"), str)
        or not isinstance(config.get("created_at"), str)
    ):
        raise ValueError(f"archive encryption config is invalid: {path}")
    recipient = _validate_recipient(config["recipient"])
    if config["key_id"] != _key_id(recipient):
        raise ValueError(f"archive encryption key identity is invalid: {path}")
    try:
        from .common import parse_timestamp

        if iso_utc(parse_timestamp(config["created_at"])) != config["created_at"]:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"archive encryption creation timestamp is invalid: {path}"
        ) from exc
    return config


def _secret_store(store: SecretStore | None) -> SecretStore:
    return store if store is not None else _secure_secret_store()


def _age_runner(runner: AgeRunner | None) -> AgeRunner:
    return runner if runner is not None else SubprocessAgeRunner()


def require_archive_identity(
    paths: AppPaths,
    *,
    store: SecretStore | None = None,
    runner: AgeRunner | None = None,
) -> tuple[dict[str, object], str] | None:
    config = encryption_config(paths)
    if config is None:
        return None
    identity = _secret_store(store).get(_KEYRING_SERVICE, str(config["key_id"]))
    if identity is None:
        raise RuntimeError(
            "archive encryption key is unavailable; restore it from the recovery file"
        )
    identity = _validate_identity(identity)
    if _age_runner(runner).recipient_for_identity(identity) != config["recipient"]:
        raise RuntimeError("archive encryption key does not match this archive")
    return config, identity


def encryption_status(
    paths: AppPaths,
    *,
    store: SecretStore | None = None,
    runner: AgeRunner | None = None,
) -> dict[str, object]:
    paths.ensure_private()
    config = encryption_config(paths)
    if config is None:
        return {"enabled": False, "key_available": False}
    key_available = False
    try:
        identity = _secret_store(store).get(
            _KEYRING_SERVICE, str(config["key_id"])
        )
        key_available = (
            identity is not None
            and _validate_identity(identity) == identity
            and _age_runner(runner).recipient_for_identity(identity)
            == config["recipient"]
        )
    except (RuntimeError, ValueError):
        key_available = False
    return {
        "enabled": True,
        "key_available": key_available,
        "algorithm": config["algorithm"],
        "recipient": config["recipient"],
        "key_id": config["key_id"],
    }


def _require_empty_directory(path: Path, label: str) -> None:
    with os.scandir(path) as entries:
        if next(entries, None) is not None:
            raise RuntimeError(f"archive encryption requires an empty {label}")


def _require_empty_archive(paths: AppPaths) -> None:
    paths.ensure_private()
    if encryption_config(paths) is not None:
        raise RuntimeError("archive encryption is already enabled")
    for path, label in (
        (paths.archive / "manifests", "manifest store"),
        (paths.archive / "dictionaries", "dictionary store"),
        (paths.archive / "objects" / "sha256", "CAS"),
        (paths.state / "quarantine", "quarantine"),
        (paths.state / "latest", "latest-index store"),
    ):
        _require_empty_directory(path, label)
    portable_imports = paths.state / "portable-imports"
    if portable_imports.exists() or portable_imports.is_symlink():
        if portable_imports.is_symlink() or not portable_imports.is_dir():
            raise RuntimeError("archive encryption portable-import staging is unsafe")
        _require_empty_directory(portable_imports, "portable-import staging")
    canary = paths.state / "archive-canary.json"
    if canary.exists() or canary.is_symlink():
        raise RuntimeError("archive encryption requires no existing restore canary")


def _recovery_destination(path: Path, *, allow_existing: bool = False) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise ValueError("archive encryption recovery file must be absolute")
    parent = expanded.parent.resolve(strict=True)
    destination = parent / expanded.name
    if not allow_existing and (destination.exists() or destination.is_symlink()):
        raise FileExistsError(
            f"archive encryption recovery file exists: {destination}"
        )
    return destination


def _load_enable_intent(paths: AppPaths) -> dict[str, object] | None:
    path = _enable_intent_path(paths)
    if not path.exists() and not path.is_symlink():
        return None
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or (os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o600)
        or (
            os.name != "nt"
            and hasattr(os, "getuid")
            and info.st_uid != os.getuid()
        )
    ):
        raise ValueError(f"archive encryption enable intent is unsafe: {path}")
    intent = load_json(path)
    if (
        set(intent) != _ENABLE_INTENT_KEYS
        or type(intent.get("schema_version")) is not int
        or intent["schema_version"] != SCHEMA_VERSION
        or intent.get("kind") != "archive-encryption-enable"
        or not isinstance(intent.get("recipient"), str)
        or not isinstance(intent.get("key_id"), str)
        or not isinstance(intent.get("created_at"), str)
        or not isinstance(intent.get("recovery_file"), str)
        or not Path(intent["recovery_file"]).is_absolute()
        or not isinstance(intent.get("recovery_sha256"), str)
        or len(intent["recovery_sha256"]) != 64
    ):
        raise ValueError(f"archive encryption enable intent is invalid: {path}")
    recipient = _validate_recipient(intent["recipient"])
    if intent["key_id"] != _key_id(recipient):
        raise ValueError(f"archive encryption enable intent key is invalid: {path}")
    try:
        from .common import parse_timestamp

        if iso_utc(parse_timestamp(intent["created_at"])) != intent["created_at"]:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"archive encryption enable timestamp is invalid: {path}"
        ) from exc
    return intent


def _recovery_matches(path: Path, expected_sha256: str) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink < 1
        or (os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o600)
    ):
        raise RuntimeError(f"archive encryption recovery file is unsafe: {path}")
    return _sha256_path(path) == expected_sha256


def _publish_recovery_stage(
    stage: Path, destination: Path, expected_sha256: str
) -> None:
    source_fd = os.open(stage, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    fd, raw = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".recovery", dir=destination.parent
    )
    temporary = Path(raw)
    try:
        os.fchmod(fd, 0o600)
        os.lseek(source_fd, 0, os.SEEK_SET)
        while block := os.read(source_fd, 4 * 1024 * 1024):
            view = memoryview(block)
            while view:
                written = os.write(fd, view)
                view = view[written:]
        os.fsync(fd)
        retained = os.fstat(fd)
        if not stat.S_ISREG(retained.st_mode) or _sha256_fd(fd) != expected_sha256:
            raise RuntimeError("archive encryption staged recovery changed")
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError:
            if _recovery_matches(destination, expected_sha256):
                fsync_dir(destination.parent)
                return
            raise FileExistsError(
                f"archive encryption recovery file exists: {destination}"
            ) from None
        try:
            published = destination.stat(follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError(
                "archive encryption recovery publication changed"
            ) from exc
        if (
            not stat.S_ISREG(published.st_mode)
            or (published.st_dev, published.st_ino)
            != (retained.st_dev, retained.st_ino)
            or _sha256_fd(fd) != expected_sha256
            or not _recovery_matches(destination, expected_sha256)
        ):
            raise RuntimeError("archive encryption recovery publication changed")
        os.fsync(fd)
        fsync_dir(destination.parent)
    finally:
        os.close(source_fd)
        os.close(fd)
        try:
            current = temporary.stat(follow_symlinks=False)
            if (
                stat.S_ISREG(current.st_mode)
                and (current.st_dev, current.st_ino)
                == (retained.st_dev, retained.st_ino)
            ):
                temporary.unlink()
        except (FileNotFoundError, UnboundLocalError):
            pass


def _sha256_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while block := os.read(fd, 4 * 1024 * 1024):
        digest.update(block)
    return digest.hexdigest()


def _finish_enable_intent(
    paths: AppPaths,
    intent: dict[str, object],
    *,
    store: SecretStore,
    runner: AgeRunner,
    identity: str | None,
) -> dict[str, object]:
    destination = Path(str(intent["recovery_file"]))
    stage = _enable_recovery_stage(paths)
    expected_sha256 = str(intent["recovery_sha256"])
    if not _recovery_matches(stage, expected_sha256):
        raise RuntimeError("archive encryption staged recovery is unavailable")
    _publish_recovery_stage(stage, destination, expected_sha256)
    key_id = str(intent["key_id"])
    stored = store.get(_KEYRING_SERVICE, key_id)
    if stored is None:
        stored = identity or runner.decrypt_recovery_file(stage)
        _validate_identity(stored)
        if runner.recipient_for_identity(stored) != intent["recipient"]:
            raise RuntimeError("archive recovery key does not match the enable intent")
        store.set(_KEYRING_SERVICE, key_id, stored)
    stored = _validate_identity(stored)
    if runner.recipient_for_identity(stored) != intent["recipient"]:
        raise RuntimeError("archive encryption key does not match the enable intent")
    if store.get(_KEYRING_SERVICE, key_id) != stored:
        raise RuntimeError("archive encryption keychain write was not durable")
    config = {
        "schema_version": SCHEMA_VERSION,
        "kind": "archive-encryption",
        "algorithm": "age-x25519",
        "recipient": intent["recipient"],
        "key_id": key_id,
        "created_at": intent["created_at"],
    }
    config_path = _config_path(paths)
    if config_path.exists() or config_path.is_symlink():
        if encryption_config(paths) != config:
            raise RuntimeError("archive encryption config conflicts with enable intent")
    else:
        atomic_json(config_path, config, replace=False)
    stage.unlink()
    fsync_dir(stage.parent)
    enable_intent = _enable_intent_path(paths)
    enable_intent.unlink()
    fsync_dir(enable_intent.parent)
    return {
        "enabled": True,
        "key_available": True,
        "recovery_file": str(destination),
        "recipient": intent["recipient"],
        "key_id": key_id,
    }


def enable_archive_encryption(
    paths: AppPaths,
    recovery_file: Path,
    *,
    store: SecretStore | None = None,
    runner: AgeRunner | None = None,
) -> dict[str, object]:
    with app_lock(paths):
        selected_store = _secret_store(store)
        selected_runner = _age_runner(runner)
        intent = _load_enable_intent(paths)
        if intent is not None:
            destination = _recovery_destination(recovery_file, allow_existing=True)
            if destination != Path(str(intent["recovery_file"])):
                raise RuntimeError(
                    "archive encryption enable is pending for another recovery file"
                )
            return _finish_enable_intent(
                paths,
                intent,
                store=selected_store,
                runner=selected_runner,
                identity=None,
            )
        destination = _recovery_destination(recovery_file)
        _require_empty_archive(paths)
        identity, recipient = selected_runner.generate_identity()
        _validate_identity(identity)
        _validate_recipient(recipient)
        if selected_runner.recipient_for_identity(identity) != recipient:
            raise RuntimeError("age identity does not match its recipient")
        key_id = _key_id(recipient)
        stage = _enable_recovery_stage(paths)
        if stage.exists() or stage.is_symlink():
            raise RuntimeError("archive encryption recovery staging already exists")
        selected_runner.encrypt_recovery_file(identity, stage)
        info = regular_file_stat(stage)
        if info["size"] <= 0:
            raise RuntimeError("archive encryption recovery file is empty")
        stage.chmod(0o600)
        with stage.open("rb") as handle:
            os.fsync(handle.fileno())
        fsync_dir(stage.parent)
        recovery_sha256 = _sha256_path(stage)
        intent = {
            "schema_version": SCHEMA_VERSION,
            "kind": "archive-encryption-enable",
            "recipient": recipient,
            "key_id": key_id,
            "created_at": iso_utc(utc_now()),
            "recovery_file": str(destination),
            "recovery_sha256": recovery_sha256,
        }
        atomic_json(_enable_intent_path(paths), intent, replace=False)
        return _finish_enable_intent(
            paths,
            intent,
            store=selected_store,
            runner=selected_runner,
            identity=identity,
        )


def restore_archive_key(
    paths: AppPaths,
    recovery_file: Path,
    *,
    store: SecretStore | None = None,
    runner: AgeRunner | None = None,
) -> dict[str, object]:
    paths.ensure_private()
    config = encryption_config(paths)
    if config is None:
        raise RuntimeError("archive encryption is not enabled")
    recovery = recovery_file.expanduser().resolve(strict=True)
    regular_file_stat(recovery)
    selected_runner = _age_runner(runner)
    identity = selected_runner.decrypt_recovery_file(recovery)
    _validate_identity(identity)
    if selected_runner.recipient_for_identity(identity) != config["recipient"]:
        raise RuntimeError("archive recovery key does not match this archive")
    selected_store = _secret_store(store)
    selected_store.set(_KEYRING_SERVICE, str(config["key_id"]), identity)
    if selected_store.get(_KEYRING_SERVICE, str(config["key_id"])) != identity:
        raise RuntimeError("archive encryption keychain write was not durable")
    return {
        "restored": True,
        "key_id": config["key_id"],
        "recipient": config["recipient"],
    }


def encrypt_cas_payload(
    paths: AppPaths,
    source: Path,
    destination: Path,
    *,
    store: SecretStore | None = None,
    runner: AgeRunner | None = None,
) -> None:
    available = require_archive_identity(paths, store=store, runner=runner)
    if available is None:
        shutil.copyfile(source, destination)
        return
    config, _ = available
    _age_runner(runner).encrypt_file(
        source, destination, str(config["recipient"])
    )
    regular_file_stat(destination)


@contextmanager
def materialize_cas_payload(
    paths: AppPaths,
    source: Path,
    *,
    expected_sha256: str | None = None,
    store: SecretStore | None = None,
    runner: AgeRunner | None = None,
) -> Iterator[Path]:
    available = require_archive_identity(paths, store=store, runner=runner)
    if available is None:
        if expected_sha256 is not None and _sha256_path(source) != expected_sha256:
            raise ValueError(f"archive CAS plaintext digest mismatch: {source}")
        yield source
        return
    _, identity = available
    root = ensure_private_subdirectory(paths.state, "encryption-materialize")
    fd, raw = tempfile.mkstemp(prefix="payload.", suffix=".zst", dir=root)
    os.close(fd)
    materialized = Path(raw)
    try:
        materialized.unlink()
        _age_runner(runner).decrypt_file(source, materialized, identity)
        regular_file_stat(materialized)
        materialized.chmod(0o600)
        if expected_sha256 is not None and _sha256_path(materialized) != expected_sha256:
            raise ValueError(f"archive CAS plaintext digest mismatch: {source}")
        yield materialized
    finally:
        materialized.unlink(missing_ok=True)


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(4 * 1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def cas_plaintext_sha256(
    paths: AppPaths,
    source: Path,
    *,
    store: SecretStore | None = None,
    runner: AgeRunner | None = None,
) -> str:
    with materialize_cas_payload(
        paths, source, store=store, runner=runner
    ) as materialized:
        return _sha256_path(materialized)
