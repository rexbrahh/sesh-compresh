from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Iterable


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot_sample(source: Path, target: Path) -> str:
    before = source.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"dictionary sample is not a regular file: {source}")
    digest = hashlib.sha256()
    with source.open("rb") as source_handle, target.open("xb") as target_handle:
        opened = os.fstat(source_handle.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError(f"dictionary sample changed before snapshot: {source}")
        while chunk := source_handle.read(4 * 1024 * 1024):
            digest.update(chunk)
            target_handle.write(chunk)
        after = os.fstat(source_handle.fileno())
        target_handle.flush()
        os.fsync(target_handle.fileno())
    current = source.lstat()
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        identity
        != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        )
        or identity
        != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        or identity
        != (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
        )
    ):
        raise RuntimeError(f"dictionary sample changed during snapshot: {source}")
    target.chmod(0o600)
    return digest.hexdigest()


def split_dictionary_corpus(
    candidates: Iterable[Path], snapshot_root: Path, *, sample_limit: int
) -> tuple[list[Path], list[Path], int]:
    """Return deterministic content-unique training and untouched holdout paths."""

    if type(sample_limit) is not int or sample_limit < 10:
        raise ValueError("dictionary benchmark needs at least 10 samples")
    snapshot_root.mkdir(parents=True, mode=0o700, exist_ok=False)
    unique: dict[str, Path] = {}
    total = 0
    for index, path in enumerate(sorted(candidates)):
        total += 1
        snapshot = snapshot_root / f"sample-{index:06d}"
        digest = _snapshot_sample(path, snapshot)
        if digest in unique:
            snapshot.unlink()
        else:
            unique[digest] = snapshot
    selected = [unique[digest] for digest in sorted(unique)[:sample_limit]]
    for snapshot in set(unique.values()) - set(selected):
        snapshot.unlink()
    if len(selected) < 10:
        raise ValueError(f"insufficient unique dictionary samples: {len(selected)}")
    holdout_count = max(2, len(selected) // 5)
    holdout_indexes = {
        round(index * (len(selected) - 1) / (holdout_count - 1))
        for index in range(holdout_count)
    }
    training = [
        path for index, path in enumerate(selected) if index not in holdout_indexes
    ]
    holdout = [path for index, path in enumerate(selected) if index in holdout_indexes]
    if len(training) < 8:
        raise ValueError("dictionary benchmark needs at least 8 training samples")
    return training, holdout, total - len(unique)


def _verify_frame(
    zstd: str, frame: Path, source: Path, *, dictionary: Path | None
) -> None:
    flags = ["-D", str(dictionary)] if dictionary is not None else []
    subprocess.run([zstd, "-q", "-t", *flags, str(frame)], check=True)
    process = subprocess.Popen(
        [zstd, "-q", "-d", "--stdout", *flags, str(frame)],
        stdout=subprocess.PIPE,
    )
    assert process.stdout is not None
    digest = hashlib.sha256()
    with process.stdout:
        while chunk := process.stdout.read(4 * 1024 * 1024):
            digest.update(chunk)
    if process.wait() != 0 or digest.hexdigest() != _sha256_file(source):
        raise RuntimeError(f"dictionary benchmark decode mismatch: {source}")


def _compress_frame(
    zstd: str,
    source: Path,
    target: Path,
    *,
    dictionary: Path | None,
) -> int:
    flags = ["-D", str(dictionary)] if dictionary is not None else []
    subprocess.run(
        [zstd, "-q", "-6", *flags, "-f", str(source), "-o", str(target)],
        check=True,
    )
    _verify_frame(zstd, target, source, dictionary=dictionary)
    return target.stat().st_size


def benchmark_dictionary_candidate(
    zstd: str,
    training: list[Path],
    holdout: list[Path],
    candidate: Path,
    *,
    incumbent: Path | None,
    max_dict_bytes: int,
    minimum_benefit_bytes: int,
) -> dict[str, Any]:
    """Train and measure a temporary candidate against the current recipe."""

    if len(training) < 8 or len(holdout) < 2 or set(training) & set(holdout):
        raise ValueError("dictionary benchmark split is invalid")
    if type(max_dict_bytes) is not int or max_dict_bytes < 1024:
        raise ValueError("dictionary size must be at least 1024 bytes")
    if type(minimum_benefit_bytes) is not int or minimum_benefit_bytes < 0:
        raise ValueError("minimum dictionary benefit must be a non-negative integer")
    candidate.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            zstd,
            "-q",
            "--train",
            *(str(path) for path in training),
            "-o",
            str(candidate),
            f"--maxdict={max_dict_bytes}",
        ],
        check=True,
    )
    candidate.chmod(0o600)
    with candidate.open("rb") as handle:
        os.fsync(handle.fileno())

    incumbent_bytes = 0
    candidate_bytes = 0
    raw_bytes = 0
    for index, source in enumerate(holdout):
        raw_bytes += source.stat().st_size
        incumbent_bytes += _compress_frame(
            zstd,
            source,
            candidate.parent / f"incumbent-{index}.zst",
            dictionary=incumbent,
        )
        candidate_bytes += _compress_frame(
            zstd,
            source,
            candidate.parent / f"candidate-{index}.zst",
            dictionary=candidate,
        )
    dictionary_bytes = candidate.stat().st_size
    gross_savings = incumbent_bytes - candidate_bytes
    measured_benefit = gross_savings - dictionary_bytes
    return {
        "training_samples": len(training),
        "holdout_samples": len(holdout),
        "holdout_raw_bytes": raw_bytes,
        "incumbent": "dictionary" if incumbent is not None else "plain",
        "incumbent_compressed_bytes": incumbent_bytes,
        "candidate_compressed_bytes": candidate_bytes,
        "candidate_dictionary_bytes": dictionary_bytes,
        "gross_savings_bytes": gross_savings,
        "measured_benefit_bytes": measured_benefit,
        "minimum_benefit_bytes": minimum_benefit_bytes,
        "beneficial": measured_benefit > minimum_benefit_bytes,
    }
