from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sesh_compresh.dictionary_benchmark as benchmark_module
from sesh_compresh.archive import _zstd_binary
from sesh_compresh.dictionary_benchmark import (
    benchmark_dictionary_candidate,
    split_dictionary_corpus,
)


class DictionaryBenchmarkTests(unittest.TestCase):
    def test_split_is_content_unique_deterministic_and_disjoint(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            candidates = []
            for index in range(12):
                path = root / f"sample-{index:02d}.jsonl"
                path.write_text(f'{{"sample":{index}}}\n', encoding="utf-8")
                candidates.append(path)
            duplicate = root / "duplicate.jsonl"
            duplicate.write_bytes(candidates[3].read_bytes())

            first = split_dictionary_corpus(
                [*reversed(candidates), duplicate], root / "first", sample_limit=12
            )
            second = split_dictionary_corpus(
                [duplicate, *candidates], root / "second", sample_limit=12
            )

            training, holdout, duplicates = first
            second_training, second_holdout, second_duplicates = second
            self.assertEqual(1, duplicates)
            self.assertEqual(duplicates, second_duplicates)
            self.assertEqual(
                [path.read_bytes() for path in training],
                [path.read_bytes() for path in second_training],
            )
            self.assertEqual(
                [path.read_bytes() for path in holdout],
                [path.read_bytes() for path in second_holdout],
            )
            self.assertEqual(12, len(training) + len(holdout))
            self.assertFalse(set(training) & set(holdout))
            self.assertGreaterEqual(len(training), 8)
            self.assertGreaterEqual(len(holdout), 2)

    def test_benchmark_charges_dictionary_and_verifies_both_recipes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            samples = []
            for index in range(80):
                path = root / f"sample-{index:03d}.jsonl"
                lines = [
                    json.dumps(
                        {
                            "type": "user",
                            "sessionId": f"session-{index}",
                            "requestId": f"request-{index}-{record}",
                            "content": "shared dictionary vocabulary " * 80,
                        }
                    )
                    for record in range(12)
                ]
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                samples.append(path)
            training, holdout, _ = split_dictionary_corpus(
                samples, root / "corpus", sample_limit=80
            )
            candidate = root / "scratch/candidate.dict"

            report = benchmark_dictionary_candidate(
                _zstd_binary(),
                training,
                holdout,
                candidate,
                incumbent=None,
                max_dict_bytes=1024,
                minimum_benefit_bytes=0,
            )

            self.assertEqual(len(training), report["training_samples"])
            self.assertEqual(len(holdout), report["holdout_samples"])
            self.assertEqual(
                report["gross_savings_bytes"] - report["candidate_dictionary_bytes"],
                report["measured_benefit_bytes"],
            )
            self.assertEqual(report["measured_benefit_bytes"] > 0, report["beneficial"])

    def test_invalid_configuration_stops_before_candidate_creation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            samples = []
            for index in range(10):
                path = root / f"sample-{index}.txt"
                path.write_text(str(index), encoding="utf-8")
                samples.append(path)
            training, holdout, _ = split_dictionary_corpus(
                samples, root / "corpus", sample_limit=10
            )
            candidate = root / "candidate.dict"

            with self.assertRaisesRegex(ValueError, "non-negative"):
                benchmark_dictionary_candidate(
                    _zstd_binary(),
                    training,
                    holdout,
                    candidate,
                    incumbent=None,
                    max_dict_bytes=1024,
                    minimum_benefit_bytes=-1,
                )

            self.assertFalse(candidate.exists())

    def test_source_replacement_after_snapshot_cannot_change_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            samples = []
            for index in range(10):
                path = root / f"sample-{index}.txt"
                path.write_text(f"original-{index}", encoding="utf-8")
                samples.append(path)
            victim = samples[0]
            expected = victim.read_bytes()
            real_snapshot = benchmark_module._snapshot_sample

            def replace_after_copy(source, target):
                digest = real_snapshot(source, target)
                if source == victim:
                    source.unlink()
                    source.write_bytes(b"foreign replacement")
                return digest

            with mock.patch.object(
                benchmark_module,
                "_snapshot_sample",
                side_effect=replace_after_copy,
            ):
                training, holdout, _ = split_dictionary_corpus(
                    samples, root / "corpus", sample_limit=10
                )

            snapshots = [path.read_bytes() for path in [*training, *holdout]]
            self.assertIn(expected, snapshots)
            self.assertNotIn(b"foreign replacement", snapshots)


if __name__ == "__main__":
    unittest.main()
