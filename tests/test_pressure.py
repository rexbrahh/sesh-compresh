from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sesh_compresh.archive as archive_module
import sesh_compresh.clean as clean_module
import sesh_compresh.common as common_module
import sesh_compresh.pressure as pressure_module
from sesh_compresh.common import AppPaths
from sesh_compresh.pressure import PressurePlanError, plan_disk_pressure


class DiskPressureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.paths = AppPaths.discover(self.home)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_reports_noop_at_trigger(self) -> None:
        usage = mock.Mock(total=1_000, used=200, free=800)
        source_device = self.home.stat().st_dev
        with (
            mock.patch.object(
                pressure_module.shutil, "disk_usage", return_value=usage
            ) as disk_usage,
            mock.patch.object(pressure_module, "create_archive_plan") as archive,
            mock.patch.object(pressure_module, "create_clean_plan") as clean,
        ):
            result = plan_disk_pressure(
                self.paths,
                trigger_free_bytes=800,
                target_free_bytes=900,
            )

        self.assertEqual(
            {
                "triggered": False,
                "partial": False,
                "filesystem_device": source_device,
                "disk_total_bytes": 1_000,
                "disk_used_bytes": 200,
                "disk_free_bytes": 800,
                "trigger_free_bytes": 800,
                "target_free_bytes": 900,
                "target_deficit_bytes": 100,
            },
            result,
        )
        disk_usage.assert_called_once_with(self.paths.home)
        archive.assert_not_called()
        clean.assert_not_called()

    def test_trigger_creates_device_scoped_plans_and_forwards_policy(
        self,
    ) -> None:
        usage = mock.Mock(total=1_000, used=750, free=250)
        source_device = self.home.stat().st_dev
        archive_path = self.home / "archive-plan.json"
        clean_path = self.home / "clean-plan.json"
        policy_path = self.home / "policy.json"
        with (
            mock.patch.object(
                pressure_module.shutil, "disk_usage", return_value=usage
            ),
            mock.patch.object(
                pressure_module,
                "create_archive_plan",
                return_value=(
                    archive_path,
                    {"sessions": [{}, {}], "logical_bytes": 300},
                ),
            ) as archive,
            mock.patch.object(
                pressure_module,
                "create_clean_plan",
                return_value=(
                    clean_path,
                    {"candidates": [{}], "allocated_bytes": 400},
                ),
            ) as clean,
        ):
            result = plan_disk_pressure(
                self.paths,
                trigger_free_bytes=300,
                target_free_bytes=600,
                policy_path=policy_path,
            )

        self.assertTrue(result["triggered"])
        self.assertFalse(result["partial"])
        self.assertEqual(source_device, result["filesystem_device"])
        self.assertEqual(350, result["target_deficit_bytes"])
        self.assertEqual(str(archive_path), result["archive_plan"])
        self.assertEqual(2, result["archive_sessions"])
        self.assertEqual(300, result["archive_logical_bytes"])
        self.assertEqual(str(clean_path), result["clean_plan"])
        self.assertEqual(1, result["clean_candidates"])
        self.assertEqual(400, result["clean_quarantined_bytes_candidate"])
        self.assertNotIn("reclaimed_bytes", result)
        self.assertNotIn("projected_free_bytes", result)
        archive.assert_called_once_with(
            self.paths, source_device=source_device, run_id=mock.ANY
        )
        clean.assert_called_once_with(
            self.paths,
            policy_path=policy_path,
            source_device=source_device,
            run_id=mock.ANY,
        )

    def test_child_failures_disclose_every_published_plan(self) -> None:
        usage = mock.Mock(total=1_000, used=900, free=100)
        clean_path = self.home / "clean-plan.json"
        clean_plan = {"candidates": [{}], "allocated_bytes": 400}
        cases = (
            ("clean", ValueError("clean failed"), None),
            ("archive", RuntimeError("archive failed"), str(clean_path)),
        )
        for stage, failure, expected_clean_path in cases:
            with self.subTest(stage=stage):
                with (
                    mock.patch.object(
                        pressure_module.shutil, "disk_usage", return_value=usage
                    ),
                    mock.patch.object(
                        pressure_module,
                        "create_clean_plan",
                        side_effect=(failure if stage == "clean" else None),
                        return_value=(clean_path, clean_plan),
                    ) as clean,
                    mock.patch.object(
                        pressure_module,
                        "create_archive_plan",
                        side_effect=(failure if stage == "archive" else None),
                    ) as archive,
                ):
                    with self.assertRaises(PressurePlanError) as raised:
                        plan_disk_pressure(
                            self.paths,
                            trigger_free_bytes=200,
                            target_free_bytes=500,
                        )

            result = raised.exception.result
            self.assertEqual(stage, result["failed_stage"])
            self.assertEqual(stage == "archive", result["partial"])
            self.assertEqual(failure.__class__.__name__, result["error_type"])
            self.assertEqual(str(failure), result["error"])
            if expected_clean_path is None:
                self.assertNotIn("clean_plan", result)
                archive.assert_not_called()
            else:
                self.assertEqual(expected_clean_path, result["clean_plan"])
                clean.assert_called_once()
                archive.assert_called_once()

    def test_clean_post_publication_failure_discloses_exact_plan(self) -> None:
        usage = mock.Mock(total=1_000, used=900, free=100)

        def publish_then_fail(path, payload, **kwargs):
            common_module.atomic_json(path, payload, **kwargs)
            raise OSError("clean plan directory sync failed")

        with (
            mock.patch.object(
                pressure_module.shutil, "disk_usage", return_value=usage
            ),
            mock.patch.object(clean_module, "open_file_paths", return_value=set()),
            mock.patch.object(clean_module, "discover_practical", return_value=[]),
            mock.patch.object(
                clean_module, "atomic_json", side_effect=publish_then_fail
            ),
            mock.patch.object(pressure_module, "create_archive_plan") as archive,
            self.assertRaises(PressurePlanError) as raised,
        ):
            plan_disk_pressure(
                self.paths,
                trigger_free_bytes=200,
                target_free_bytes=500,
            )

        result = raised.exception.result
        plan_path = Path(result["clean_plan"])
        self.assertTrue(result["partial"])
        self.assertEqual("clean", result["failed_stage"])
        self.assertTrue(plan_path.is_file())
        self.assertEqual("clean-plan", common_module.load_json(plan_path)["kind"])
        archive.assert_not_called()

    def test_archive_post_publication_failure_discloses_both_plans(self) -> None:
        usage = mock.Mock(total=1_000, used=900, free=100)

        def publish_then_fail(path, payload, **kwargs):
            common_module.atomic_json(path, payload, **kwargs)
            raise OSError("archive plan directory sync failed")

        with (
            mock.patch.object(
                pressure_module.shutil, "disk_usage", return_value=usage
            ),
            mock.patch.object(clean_module, "open_file_paths", return_value=set()),
            mock.patch.object(clean_module, "discover_practical", return_value=[]),
            mock.patch.object(archive_module, "open_file_paths", return_value=set()),
            mock.patch.object(archive_module, "discover_sessions", return_value=[]),
            mock.patch.object(
                archive_module, "atomic_json", side_effect=publish_then_fail
            ),
            self.assertRaises(PressurePlanError) as raised,
        ):
            plan_disk_pressure(
                self.paths,
                trigger_free_bytes=200,
                target_free_bytes=500,
            )

        result = raised.exception.result
        clean_path = Path(result["clean_plan"])
        archive_path = Path(result["archive_plan"])
        self.assertTrue(result["partial"])
        self.assertEqual("archive", result["failed_stage"])
        self.assertEqual("clean-plan", common_module.load_json(clean_path)["kind"])
        self.assertEqual(
            "archive-plan", common_module.load_json(archive_path)["kind"]
        )

    def test_thresholds_require_ordered_non_negative_exact_integers(self) -> None:
        invalid = (
            (True, 2),
            (1.0, 2),
            (-1, 2),
            (2, False),
            (2, 1.0),
            (2, -1),
            (3, 2),
        )
        with mock.patch.object(pressure_module.shutil, "disk_usage") as disk_usage:
            for trigger, target in invalid:
                with self.subTest(trigger=trigger, target=target):
                    with self.assertRaises(ValueError):
                        plan_disk_pressure(
                            self.paths,
                            trigger_free_bytes=trigger,
                            target_free_bytes=target,
                        )
            disk_usage.assert_not_called()


if __name__ == "__main__":
    unittest.main()
