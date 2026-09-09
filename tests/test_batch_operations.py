# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Unit tests for batch_operations module."""

import tempfile
import unittest
from unittest.mock import MagicMock, patch

from spsec_configurator.core.batch_operations import (
    BatchResult,
    batch_bootstrap_devices,
    batch_add_devices_to_group,
    batch_remove_devices_from_group,
    batch_factory_reset,
)
from spsec_configurator.core.group_manager import GroupManager, GroupKeys


class TestBatchOperations(unittest.TestCase):
    """Test batch operations on devices and groups."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.config_path = f"{self._dir.name}/groups_config.json"
        self.gm = GroupManager(self.config_path)

    def tearDown(self):
        self._dir.cleanup()

    def test_batch_bootstrap_devices(self):
        cfg = MagicMock()

        def mock_bootstrap(c, pid, int_k, int_s, int_id, seed_k, seed_s, seed_id):
            return 0 if pid == 120 else -1

        with patch("spsec_configurator.core.batch_operations.configurator_bootstrap_device", side_effect=mock_bootstrap):
            res = batch_bootstrap_devices(
                cfg,
                participant_ids=[120, 121],
                integrator_key=bytes(32),
                integrator_salt=bytes(8),
                integrator_key_id=1,
                seed_key=bytes(32),
                seed_salt=bytes(8),
                seed_key_id=2,
            )

            self.assertEqual(res.total, 2)
            self.assertEqual(res.successful, 1)
            self.assertEqual(res.failed, 1)
            self.assertEqual(res.failed_items, [121])
            self.assertIn(121, res.errors)

    def test_batch_add_devices_to_group(self):
        cfg = MagicMock()
        self.gm.create_group(1, "TestGroup")

        with patch("spsec_configurator.core.batch_operations.add_device_to_group_with_keys", return_value=0):
            res = batch_add_devices_to_group(cfg, self.gm, 1, [120, 121, 122])

            self.assertEqual(res.total, 3)
            self.assertEqual(res.successful, 3)
            self.assertEqual(res.failed, 0)

    def test_batch_remove_devices_from_group(self):
        cfg = MagicMock()
        self.gm.create_group(1, "TestGroup")
        self.gm.add_device_to_group(1, 120)
        self.gm.add_device_to_group(1, 121)

        with patch("spsec_configurator.core.batch_operations.remove_device_from_group", return_value=0):
            res = batch_remove_devices_from_group(cfg, self.gm, 1, [120, 121])

            self.assertEqual(res.total, 2)
            self.assertEqual(res.successful, 2)
            self.assertEqual(res.failed, 0)

    def test_batch_factory_reset(self):
        cfg = MagicMock()

        def mock_reset(c, pid):
            return 0 if pid != 122 else -1

        with patch("spsec_configurator.core.batch_operations.configurator_factory_reset", side_effect=mock_reset):
            res = batch_factory_reset(cfg, [120, 121, 122])

            self.assertEqual(res.total, 3)
            self.assertEqual(res.successful, 2)
            self.assertEqual(res.failed, 1)
            self.assertEqual(res.failed_items, [122])


if __name__ == "__main__":
    unittest.main()
