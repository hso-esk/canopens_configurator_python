# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Unit tests for config_import_export module."""

import json
import os
import stat
import tempfile
import unittest

from spsec_configurator.core.config_import_export import (
    export_configuration,
    import_configuration,
    export_group_keys,
    import_group_keys,
)
from spsec_configurator.core.group_manager import GroupManager, GroupKeys


def _sample_keys() -> GroupKeys:
    return GroupKeys(
        integrator_key=bytes(range(32)),
        integrator_salt=bytes(range(8)),
        integrator_key_id=0x11223344,
        seed_key=bytes(range(32, 64)),
        seed_salt=bytes(range(8, 16)),
        seed_key_id=0x55667788,
    )


class TestConfigImportExport(unittest.TestCase):
    """Test importing and exporting group configuration."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._dir.name, "groups_config.json")
        self.gm = GroupManager(self.config_path)

    def tearDown(self):
        self._dir.cleanup()

    def test_export_and_import_roundtrip(self):
        self.gm.create_group(1, "Group 1", "First group")
        self.gm.set_group_keys(1, _sample_keys())
        self.gm.register_device(120, device_type="Sensor", firmware_version="1.0")
        self.gm.add_device_to_group(1, 120)

        export_file = os.path.join(self._dir.name, "exported.json")
        self.assertTrue(export_configuration(self.gm, export_file))

        # Check permissions: 0600 (read/write only by owner)
        file_mode = stat.S_IMODE(os.stat(export_file).st_mode)
        self.assertEqual(file_mode, 0o600)

        # Import into a new empty group manager
        new_config_path = os.path.join(self._dir.name, "new_config.json")
        new_gm = GroupManager(new_config_path)

        self.assertTrue(import_configuration(new_gm, export_file, merge=False))
        self.assertEqual(len(new_gm.list_groups()), 1)
        self.assertEqual(new_gm.get_group(1).name, "Group 1")
        self.assertIn(120, new_gm.get_group(1).member_pids)
        self.assertIsNotNone(new_gm.get_group(1).group_keys)

    def test_export_group_keys_roundtrip(self):
        self.gm.create_group(2, "Group 2")
        keys = _sample_keys()
        self.gm.set_group_keys(2, keys)

        key_file = os.path.join(self._dir.name, "group2_keys.json")
        self.assertTrue(export_group_keys(self.gm, 2, key_file))

        file_mode = stat.S_IMODE(os.stat(key_file).st_mode)
        self.assertEqual(file_mode, 0o600)

        # Import into another group in another manager
        new_gm = GroupManager(os.path.join(self._dir.name, "keys_config.json"))
        new_gm.create_group(2, "Imported Group")
        self.assertTrue(import_group_keys(new_gm, 2, key_file))

        imported_keys = new_gm.get_group_keys(2)
        self.assertIsNotNone(imported_keys)
        self.assertEqual(imported_keys.integrator_key, keys.integrator_key)
        self.assertEqual(imported_keys.seed_key_id, keys.seed_key_id)

    def test_unsupported_format_rejected(self):
        self.assertFalse(export_configuration(self.gm, "foo.xml", format="xml"))
        self.assertFalse(import_configuration(self.gm, "foo.xml", format="xml"))

    def test_import_nonexistent_file_returns_false(self):
        self.assertFalse(import_configuration(self.gm, os.path.join(self._dir.name, "nonexistent.json")))
        self.assertFalse(import_group_keys(self.gm, 1, os.path.join(self._dir.name, "nonexistent.json")))


if __name__ == "__main__":
    unittest.main()
