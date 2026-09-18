#
# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.
#

"""CONFIGURATOR_REQUIREMENTS.md §14.3: versioned config history and rollback.
Every groups_config.json mutation archives its prior contents so rollback can restore them.
"""

import os
import stat
import tempfile
import unittest

from spsec_configurator.core.config_history import (
    diff_versions,
    history_dir,
    list_versions,
    restore,
    snapshot,
    summarize,
)
from spsec_configurator.core.group_manager import GroupManager


class TestSnapshot(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.config = os.path.join(self._dir.name, "groups_config.json")

    def tearDown(self):
        self._dir.cleanup()

    def test_snapshot_of_missing_file_is_a_noop(self):
        self.assertIsNone(snapshot(self.config))
        self.assertEqual(list_versions(self.config), [])

    def test_snapshot_archives_current_contents(self):
        with open(self.config, "w") as fh:
            fh.write('{"version": "1.0", "groups": [], "devices": []}')

        path = snapshot(self.config)
        self.assertIsNotNone(path)
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(len(list_versions(self.config)), 1)

    def test_snapshots_are_not_world_readable(self):
        """The config carries group keys, so its archives must not leak."""
        with open(self.config, "w") as fh:
            fh.write("{}")
        path = snapshot(self.config)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode & 0o077, 0, f"snapshot mode too open: {oct(mode)}")

    def test_prunes_to_keep_limit(self):
        with open(self.config, "w") as fh:
            fh.write("{}")
        for _ in range(6):
            snapshot(self.config, keep=3)
        self.assertLessEqual(len(list_versions(self.config)), 3)

    def test_versions_are_newest_first(self):
        with open(self.config, "w") as fh:
            fh.write("{}")
        snapshot(self.config)
        snapshot(self.config)
        ids = [vid for vid, _ in list_versions(self.config)]
        self.assertEqual(ids, sorted(ids, reverse=True))


class TestHistoryThroughGroupManager(unittest.TestCase):
    """The hook in GroupManager._save_config is what makes this automatic."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.config = os.path.join(self._dir.name, "groups_config.json")

    def tearDown(self):
        self._dir.cleanup()

    def test_mutations_accumulate_history(self):
        gm = GroupManager(self.config)
        gm.create_group(1, "First")      # nothing on disk yet -> no snapshot
        gm.create_group(2, "Second")     # archives the 1-group state
        gm.create_group(3, "Third")      # archives the 2-group state

        versions = list_versions(self.config)
        self.assertGreaterEqual(len(versions), 2)

    def test_rollback_restores_previous_groups(self):
        gm = GroupManager(self.config)
        gm.create_group(1, "Keeper")
        gm.create_group(2, "Doomed")     # snapshot here still has only group 1

        # Oldest snapshot = the state with just group 1.
        oldest_version = list_versions(self.config)[-1][0]

        self.assertTrue(restore(self.config, oldest_version))

        reloaded = GroupManager(self.config)
        self.assertIsNotNone(reloaded.get_group(1))
        self.assertIsNone(reloaded.get_group(2), "group 2 should be rolled back")

    def test_rollback_is_itself_reversible(self):
        gm = GroupManager(self.config)
        gm.create_group(1, "Keeper")
        gm.create_group(2, "Doomed")
        before = len(list_versions(self.config))

        restore(self.config, list_versions(self.config)[-1][0])

        # Restoring archives the pre-rollback state, enabling forward progression again.
        self.assertGreater(len(list_versions(self.config)), before)

    def test_restore_unknown_version_fails(self):
        gm = GroupManager(self.config)
        gm.create_group(1, "Only")
        self.assertFalse(restore(self.config, "not-a-version"))

    def test_diff_reports_added_group(self):
        gm = GroupManager(self.config)
        gm.create_group(1, "Keeper")
        gm.create_group(2, "Added")

        oldest = list_versions(self.config)[-1][0]
        lines = diff_versions(self.config, oldest)

        self.assertIsNotNone(lines)
        self.assertTrue(
            any("group 2" in line and line.startswith("+") for line in lines),
            f"expected group 2 reported as added, got: {lines}",
        )

    def test_diff_unknown_version_returns_none(self):
        gm = GroupManager(self.config)
        gm.create_group(1, "Only")
        self.assertIsNone(diff_versions(self.config, "nope"))


class TestSummarize(unittest.TestCase):
    def test_summarize_malformed_json_does_not_raise(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "broken.json")
            with open(path, "w") as fh:
                fh.write("{ this is not json")
            info = summarize(path)
            self.assertIn("error", info)


if __name__ == "__main__":
    unittest.main()
