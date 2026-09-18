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

import unittest
import tempfile
import secrets
from unittest.mock import patch, MagicMock

from spsec_configurator.core.group_manager import GroupManager, GroupKeys
from spsec_configurator.core.group_operations import (
    distribute_group_keys,
    update_group_keys,
    remove_device_from_group,
)
from spsec_configurator.core.keys import generate_key_id
from spsec_configurator.core.spsec_definitions import KEY_LEN, SALT_LEN


class TestGenerateKeyId(unittest.TestCase):
    """Test generate_key_id() range validation."""

    def test_generate_key_id_never_zero(self):
        """generate_key_id should never return 0 (uninstalled marker)."""
        for _ in range(5000):
            key_id = generate_key_id()
            self.assertNotEqual(key_id, 0, "generate_key_id returned 0 (uninstalled marker)")

    def test_generate_key_id_never_max(self):
        """generate_key_id should never return 0xFFFFFFFF (reserved invalidation)."""
        for _ in range(5000):
            key_id = generate_key_id()
            self.assertNotEqual(key_id, 0xFFFFFFFF, "generate_key_id returned 0xFFFFFFFF (reserved)")

    def test_generate_key_id_in_valid_range(self):
        """generate_key_id should always be in range 1 .. 0xFFFFFFFE."""
        for _ in range(5000):
            key_id = generate_key_id()
            self.assertGreaterEqual(key_id, 1)
            self.assertLessEqual(key_id, 0xFFFFFFFE)

    def test_generate_key_id_varies(self):
        """generate_key_id should produce different values across calls."""
        ids = set(generate_key_id() for _ in range(100))
        self.assertGreater(len(ids), 90, "generate_key_id produced too many duplicates")


def _make_keys() -> GroupKeys:
    """A fresh random group key set."""
    return GroupKeys(
        integrator_key=secrets.token_bytes(KEY_LEN),
        integrator_salt=secrets.token_bytes(SALT_LEN),
        integrator_key_id=generate_key_id(),
        seed_key=secrets.token_bytes(KEY_LEN),
        seed_salt=secrets.token_bytes(SALT_LEN),
        seed_key_id=generate_key_id(),
    )


class TestUpdateGroupKeys(unittest.TestCase):
    """Test update_group_keys ordering and rollback."""

    def setUp(self):
        """Create a temporary config directory and GroupManager."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_file = f"{self.temp_dir.name}/config.json"
        self.group_manager = GroupManager(self.config_file)

    def tearDown(self):
        """Clean up temporary directory."""
        self.temp_dir.cleanup()

    def test_update_group_keys_distributes_new_keys(self):
        """update_group_keys should distribute the NEW keys, not the old ones."""
        # Create a group with two members
        group = self.group_manager.create_group(1, "TestGroup")
        old_keys = GroupKeys(
            integrator_key=secrets.token_bytes(KEY_LEN),
            integrator_salt=secrets.token_bytes(SALT_LEN),
            integrator_key_id=generate_key_id(),
            seed_key=secrets.token_bytes(KEY_LEN),
            seed_salt=secrets.token_bytes(SALT_LEN),
            seed_key_id=generate_key_id(),
        )
        self.group_manager.set_group_keys(1, old_keys)
        self.group_manager.add_device_to_group(1, 100)
        self.group_manager.add_device_to_group(1, 101)

        new_keys = GroupKeys(
            integrator_key=secrets.token_bytes(KEY_LEN),
            integrator_salt=secrets.token_bytes(SALT_LEN),
            integrator_key_id=generate_key_id(),
            seed_key=secrets.token_bytes(KEY_LEN),
            seed_salt=secrets.token_bytes(SALT_LEN),
            seed_key_id=generate_key_id(),
        )

        # Record which seed keys were written to which PIDs
        recorded_calls = {}

        def mock_bootstrap(cfg, pid, int_key, int_salt, int_key_id,
                          seed_key, seed_salt, seed_key_id):
            recorded_calls[pid] = seed_key
            return 0

        cfg = MagicMock()

        with patch("spsec_configurator.core.group_operations.configurator_bootstrap_device", side_effect=mock_bootstrap), \
             patch("spsec_configurator.core.group_operations.verify_group_keys",
                   return_value=(True, [])):
            ret = update_group_keys(cfg, self.group_manager, 1, new_keys)

        self.assertEqual(ret, 0, "update_group_keys should return 0")
        self.assertIn(100, recorded_calls, "PID 100 should have been provisioned")
        self.assertIn(101, recorded_calls, "PID 101 should have been provisioned")
        self.assertEqual(recorded_calls[100], new_keys.seed_key,
                        f"PID 100 seed key should be the new key, not the old one")
        self.assertEqual(recorded_calls[101], new_keys.seed_key,
                        f"PID 101 seed key should be the new key, not the old one")

    def test_update_group_keys_reverts_when_a_member_never_acknowledges(self):
        """A member that never reports the new Key IDs must revert the rollout -
        else the group splits across two key generations."""
        self.group_manager.create_group(7, "AckTimeout")
        old_keys = _make_keys()
        self.group_manager.set_group_keys(7, old_keys)
        self.group_manager.add_device_to_group(7, 700)
        new_keys = _make_keys()

        cfg = MagicMock()
        with patch("spsec_configurator.core.group_operations.configurator_bootstrap_device",
                   return_value=0), \
             patch("spsec_configurator.core.group_operations.verify_group_keys",
                   return_value=(False, [700])):
            ret = update_group_keys(cfg, self.group_manager, 7, new_keys,
                                    ack_timeout_s=0.2)

        self.assertEqual(ret, -5, "an unacknowledged rollout must fail")
        stored = self.group_manager.get_group(7).group_keys
        self.assertEqual(stored.seed_key, old_keys.seed_key,
                         "stored keys must be reverted to the previous set")

    def test_update_group_keys_can_keep_new_keys_on_timeout(self):
        """revert_on_timeout=False reports the failure but keeps the new keys."""
        self.group_manager.create_group(8, "NoRevert")
        old_keys = _make_keys()
        self.group_manager.set_group_keys(8, old_keys)
        self.group_manager.add_device_to_group(8, 800)
        new_keys = _make_keys()

        cfg = MagicMock()
        with patch("spsec_configurator.core.group_operations.configurator_bootstrap_device",
                   return_value=0), \
             patch("spsec_configurator.core.group_operations.verify_group_keys",
                   return_value=(False, [800])):
            ret = update_group_keys(cfg, self.group_manager, 8, new_keys,
                                    ack_timeout_s=0.2, revert_on_timeout=False)

        self.assertEqual(ret, -5)
        stored = self.group_manager.get_group(8).group_keys
        self.assertEqual(stored.seed_key, new_keys.seed_key,
                         "new keys must be kept when revert is disabled")

    def test_update_group_keys_skips_ack_check_when_disabled(self):
        """ack_timeout_s=0 keeps the old behaviour: distribution result only."""
        self.group_manager.create_group(9, "NoAck")
        self.group_manager.set_group_keys(9, _make_keys())
        self.group_manager.add_device_to_group(9, 900)
        new_keys = _make_keys()

        cfg = MagicMock()
        with patch("spsec_configurator.core.group_operations.configurator_bootstrap_device",
                   return_value=0), \
             patch("spsec_configurator.core.group_operations.verify_group_keys") as verify:
            ret = update_group_keys(cfg, self.group_manager, 9, new_keys,
                                    ack_timeout_s=0)

        self.assertEqual(ret, 0)
        verify.assert_not_called()

    def test_update_group_keys_rolls_back_on_failure(self):
        """update_group_keys should roll back stored keys if distribution fails."""
        group = self.group_manager.create_group(2, "TestGroup2")
        old_keys = GroupKeys(
            integrator_key=secrets.token_bytes(KEY_LEN),
            integrator_salt=secrets.token_bytes(SALT_LEN),
            integrator_key_id=generate_key_id(),
            seed_key=secrets.token_bytes(KEY_LEN),
            seed_salt=secrets.token_bytes(SALT_LEN),
            seed_key_id=generate_key_id(),
        )
        self.group_manager.set_group_keys(2, old_keys)
        self.group_manager.add_device_to_group(2, 200)

        new_keys = GroupKeys(
            integrator_key=secrets.token_bytes(KEY_LEN),
            integrator_salt=secrets.token_bytes(SALT_LEN),
            integrator_key_id=generate_key_id(),
            seed_key=secrets.token_bytes(KEY_LEN),
            seed_salt=secrets.token_bytes(SALT_LEN),
            seed_key_id=generate_key_id(),
        )

        def mock_bootstrap_fail(cfg, pid, int_key, int_salt, int_key_id,
                               seed_key, seed_salt, seed_key_id):
            return -1  # Simulate failure

        cfg = MagicMock()

        with patch("spsec_configurator.core.group_operations.configurator_bootstrap_device", side_effect=mock_bootstrap_fail):
            ret = update_group_keys(cfg, self.group_manager, 2, new_keys)

        self.assertLess(ret, 0, "update_group_keys should return negative on failure")

        # Check that keys rolled back to old set
        rolled_back_keys = self.group_manager.get_group_keys(2)
        self.assertEqual(rolled_back_keys.seed_key, old_keys.seed_key,
                        "Seed key should have rolled back to the old value")
        self.assertEqual(rolled_back_keys.seed_key_id, old_keys.seed_key_id,
                        "Seed key ID should have rolled back to the old value")


class TestRemoveDeviceRekeySurvivors(unittest.TestCase):
    """Test remove_device_from_group with rekey_survivors."""

    def setUp(self):
        """Create a temporary config directory and GroupManager."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_file = f"{self.temp_dir.name}/config.json"
        self.group_manager = GroupManager(self.config_file)

    def tearDown(self):
        """Clean up temporary directory."""
        self.temp_dir.cleanup()

    def test_remove_device_rekeys_survivors(self):
        """remove_device_from_group with rekey_survivors=True should only update survivors."""
        group = self.group_manager.create_group(3, "TestGroup3")
        keys = GroupKeys(
            integrator_key=secrets.token_bytes(KEY_LEN),
            integrator_salt=secrets.token_bytes(SALT_LEN),
            integrator_key_id=generate_key_id(),
            seed_key=secrets.token_bytes(KEY_LEN),
            seed_salt=secrets.token_bytes(SALT_LEN),
            seed_key_id=generate_key_id(),
        )
        self.group_manager.set_group_keys(3, keys)

        # Add three members
        self.group_manager.add_device_to_group(3, 300)
        self.group_manager.add_device_to_group(3, 301)
        self.group_manager.add_device_to_group(3, 302)

        recorded_pids = []

        def mock_bootstrap(cfg, pid, int_key, int_salt, int_key_id,
                          seed_key, seed_salt, seed_key_id):
            recorded_pids.append(pid)
            return 0

        def mock_factory_reset(cfg, pid):
            return 0

        cfg = MagicMock()

        with patch("spsec_configurator.core.group_operations.configurator_bootstrap_device", side_effect=mock_bootstrap), \
             patch("spsec_configurator.core.group_operations.configurator_factory_reset", side_effect=mock_factory_reset), \
             patch("spsec_configurator.core.group_operations.verify_group_keys",
                   return_value=(True, [])):
            ret = remove_device_from_group(cfg, self.group_manager, 3, 301, reset_keys=True, rekey_survivors=True)

        self.assertEqual(ret, 0, "remove_device_from_group should return 0")

        # PID 301 should be gone from the group
        group_after = self.group_manager.get_group(3)
        self.assertNotIn(301, group_after.member_pids, "PID 301 should be removed from group")

        # Surviving nodes (300, 302) re-keyed; removed node 301 is not bootstrapped.
        self.assertIn(300, recorded_pids, "Survivor PID 300 should receive new keys")
        self.assertIn(302, recorded_pids, "Survivor PID 302 should receive new keys")


def _sample_keys() -> GroupKeys:
    return GroupKeys(
        integrator_key=secrets.token_bytes(KEY_LEN),
        integrator_salt=secrets.token_bytes(SALT_LEN),
        integrator_key_id=generate_key_id(),
        seed_key=secrets.token_bytes(KEY_LEN),
        seed_salt=secrets.token_bytes(SALT_LEN),
        seed_key_id=generate_key_id(),
    )


class TestGroupLifecycle(unittest.TestCase):
    """TC-CFG-006: create/delete groups with JSON disk persistence."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.config_path = f"{self._dir.name}/groups_config.json"

    def tearDown(self):
        self._dir.cleanup()

    def test_create_get_and_list(self):
        gm = GroupManager(self.config_path)
        group = gm.create_group(1, "DriveGroup", "Emergency stop")
        self.assertEqual(group.group_id, 1)
        self.assertEqual(gm.get_group(1).name, "DriveGroup")
        self.assertEqual(len(gm.list_groups()), 1)

    def test_duplicate_group_id_is_rejected(self):
        gm = GroupManager(self.config_path)
        gm.create_group(1, "First")
        with self.assertRaises(ValueError):
            gm.create_group(1, "Second")

    def test_delete_group(self):
        gm = GroupManager(self.config_path)
        gm.create_group(7, "Doomed")
        self.assertTrue(gm.delete_group(7))
        self.assertIsNone(gm.get_group(7))
        # Deleting a group that isn't there reports failure rather than raising.
        self.assertFalse(gm.delete_group(7))

    def test_groups_persist_across_instances(self):
        """A second GroupManager on the same file must see the same groups."""
        gm = GroupManager(self.config_path)
        gm.create_group(3, "Persisted", "survives a restart")
        gm.add_device_to_group(3, 121)

        reloaded = GroupManager(self.config_path)
        group = reloaded.get_group(3)
        self.assertIsNotNone(group, "group should have been written to disk")
        self.assertEqual(group.name, "Persisted")
        self.assertIn(121, group.member_pids)

    def test_missing_config_file_starts_empty(self):
        gm = GroupManager(f"{self._dir.name}/does_not_exist.json")
        self.assertEqual(gm.list_groups(), [])


class TestGroupMembership(unittest.TestCase):
    """TC-CFG-007: membership add/remove, queries, duplicate rejection."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.gm = GroupManager(f"{self._dir.name}/groups_config.json")
        self.gm.create_group(1, "Group One")

    def tearDown(self):
        self._dir.cleanup()

    def test_add_and_query_membership(self):
        self.assertTrue(self.gm.add_device_to_group(1, 120))
        self.assertTrue(self.gm.is_device_in_group(1, 120))
        self.assertIn(120, self.gm.get_group(1).member_pids)

    def test_device_not_in_group(self):
        self.assertFalse(self.gm.is_device_in_group(1, 199))

    def test_duplicate_member_is_not_added_twice(self):
        self.gm.add_device_to_group(1, 120)
        self.gm.add_device_to_group(1, 120)
        self.assertEqual(self.gm.get_group(1).member_pids.count(120), 1)

    def test_remove_member(self):
        self.gm.add_device_to_group(1, 120)
        self.assertTrue(self.gm.remove_device_from_group(1, 120))
        self.assertFalse(self.gm.is_device_in_group(1, 120))

    def test_add_to_unknown_group_fails(self):
        self.assertFalse(self.gm.add_device_to_group(99, 120))


class TestGroupKeyStorage(unittest.TestCase):
    """TC-CFG-008: set/get group keys and their round-trip through JSON."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.config_path = f"{self._dir.name}/groups_config.json"

    def tearDown(self):
        self._dir.cleanup()

    def test_set_and_get_keys(self):
        gm = GroupManager(self.config_path)
        gm.create_group(1, "Keyed")
        keys = _sample_keys()
        self.assertTrue(gm.set_group_keys(1, keys))

        got = gm.get_group_keys(1)
        self.assertEqual(got.integrator_key, keys.integrator_key)
        self.assertEqual(got.seed_key, keys.seed_key)
        self.assertEqual(got.seed_key_id, keys.seed_key_id)

    def test_keys_survive_serialization(self):
        gm = GroupManager(self.config_path)
        gm.create_group(1, "Keyed")
        keys = _sample_keys()
        gm.set_group_keys(1, keys)

        got = GroupManager(self.config_path).get_group_keys(1)
        self.assertIsNotNone(got, "keys should round-trip through JSON")
        self.assertEqual(got.integrator_key, keys.integrator_key)
        self.assertEqual(got.integrator_salt, keys.integrator_salt)
        self.assertEqual(got.integrator_key_id, keys.integrator_key_id)
        self.assertEqual(got.seed_key, keys.seed_key)
        self.assertEqual(got.seed_salt, keys.seed_salt)
        self.assertEqual(got.seed_key_id, keys.seed_key_id)

    def test_group_without_keys_returns_none(self):
        gm = GroupManager(self.config_path)
        gm.create_group(2, "Unkeyed")
        self.assertIsNone(gm.get_group_keys(2))


if __name__ == "__main__":
    unittest.main()
