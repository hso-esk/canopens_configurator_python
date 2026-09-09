# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Unit tests for device_discovery module."""

import unittest
from unittest.mock import MagicMock, patch

from spsec_configurator.core.device_discovery import (
    DiscoveredDevice,
    device_is_unprovisioned,
    discover_device,
    scan_network,
    discover_and_register,
)
from spsec_configurator.core.group_manager import GroupManager
from spsec_configurator.core.spsec_definitions import (
    SPSEC_REG_STATUS,
    SPSEC_REG_LAST_SECURITY_EVENT,
    SPSEC_REG_CORE_VERSION_INFO,
    SPSEC_REG_MAPPING_VERSION_INFO,
    SPSEC_REG_DEVICE_IDENTIFICATION,
    SPSEC_REG_MCU_SERIAL_NUMBER,
    SPSEC_REG_PROVISIONING_KEY_ID,
    SPSEC_REG_INTEGRATOR_KEY_ID,
    SPSEC_REG_SEED_KEY_ID,
)


class TestDeviceIsUnprovisioned(unittest.TestCase):
    """Test device_is_unprovisioned helper function."""

    def test_none_device_returns_false(self):
        self.assertFalse(device_is_unprovisioned(None))

    def test_none_key_id_is_unprovisioned(self):
        dev = DiscoveredDevice(participant_id=120, provisioning_key_id=None)
        self.assertTrue(device_is_unprovisioned(dev))

    def test_zero_key_id_is_unprovisioned(self):
        dev = DiscoveredDevice(participant_id=120, provisioning_key_id=0x00000000)
        self.assertTrue(device_is_unprovisioned(dev))

    def test_all_ones_key_id_is_unprovisioned(self):
        dev = DiscoveredDevice(participant_id=120, provisioning_key_id=0xFFFFFFFF)
        self.assertTrue(device_is_unprovisioned(dev))

    def test_valid_key_id_is_provisioned(self):
        dev = DiscoveredDevice(participant_id=120, provisioning_key_id=0x12345678)
        self.assertFalse(device_is_unprovisioned(dev))


class TestDiscoverDevice(unittest.TestCase):
    """Test discover_device with mocked configurator calls."""

    def test_unreachable_device_returns_none(self):
        cfg = MagicMock()
        with patch("spsec_configurator.core.device_discovery.configurator_start_session", return_value=-6):
            res = discover_device(cfg, 120, timeout_seconds=0.5)
            self.assertIsNone(res)

    def test_reachable_device_queries_all_registers(self):
        cfg = MagicMock()

        def mock_read(c, pid, reg, buf, length):
            if reg == SPSEC_REG_STATUS:
                buf[0] = 0x04
            elif reg == SPSEC_REG_LAST_SECURITY_EVENT:
                buf[:2] = (0x1234).to_bytes(2, "little")
            elif reg == SPSEC_REG_CORE_VERSION_INFO:
                b = b"0.34\x00"
                buf[:len(b)] = b
            elif reg == SPSEC_REG_MAPPING_VERSION_INFO:
                b = b"302-1.40\x00"
                buf[:len(b)] = b
            elif reg == SPSEC_REG_DEVICE_IDENTIFICATION:
                b = b"TestDev/1\x00"
                buf[:len(b)] = b
            elif reg == SPSEC_REG_MCU_SERIAL_NUMBER:
                buf[:16] = bytes([0xAA] * 16)
            elif reg == SPSEC_REG_PROVISIONING_KEY_ID:
                buf[:4] = (0x11111111).to_bytes(4, "little")
            elif reg == SPSEC_REG_INTEGRATOR_KEY_ID:
                buf[:4] = (0x22222222).to_bytes(4, "little")
            elif reg == SPSEC_REG_SEED_KEY_ID:
                buf[:4] = (0x33333333).to_bytes(4, "little")
            return 0

        with patch("spsec_configurator.core.device_discovery.configurator_start_session", return_value=0), \
             patch("spsec_configurator.core.device_discovery.configurator_read_register", side_effect=mock_read), \
             patch("spsec_configurator.core.device_discovery.configurator_terminate_session", return_value=0):
            dev = discover_device(cfg, 120, timeout_seconds=1.0)

            self.assertIsNotNone(dev)
            self.assertTrue(dev.reachable)
            self.assertEqual(dev.participant_id, 120)
            self.assertEqual(dev.status, 0x04)
            self.assertEqual(dev.last_security_event, 0x1234)
            self.assertEqual(dev.core_version, "0.34")
            self.assertEqual(dev.mapping_version, "302-1.40")
            self.assertEqual(dev.device_identification, "TestDev/1")
            self.assertEqual(dev.mcu_serial_number, "aa" * 16)
            self.assertEqual(dev.provisioning_key_id, 0x11111111)
            self.assertEqual(dev.integrator_key_id, 0x22222222)
            self.assertEqual(dev.seed_key_id, 0x33333333)

    def test_scan_network(self):
        cfg = MagicMock()
        dev1 = DiscoveredDevice(participant_id=120, reachable=True)

        with patch("spsec_configurator.core.device_discovery.discover_device", side_effect=[dev1, None]):
            found = scan_network(cfg, pid_range=range(120, 122), timeout_per_device=0.1)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].participant_id, 120)


if __name__ == "__main__":
    unittest.main()
