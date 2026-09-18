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

"""CONFIGURATOR_REQUIREMENTS.md §14.1: code update transport (90h-92h).
Pins the 90h bit layout (SPsec302 §2.3.7.1) and upload guards (empty/oversize/no-capability).
"""

import unittest
from unittest.mock import patch

from spsec_configurator.core.code_update import (
    MAX_IMAGE_BYTES,
    CodeUpdateCapabilities,
    SPSEC_REG_CODE_UPDATE_CAPABILITIES,
    SPSEC_REG_CODE_UPDATE_FILE,
    SPSEC_REG_PUBLIC_AUTH_KEY,
    upload_code_update_file,
)


class TestCapabilityDecoding(unittest.TestCase):
    """SPsec302 §2.3.7.1 bit layout."""

    def test_capable_bit(self):
        caps = CodeUpdateCapabilities.from_bytes((0x00000001).to_bytes(4, "little"))
        self.assertTrue(caps.update_capable)
        self.assertEqual(caps.manufacturer, 0)

    def test_not_capable(self):
        caps = CodeUpdateCapabilities.from_bytes((0x00000000).to_bytes(4, "little"))
        self.assertFalse(caps.update_capable)

    def test_manufacturer_bits_are_the_top_byte(self):
        caps = CodeUpdateCapabilities.from_bytes((0xA5000001).to_bytes(4, "little"))
        self.assertTrue(caps.update_capable)
        self.assertEqual(caps.manufacturer, 0xA5)

    def test_reserved_bits_do_not_set_capability(self):
        """Only bit 0 means 'capable' - reserved bits 1-23 must not."""
        caps = CodeUpdateCapabilities.from_bytes((0x00FFFFFE).to_bytes(4, "little"))
        self.assertFalse(caps.update_capable)

    def test_raw_is_little_endian(self):
        caps = CodeUpdateCapabilities.from_bytes(bytes([0x01, 0x00, 0x00, 0xA5]))
        self.assertEqual(caps.raw, 0xA5000001)


class TestUploadGuards(unittest.TestCase):
    def test_empty_image_is_refused(self):
        self.assertNotEqual(upload_code_update_file(None, 120, b""), 0)

    def test_oversize_image_is_refused(self):
        big = b"\x00" * (MAX_IMAGE_BYTES + 1)
        self.assertNotEqual(upload_code_update_file(None, 120, big), 0)

    def test_refuses_when_device_reports_no_capability(self):
        def fake_read(cfg, pid, reg, buf, length):
            if reg == SPSEC_REG_CODE_UPDATE_CAPABILITIES:
                buf[:4] = (0x00000000).to_bytes(4, "little")  # bit 0 clear
                return 0
            return -1

        with patch("spsec_configurator.core.code_update.configurator_read_register",
                   side_effect=fake_read), \
             patch("spsec_configurator.core.code_update.configurator_write_register") as w:
            ret = upload_code_update_file(None, 120, b"firmware")

        self.assertNotEqual(ret, 0)
        w.assert_not_called()

    def test_uploads_to_92h_when_capable(self):
        def fake_read(cfg, pid, reg, buf, length):
            if reg == SPSEC_REG_CODE_UPDATE_CAPABILITIES:
                buf[:4] = (0x00000001).to_bytes(4, "little")
                return 0
            if reg == SPSEC_REG_PUBLIC_AUTH_KEY:
                buf[:len(buf)] = bytes(len(buf))
                return 0
            return -1

        image = b"firmware image bytes"
        with patch("spsec_configurator.core.code_update.configurator_read_register",
                   side_effect=fake_read), \
             patch("spsec_configurator.core.code_update.configurator_write_register",
                   return_value=0) as w:
            ret = upload_code_update_file(None, 120, image)

        self.assertEqual(ret, 0)
        w.assert_called_once()
        args = w.call_args[0]
        self.assertEqual(args[2], SPSEC_REG_CODE_UPDATE_FILE)
        self.assertEqual(args[3], image)

    def test_chunk_size_aligned_with_participant_parser(self):
        """MAX_SEG_DATA must be 32, not 48 - the WRSEG parser picks 32 either way,
        so 48 would silently drop 16 bytes/segment and corrupt 92h uploads."""
        from spsec_configurator.core.configurator import MAX_SEG_DATA

        self.assertEqual(MAX_SEG_DATA, 32)


    def test_write_failure_is_propagated(self):
        def fake_read(cfg, pid, reg, buf, length):
            if reg == SPSEC_REG_CODE_UPDATE_CAPABILITIES:
                buf[:4] = (0x00000001).to_bytes(4, "little")
                return 0
            buf[:len(buf)] = bytes(len(buf))
            return 0

        with patch("spsec_configurator.core.code_update.configurator_read_register",
                   side_effect=fake_read), \
             patch("spsec_configurator.core.code_update.configurator_write_register",
                   return_value=-7):
            self.assertEqual(upload_code_update_file(None, 120, b"img"), -7)

    def test_capability_check_can_be_skipped(self):
        """check_capability=False goes straight to the write."""
        with patch("spsec_configurator.core.code_update.configurator_read_register") as r, \
             patch("spsec_configurator.core.code_update.configurator_write_register",
                   return_value=0) as w:
            ret = upload_code_update_file(None, 120, b"img", check_capability=False)

        self.assertEqual(ret, 0)
        r.assert_not_called()
        w.assert_called_once()


if __name__ == "__main__":
    unittest.main()
