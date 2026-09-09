"""§11 D negative/fault-injection tests; needs a live participant, else skipped.
Fault injection wraps `_send_appdata()`, the single outgoing choke point."""

import os
import unittest

_PID = os.environ.get("SPSEC_LIVE_PID")
_IFACE = os.environ.get("SPSEC_LIVE_IFACE", "vcan0")
_KEYS = os.environ.get("SPSEC_LIVE_KEYS")

_SKIP = not (_PID and _KEYS and os.path.isfile(_KEYS))

if not _SKIP:
    from spsec_configurator.core import configurator as cfgmod
    from spsec_configurator.core.configurator import (
        configurator_init,
        configurator_destroy,
        configurator_start_session,
        configurator_read_register,
        configurator_write_register,
        configurator_terminate_session,
    )
    from spsec_configurator.core.spsec_definitions import (
        SPSEC_REG_STATUS,
        SPSEC_REG_PROVISIONING_KEY,
        SPSEC_REG_PROVISIONING_KEY_SALT,
        SPSEC_KEY_SELECTOR_ZERO_KEY,
    )


@unittest.skipIf(_SKIP, "no live participant (set SPSEC_LIVE_PID/_KEYS)")
class LiveNegativeTests(unittest.TestCase):
    def setUp(self):
        self.pid = int(_PID)
        self.cfg = configurator_init(_IFACE, _KEYS)

    def tearDown(self):
        try:
            configurator_terminate_session(self.cfg, self.pid)
        except Exception:
            pass
        configurator_destroy(self.cfg)

    # -- TC-CFG-027: unauthorized register access ---------------------------
    def test_reading_a_write_only_key_register_is_refused(self):
        """20h-2Fh hold key material and must never be readable."""
        self.assertEqual(
            configurator_start_session(
                self.cfg, self.pid, SPSEC_KEY_SELECTOR_ZERO_KEY, 5.0), 0)

        buf = bytearray(32)
        ret = configurator_read_register(
            self.cfg, self.pid, SPSEC_REG_PROVISIONING_KEY, buf, 32)

        self.assertNotEqual(ret, 0, "reading the Provisioning Key must fail")
        self.assertEqual(bytes(buf), bytes(32), "no key bytes may be returned")

    def test_reading_a_key_salt_is_refused(self):
        """30h-3Fh: SPsec302 §2.3.2 gives salts the same access as their key."""
        self.assertEqual(
            configurator_start_session(
                self.cfg, self.pid, SPSEC_KEY_SELECTOR_ZERO_KEY, 5.0), 0)

        buf = bytearray(8)
        ret = configurator_read_register(
            self.cfg, self.pid, SPSEC_REG_PROVISIONING_KEY_SALT, buf, 8)

        self.assertNotEqual(ret, 0, "reading a pre-shared salt must fail")
        self.assertEqual(bytes(buf), bytes(8))

    # -- TC-CFG-025: corrupted authentication tag ---------------------------
    def test_corrupted_auth_tag_is_rejected(self):
        """Flip one bit in every outgoing frame's last byte (the tag)."""
        original = cfgmod._send_appdata

        def corrupting_send(cfg, ad):
            if ad.data is not None and len(ad.data) > 0:
                data = bytearray(ad.data)
                data[-1] ^= 0x01
                ad.data = bytes(data)
            return original(cfg, ad)

        cfgmod._send_appdata = corrupting_send
        try:
            ret = configurator_start_session(
                self.cfg, self.pid, SPSEC_KEY_SELECTOR_ZERO_KEY, 5.0)
        finally:
            cfgmod._send_appdata = original

        self.assertNotEqual(
            ret, 0, "a handshake with corrupted tags must not succeed")

    # -- TC-CFG-026: replayed session counter --------------------------------
    def test_replayed_session_counter_is_rejected(self):
        """Reusing an already-consumed counter must not be accepted -
        rewinding it mimics a recorded-and-resent frame without needing raw CAN capture."""
        ret = configurator_start_session(
            self.cfg, self.pid, SPSEC_KEY_SELECTOR_ZERO_KEY, 5.0)
        self.assertEqual(ret, 0, "precondition: session must open")

        cnt_at_session_start = self.cfg.session_cnt

        buf = bytearray(1)
        self.assertEqual(
            configurator_read_register(self.cfg, self.pid, SPSEC_REG_STATUS, buf, 1),
            0, "precondition: a normal read must succeed")

        # Replay: wind the counter back over the reads just consumed.
        self.cfg.session_cnt = cnt_at_session_start

        replay = configurator_read_register(
            self.cfg, self.pid, SPSEC_REG_STATUS, buf, 1)
        self.assertNotEqual(
            replay, 0,
            "a request replaying a consumed session counter must be rejected")

    # -- TC-CFG-028: dropped response / timeout ------------------------------
    def test_dropped_frames_time_out_cleanly(self):
        """Swallow every outgoing frame: the client must time out, not hang."""
        original = cfgmod._send_appdata
        cfgmod._send_appdata = lambda cfg, ad: 0  # pretend it went out
        try:
            ret = configurator_start_session(
                self.cfg, self.pid, SPSEC_KEY_SELECTOR_ZERO_KEY, 2.0)
        finally:
            cfgmod._send_appdata = original

        self.assertLess(ret, 0, "a session with no reachable peer must fail")

    def test_session_survives_after_a_failed_attempt(self):
        """A failed handshake must not poison the next one."""
        original = cfgmod._send_appdata
        cfgmod._send_appdata = lambda cfg, ad: 0
        try:
            configurator_start_session(
                self.cfg, self.pid, SPSEC_KEY_SELECTOR_ZERO_KEY, 2.0)
        finally:
            cfgmod._send_appdata = original

        fresh = configurator_init(_IFACE, _KEYS)
        try:
            self.assertEqual(
                configurator_start_session(
                    fresh, self.pid, SPSEC_KEY_SELECTOR_ZERO_KEY, 5.0), 0,
                "participant should still accept a well-formed session")
            buf = bytearray(1)
            self.assertEqual(
                configurator_read_register(
                    fresh, self.pid, SPSEC_REG_STATUS, buf, 1), 0)
        finally:
            try:
                configurator_terminate_session(fresh, self.pid)
            except Exception:
                pass
            configurator_destroy(fresh)


if __name__ == "__main__":
    unittest.main()
