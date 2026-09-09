"""TC-CFG-010: CAN FD frame parsing. Short frames must return None, not raise
or silently build a message from truncated bytes - first parser attacker input hits.
"""

import unittest

from spsec_configurator.core.protocol_can import parse_received
from spsec_configurator.core.spsec_definitions import (
    AUTH_TAG_SIZE,
    RANDOM_SIZE,
    SPSEC_ADDRESS_SESSION_BASE,
    SPSEC_CPMT_SESS_HELLO,
    SPSEC_CPMT_SESS_FINISH,
    SPSEC_MSGTYPE_SERVER_HELLO,
    SPSEC_MSGTYPE_SERVER_FINISHED,
)


def _session_arb(pid: int, sub_type: int, byte2: int = 0xFF) -> int:
    """Build a session arbitration ID: [pid, cpmt_type, counter/0xFF, base_hi], little-endian."""
    return int.from_bytes(
        bytes([pid & 0x7F, sub_type, byte2, SPSEC_ADDRESS_SESSION_BASE >> 24]),
        "little",
    )


class TestServerHelloFraming(unittest.TestCase):
    def test_parses_valid_server_hello(self):
        arb = _session_arb(121, SPSEC_CPMT_SESS_HELLO)
        payload = bytes(range(RANDOM_SIZE))

        msg = parse_received(arb, payload)

        self.assertIsNotNone(msg)
        self.assertEqual(msg.msg_type, SPSEC_MSGTYPE_SERVER_HELLO)
        self.assertEqual(msg.msg_content.participant_id, 121)
        self.assertEqual(bytes(msg.msg_content.random), payload)

    def test_short_server_hello_is_rejected(self):
        """A Hello carrying fewer than RANDOM_SIZE bytes must not parse."""
        arb = _session_arb(121, SPSEC_CPMT_SESS_HELLO)
        for length in (0, 1, RANDOM_SIZE - 1):
            with self.subTest(length=length):
                self.assertIsNone(parse_received(arb, bytes(length)))

    def test_client_direction_bit_is_not_parsed_as_server_hello(self):
        """Bit 7 set marks a client->server frame; self-originated frames must be ignored."""
        arb = int.from_bytes(
            bytes([121 | 0x80, SPSEC_CPMT_SESS_HELLO, 0xFF,
                   SPSEC_ADDRESS_SESSION_BASE >> 24]),
            "little",
        )
        self.assertIsNone(parse_received(arb, bytes(RANDOM_SIZE)))


class TestServerFinishedFraming(unittest.TestCase):
    def test_parses_valid_server_finished(self):
        arb = _session_arb(120, SPSEC_CPMT_SESS_FINISH, byte2=0x2A)
        payload = bytes(range(AUTH_TAG_SIZE))

        msg = parse_received(arb, payload)

        self.assertIsNotNone(msg)
        self.assertEqual(msg.msg_type, SPSEC_MSGTYPE_SERVER_FINISHED)
        self.assertEqual(msg.msg_content.participant_id, 120)
        self.assertEqual(msg.msg_content.cnt, 0x2A)
        self.assertEqual(bytes(msg.msg_content.auth_tag), payload)

    def test_short_server_finished_is_rejected(self):
        arb = _session_arb(120, SPSEC_CPMT_SESS_FINISH, byte2=0x2A)
        for length in (0, AUTH_TAG_SIZE - 1):
            with self.subTest(length=length):
                self.assertIsNone(parse_received(arb, bytes(length)))


class TestUnknownFrames(unittest.TestCase):
    def test_foreign_address_range_is_ignored(self):
        """A frame outside the SPsec session range is ignored."""
        arb = int.from_bytes(bytes([120, 0, 0xFF, 0x00]), "little")
        self.assertIsNone(parse_received(arb, bytes(RANDOM_SIZE)))

    def test_unknown_sub_type_is_ignored(self):
        arb = _session_arb(120, 0x7E)
        self.assertIsNone(parse_received(arb, bytes(RANDOM_SIZE)))

    def test_empty_payload_never_raises(self):
        """Whatever arrives, the parser must not explode."""
        for sub_type in range(0, 16):
            with self.subTest(sub_type=sub_type):
                parse_received(_session_arb(120, sub_type), b"")


if __name__ == "__main__":
    unittest.main()
