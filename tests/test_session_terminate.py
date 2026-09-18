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

"""TC-CFG-016: session terminate counter accounting.
Regression test for an off-by-one (compared against session_cnt+1) that made every terminate fail and skipped auth-tag verification.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from spsec_configurator.core import configurator as C
from spsec_configurator.core.keys import SPsecSalt
from spsec_configurator.core.messages import (
    SPsecSessionTerminateMessage,
    authtagparticipantdata_new,
)
from spsec_configurator.core.spsec_definitions import (
    AUTH_TAG_SIZE,
    KEY_LEN,
    SALT_LEN,
    SPSEC_MSGTYPE_SERVER_TERMINATE,
)

GOOD_TAG = bytes(range(AUTH_TAG_SIZE))


def _cfg(session_cnt: int) -> SimpleNamespace:
    """Minimal stand-in carrying only what terminate touches."""
    auth = authtagparticipantdata_new()
    auth.spsec_salt = SPsecSalt(salt=bytearray(SALT_LEN))
    return SimpleNamespace(
        session_cnt=session_cnt,
        session_key=bytearray(KEY_LEN),
        session_auth_tag_data=auth,
        algorithm=0,
        in_session=True,
    )


def _response(cnt: int, tag: bytes = GOOD_TAG) -> SimpleNamespace:
    msg = SPsecSessionTerminateMessage(pid=120, cnt=cnt)
    msg.address = 0
    msg.auth_tag = bytearray(tag)
    return SimpleNamespace(
        msg_type=SPSEC_MSGTYPE_SERVER_TERMINATE, msg_content=msg
    )


class TestTerminateCounter(unittest.TestCase):
    """The request consumes one counter, the response the next one."""

    def _run(self, response_cnt: int) -> int:
        cfg = _cfg(100)
        # Request takes 101, so the response must carry 102.
        with patch.object(C, "_send_appdata", return_value=0), \
             patch.object(C, "compute_tag_only", return_value=GOOD_TAG), \
             patch.object(C, "configurator_receive",
                          return_value=_response(response_cnt)):
            return C.configurator_terminate_session(cfg, 120)

    def test_matching_counter_succeeds(self):
        self.assertEqual(self._run(102), 0)

    def test_off_by_one_counter_is_rejected(self):
        """103 is what the old buggy code demanded - it must now fail."""
        self.assertEqual(self._run(103), -8)

    def test_stale_counter_is_rejected(self):
        self.assertEqual(self._run(101), -8)

    def test_counter_is_compared_by_lsb_only(self):
        """Only the low byte is on the wire, so 102 + 256 still matches."""
        self.assertEqual(self._run(102 + 256), 0)

    def test_bad_auth_tag_is_rejected(self):
        """Reachable only once the counter check passes - it used to be dead."""
        cfg = _cfg(100)
        with patch.object(C, "_send_appdata", return_value=0), \
             patch.object(C, "compute_tag_only", return_value=GOOD_TAG), \
             patch.object(C, "configurator_receive",
                          return_value=_response(102, b"\xFF" * AUTH_TAG_SIZE)):
            self.assertEqual(C.configurator_terminate_session(cfg, 120), -3)

    def test_no_response_times_out(self):
        cfg = _cfg(100)
        with patch.object(C, "_send_appdata", return_value=0), \
             patch.object(C, "compute_tag_only", return_value=GOOD_TAG), \
             patch.object(C, "configurator_receive", return_value=None):
            self.assertEqual(C.configurator_terminate_session(cfg, 120), -6)

    def test_session_is_cleared_on_success(self):
        cfg = _cfg(100)
        with patch.object(C, "_send_appdata", return_value=0), \
             patch.object(C, "compute_tag_only", return_value=GOOD_TAG), \
             patch.object(C, "configurator_receive",
                          return_value=_response(102)):
            C.configurator_terminate_session(cfg, 120)
        self.assertFalse(cfg.in_session)
        self.assertEqual(cfg.session_cnt, 0)


if __name__ == "__main__":
    unittest.main()
