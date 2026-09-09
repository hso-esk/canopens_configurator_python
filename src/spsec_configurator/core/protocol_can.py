# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

from __future__ import annotations

from .logging_util import log_info, log_debug, log_error
from .spsec_definitions import (
    AUTH_TAG_SIZE,
    SPSEC_CPMT_SESS_HELLO,
    SPSEC_CPMT_SESS_FINISH,
    SPSEC_CPMT_SESS_RDINIT,
    SPSEC_CPMT_SESS_RDSEG,
    SPSEC_CPMT_SESS_WRINIT,
    SPSEC_CPMT_SESS_WRSEG,
    SPSEC_CPMT_SESS_TERMINATE,
    SPSEC_CPMT_HB,
    SPSEC_MSGTYPE_SERVER_HELLO,
    SPSEC_MSGTYPE_SERVER_FINISHED,
    SPSEC_MSGTYPE_SERVER_READ_INITIATE,
    SPSEC_MSGTYPE_SERVER_READ_SEGMENT,
    SPSEC_MSGTYPE_SERVER_WRITE_INITIATE,
    SPSEC_MSGTYPE_SERVER_WRITE_SEGMENT,
    SPSEC_MSGTYPE_SERVER_TERMINATE,
    SPSEC_MSGTYPE_HEARTBEAT,
    SPSEC_ADDRESS_SESSION_BASE,
    SPSEC_ADDRESS_HEARTBEAT_BASE,
)
from .messages import (
    SPsecMessage,
    SPsecServerHelloMessage,
    SPsecClientFinishedMessage,
    SPsecServerFinishedMessage,
    SPsecReadInitiateMessage,
    SPsecClientReadSegmentRequest,
    SPsecServerReadSegmentResponse,
    SPsecWriteInitiateMessage,
    SPsecClientWriteSegmentResponse,
    SPsecSessionTerminateMessage,
    SPsecHeartbeatMessage,
)


def _is_first_bit_set(byte: int) -> bool:
    return (byte & 0x80) != 0


def parse_received(base_id: int, data: bytes) -> SPsecMessage | None:
    arb = base_id.to_bytes(4, "little")
    # arb[3] holds the high byte of the address
    if arb[3] == (SPSEC_ADDRESS_SESSION_BASE >> 24):
        # Session messages
        if arb[1] == SPSEC_CPMT_SESS_HELLO and arb[2] == 0xFF and not _is_first_bit_set(arb[0]):
            pid = arb[0] & 0x7F
            log_info("proto", "Received ServerHello from PID %u", pid)
            if len(data) < 16:
                return None
            msg = SPsecServerHelloMessage(pid, data[:16])
            return SPsecMessage(SPSEC_MSGTYPE_SERVER_HELLO, msg)
        elif arb[1] == SPSEC_CPMT_SESS_FINISH and not _is_first_bit_set(arb[0]):
            pid = arb[0] & 0x7F
            log_info("proto", "Received ServerFinished from PID %u", pid)
            cnt_lsb = arb[2]
            if len(data) < AUTH_TAG_SIZE:
                return None
            msg = SPsecServerFinishedMessage(pid, cnt_lsb, data[:AUTH_TAG_SIZE], base_id)
            return SPsecMessage(SPSEC_MSGTYPE_SERVER_FINISHED, msg)
        elif arb[1] == SPSEC_CPMT_SESS_RDINIT and not _is_first_bit_set(arb[0]):
            if len(data) < 8 + AUTH_TAG_SIZE:
                return None
            pid = arb[0] & 0x7F
            cnt_lsb = arb[2]
            msg = SPsecReadInitiateMessage(pid, cnt_lsb, 0, 0)
            msg.ciphertext[:] = data[:8]
            msg.auth_tag[:] = data[8:8 + AUTH_TAG_SIZE]
            msg.address = base_id
            log_info("proto", "Received ServerReadInitiateResponse with PID %u", pid)
            return SPsecMessage(SPSEC_MSGTYPE_SERVER_READ_INITIATE, msg)
        elif arb[1] == SPSEC_CPMT_SESS_RDSEG and not _is_first_bit_set(arb[0]):
            if len(data) < AUTH_TAG_SIZE:
                return None
            pid = arb[0] & 0x7F
            cnt_lsb = arb[2]
            seg_len = len(data) - AUTH_TAG_SIZE
            resp = SPsecServerReadSegmentResponse(pid, cnt_lsb, bytearray(seg_len), seg_len)
            resp.ciphertext_ptr = bytearray(seg_len)
            resp.ciphertext_ptr[:] = data[:seg_len]
            resp.auth_tag[:] = data[seg_len:seg_len + AUTH_TAG_SIZE]
            resp.address = base_id
            log_info("proto", "Received ServerReadSegmentResponse with PID %u", pid)
            return SPsecMessage(SPSEC_MSGTYPE_SERVER_READ_SEGMENT, resp)
        elif arb[1] == SPSEC_CPMT_SESS_WRINIT and not _is_first_bit_set(arb[0]):
            if len(data) < 8 + AUTH_TAG_SIZE:
                return None
            pid = arb[0] & 0x7F
            cnt_lsb = arb[2]
            msg = SPsecWriteInitiateMessage(pid, cnt_lsb, 0, 0)
            msg.ciphertext[:] = data[:8]
            msg.auth_tag[:] = data[8:8 + AUTH_TAG_SIZE]
            msg.address = base_id
            log_info("proto", "Received ServerWriteInitiateResponse with PID %u", pid)
            return SPsecMessage(SPSEC_MSGTYPE_SERVER_WRITE_INITIATE, msg)
        elif arb[1] == SPSEC_CPMT_SESS_WRSEG and not _is_first_bit_set(arb[0]):
            if len(data) < 4 + AUTH_TAG_SIZE:
                return None
            pid = arb[0] & 0x7F
            cnt_lsb = arb[2]
            msg = SPsecClientWriteSegmentResponse(pid, cnt_lsb, 0)
            msg.ciphertext[:] = data[:4]
            msg.auth_tag[:] = data[4:4 + AUTH_TAG_SIZE]
            msg.address = base_id
            log_info("proto", "Received ServerWriteSegmentResponse with PID %u", pid)
            return SPsecMessage(SPSEC_MSGTYPE_SERVER_WRITE_SEGMENT, msg)
        elif arb[1] == SPSEC_CPMT_SESS_TERMINATE and not _is_first_bit_set(arb[0]):
            if len(data) < AUTH_TAG_SIZE:
                return None
            pid = arb[0] & 0x7F
            msg = SPsecSessionTerminateMessage(pid, arb[2])
            msg.address = base_id
            msg.auth_tag[:] = data[:AUTH_TAG_SIZE]
            log_info("proto", "Received ServerSessionTerminateResponse with PID %u", pid)
            return SPsecMessage(SPSEC_MSGTYPE_SERVER_TERMINATE, msg)
    elif arb[3] == (SPSEC_ADDRESS_HEARTBEAT_BASE >> 24) and arb[1] == SPSEC_CPMT_HB and not _is_first_bit_set(arb[0]):
        # Heartbeat broadcast (SPSEC_CPMT_HB = 10, status in arb[2])
        pid = arb[0] & 0x7F
        status = arb[2]
        
        # Extract tag if available (usually in the last 8 bytes of data)
        tag = b""
        if len(data) >= 8:
            tag = data[-8:]
            
        msg = SPsecHeartbeatMessage(pid, status, tag)
        return SPsecMessage(SPSEC_MSGTYPE_HEARTBEAT, msg)
    # Unrecognized
    log_debug("proto", "Unrecognized frame: base=%08x len=%d", base_id, len(data))
    return None


