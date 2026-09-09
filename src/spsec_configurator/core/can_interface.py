# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

from __future__ import annotations

import can
from dataclasses import dataclass
from typing import Optional

from .logging_util import log_info, log_error, log_debug
from .messages import AppData, SPsecMessage
from .spsec_definitions import SPSEC_CAN_EFF_FLAG, SPSEC_CAN_ID_MASK, SPSEC_MSGTYPE_APP_DATA
from .protocol_can import parse_received


@dataclass
class CommChannel:
    bus: can.Bus
    interface_name: str


def can_channel_init(interface_name: str) -> CommChannel:
    # Use SocketCAN; bitrate handled by system. FD frames enabled.
    bus = can.Bus(channel=interface_name, interface="socketcan", fd=True)
    log_info("can", "Opened SocketCAN interface %s", interface_name)
    return CommChannel(bus=bus, interface_name=interface_name)


def can_channel_destroy(channel: CommChannel) -> None:
    try:
        channel.bus.shutdown()
    except Exception:
        pass


def can_channel_receive(channel: CommChannel, timeout_ms: int) -> Optional[SPsecMessage]:
    timeout_s = None if timeout_ms <= 0 else timeout_ms / 1000.0
    msg = channel.bus.recv(timeout=timeout_s)
    if msg is None:
        return None
    base_id = msg.arbitration_id & SPSEC_CAN_ID_MASK
    data = bytes(msg.data)
    arb_bytes = base_id.to_bytes(4, "little")
    log_info("can", "Received arb_id: %08x (base: %08x), len: %d", msg.arbitration_id, base_id, len(data))
    log_debug("can", "arb_id_bytes: %02x %02x %02x %02x", arb_bytes[0], arb_bytes[1], arb_bytes[2], arb_bytes[3])
    parsed = parse_received(base_id, data)
    if parsed is not None:
        return parsed
    ad = AppData(base_id, data)
    return SPsecMessage(SPSEC_MSGTYPE_APP_DATA, ad)


def channel_send_appdata(channel: CommChannel, message: AppData) -> int:
    frame = can.Message(
        arbitration_id=message.address | SPSEC_CAN_EFF_FLAG,
        data=bytes(message.data),
        is_extended_id=True,
        is_fd=True,
        bitrate_switch=True,
    )
    try:
        channel.bus.send(frame)
    except can.CanError as e:
        log_error("can", "Failed to send CAN message: %s", e)
        return -1
    data = bytes(frame.data)
    preview_len = 8 if len(data) > 8 else len(data)
    hex_preview = data[:preview_len].hex()
    suffix = "..." if len(data) > preview_len else ""
    log_info("can", "Sending frame: ID=%08x, Len=%d, Data=%s%s", frame.arbitration_id, len(data), hex_preview, suffix)
    return 0


