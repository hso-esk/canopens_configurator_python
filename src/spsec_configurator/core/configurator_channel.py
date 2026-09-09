# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .logging_util import log_info
from .messages import (
    AppData,
    SPsecMessage,
    SPsecClientHelloMessage,
    SPsecClientFinishedMessage,
    SPsecReadInitiateMessage,
    SPsecClientReadSegmentRequest,
    SPsecWriteInitiateMessage,
    SPsecClientWriteSegmentRequest,
    SPsecSessionTerminateMessage,
)
from .can_interface import CommChannel, channel_send_appdata
from .spsec_definitions import (
    AUTH_TAG_SIZE,
    SPSEC_CPMT_SESS_HELLO,
    SPSEC_CPMT_SESS_FINISH,
    SPSEC_CPMT_SESS_RDINIT,
    SPSEC_CPMT_SESS_RDSEG,
    SPSEC_CPMT_SESS_WRINIT,
    SPSEC_CPMT_SESS_WRSEG,
    SPSEC_CPMT_SESS_TERMINATE,
    SPSEC_ADDRESS_SESSION_BASE,
    SPSEC_ADDRESS_DISCOVERY_BASE,
    SPSEC_ADDRESS_DESTINATION_BIT,
)


@dataclass
class SPsecCommChannel:
    channel: CommChannel
    participant_id: int = 0


def set_client_finished_address(msg: SPsecClientFinishedMessage) -> int:
    cnt_low = msg.cnt & 0xFF
    base_id = SPSEC_ADDRESS_SESSION_BASE | (cnt_low << 16) | (SPSEC_CPMT_SESS_FINISH << 8) | (msg.participant_id | SPSEC_ADDRESS_DESTINATION_BIT)
    msg.address = base_id
    return 0


def set_read_initiate_request_address(msg: SPsecReadInitiateMessage) -> None:
    cnt_low = msg.cnt & 0xFF
    msg.address = SPSEC_ADDRESS_SESSION_BASE | (cnt_low << 16) | (SPSEC_CPMT_SESS_RDINIT << 8) | (msg.pid | SPSEC_ADDRESS_DESTINATION_BIT)


def set_read_segment_request_address(msg: SPsecClientReadSegmentRequest) -> None:
    cnt_low = msg.cnt & 0xFF
    msg.address = SPSEC_ADDRESS_SESSION_BASE | (cnt_low << 16) | (SPSEC_CPMT_SESS_RDSEG << 8) | (msg.pid | SPSEC_ADDRESS_DESTINATION_BIT)


def set_write_initiate_request_address(msg: SPsecWriteInitiateMessage) -> None:
    cnt_low = msg.cnt & 0xFF
    msg.address = SPSEC_ADDRESS_SESSION_BASE | (cnt_low << 16) | (SPSEC_CPMT_SESS_WRINIT << 8) | (msg.pid | SPSEC_ADDRESS_DESTINATION_BIT)


def set_segment_write_request_address(msg: SPsecClientWriteSegmentRequest) -> None:
    cnt_low = msg.cnt & 0xFF
    msg.address = SPSEC_ADDRESS_SESSION_BASE | (cnt_low << 16) | (SPSEC_CPMT_SESS_WRSEG << 8) | (msg.pid | SPSEC_ADDRESS_DESTINATION_BIT)


def set_session_terminate_request_address(msg: SPsecSessionTerminateMessage) -> None:
    cnt_low = msg.cnt & 0xFF
    msg.address = SPSEC_ADDRESS_SESSION_BASE | (cnt_low << 16) | (SPSEC_CPMT_SESS_TERMINATE << 8) | (msg.pid | SPSEC_ADDRESS_DESTINATION_BIT)


def configurator_channel_send_client_hello(channel: SPsecCommChannel, msg: SPsecClientHelloMessage) -> int:
    base_id = SPSEC_ADDRESS_DISCOVERY_BASE | (SPSEC_CPMT_SESS_HELLO << 8) | (msg.participant_id | SPSEC_ADDRESS_DESTINATION_BIT)
    payload = bytes(msg.key_selector) + bytes(msg.random)
    ad = AppData(base_id, payload)
    return channel_send_appdata(channel.channel, ad)


def configurator_channel_send_client_finished(channel: SPsecCommChannel, msg: SPsecClientFinishedMessage) -> int:
    payload = bytes(msg.auth_tag)
    ad = AppData(msg.address, payload)
    return channel_send_appdata(channel.channel, ad)


def configurator_channel_send_read_initiate_request(channel: SPsecCommChannel, msg: SPsecReadInitiateMessage) -> int:
    payload = bytes(msg.ciphertext) + bytes(msg.auth_tag)
    ad = AppData(msg.address, payload)
    return channel_send_appdata(channel.channel, ad)


def configurator_channel_send_read_segment_request(channel: SPsecCommChannel, msg: SPsecClientReadSegmentRequest) -> int:
    payload = bytes(msg.auth_tag)
    ad = AppData(msg.address, payload)
    return channel_send_appdata(channel.channel, ad)


def configurator_channel_send_write_initiate_request(channel: SPsecCommChannel, msg: SPsecWriteInitiateMessage) -> int:
    payload = bytes(msg.ciphertext) + bytes(msg.auth_tag)
    ad = AppData(msg.address, payload)
    return channel_send_appdata(channel.channel, ad)


def configurator_channel_send_write_segment_request(channel: SPsecCommChannel, msg: SPsecClientWriteSegmentRequest) -> int:
    payload = bytes(msg.ciphertext_ptr or b"") + bytes(msg.auth_tag)
    ad = AppData(msg.address, payload)
    return channel_send_appdata(channel.channel, ad)


def configurator_channel_send_session_terminate_request(channel: SPsecCommChannel, msg: SPsecSessionTerminateMessage) -> int:
    payload = bytes(msg.auth_tag)
    ad = AppData(msg.address, payload)
    return channel_send_appdata(channel.channel, ad)


