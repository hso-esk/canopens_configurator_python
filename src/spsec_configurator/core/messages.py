# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .spsec_definitions import (
    AUTH_TAG_SIZE,
    RANDOM_SIZE,
    REQUIRED_NONCE_LEN,
)


@dataclass
class SPsecMessage:
    msg_type: int
    msg_content: object


@dataclass
class SPsecClientHelloMessage:
    participant_id: int
    key_selector: bytes
    random: bytes


def spsecclienthello_new(participant_id: int, key_selector: int, random: bytes) -> SPsecClientHelloMessage:
    if len(random) != RANDOM_SIZE:
        raise ValueError("random must be 16 bytes")
    ks = bytes([key_selector, 0xFF, 0xFF, 0xFF])
    return SPsecClientHelloMessage(participant_id, ks, random)


@dataclass
class SPsecServerHelloMessage:
    participant_id: int
    random: bytes


@dataclass
class SPsecClientFinishedMessage:
    participant_id: int
    cnt: int
    auth_tag: bytearray = field(default_factory=lambda: bytearray(AUTH_TAG_SIZE))
    address: int = 0


@dataclass
class SPsecServerFinishedMessage:
    participant_id: int
    cnt: int
    auth_tag: bytes
    address: int


@dataclass
class SPsecReadInitiateMessage:
    pid: int
    cnt: int
    reg: int
    len: int
    address: int = 0
    plaintext: bytearray = field(default_factory=lambda: bytearray(8))
    ciphertext: bytearray = field(default_factory=lambda: bytearray(8))
    auth_tag: bytearray = field(default_factory=lambda: bytearray(AUTH_TAG_SIZE))


@dataclass
class SPsecClientReadSegmentRequest:
    pid: int
    cnt: int
    address: int = 0
    auth_tag: bytearray = field(default_factory=lambda: bytearray(AUTH_TAG_SIZE))


@dataclass
class SPsecServerReadSegmentResponse:
    pid: int
    cnt: int
    dat: bytearray
    data_len: int
    address: int = 0
    ciphertext_ptr: bytearray | None = None
    auth_tag: bytearray = field(default_factory=lambda: bytearray(AUTH_TAG_SIZE))


@dataclass
class SPsecWriteInitiateMessage:
    pid: int
    cnt: int
    reg: int
    len: int
    address: int = 0
    plaintext: bytearray = field(default_factory=lambda: bytearray(8))
    ciphertext: bytearray = field(default_factory=lambda: bytearray(8))
    auth_tag: bytearray = field(default_factory=lambda: bytearray(AUTH_TAG_SIZE))


@dataclass
class SPsecClientWriteSegmentRequest:
    pid: int
    cnt: int
    dat: bytes
    data_len: int
    address: int = 0
    ciphertext_ptr: bytearray | None = None
    auth_tag: bytearray = field(default_factory=lambda: bytearray(AUTH_TAG_SIZE))


@dataclass
class SPsecClientWriteSegmentResponse:
    pid: int
    cnt: int
    err: int
    address: int = 0
    plaintext: bytearray = field(default_factory=lambda: bytearray(4))
    ciphertext: bytearray = field(default_factory=lambda: bytearray(4))
    auth_tag: bytearray = field(default_factory=lambda: bytearray(AUTH_TAG_SIZE))


@dataclass
class SPsecSessionTerminateMessage:
    pid: int
    cnt: int
    address: int = 0
    auth_tag: bytearray = field(default_factory=lambda: bytearray(AUTH_TAG_SIZE))


@dataclass
class SPsecHeartbeatMessage:
    participant_id: int
    status: int
    auth_tag: bytes


@dataclass
class AppData:
    address: int
    data: bytes


@dataclass
class SPsecAppData:
    address: int
    secure_data: bytes
    secure_data_len: int
    padding_size: int
    timestamp: bytearray
    auth_tag: bytes
    auth_tag_len: int


@dataclass
class ConfigurationSessionAuthTagData:
    key_selector: bytearray
    cli_random: bytearray
    srv_random: bytearray
    cli_auth_tag: bytearray
    address: int
    spsec_salt: "SPsecSalt | None"


def authtagparticipantdata_new() -> ConfigurationSessionAuthTagData:
    return ConfigurationSessionAuthTagData(
        key_selector=bytearray(b"\x00\xFF\xFF\xFF"),
        cli_random=bytearray(RANDOM_SIZE),
        srv_random=bytearray(RANDOM_SIZE),
        cli_auth_tag=bytearray(AUTH_TAG_SIZE),
        address=0,
        spsec_salt=None,
    )


def calculate_shared_cnt(data: ConfigurationSessionAuthTagData) -> int:
    # XOR first 4 bytes of cli_random and srv_random, LE
    xor_bytes = bytes(a ^ b for a, b in zip(data.cli_random[:4], data.srv_random[:4]))
    return xor_bytes[0] | (xor_bytes[1] << 8) | (xor_bytes[2] << 16) | (xor_bytes[3] << 24)


def generate_nonce_from_session_cnt(session_cnt: int, salt: "SPsecSalt") -> bytes:
    if salt is None:
        raise ValueError("salt is required")
    if session_cnt >= 0xFFFFFFFF - 1000:
        raise ValueError(f"Session counter {session_cnt} is within wrap margin (1000)")
    # Little-endian counter + salt bytes to fill 16
    nonce = bytearray(REQUIRED_NONCE_LEN)
    nonce[0] = session_cnt & 0xFF
    nonce[1] = (session_cnt >> 8) & 0xFF
    nonce[2] = (session_cnt >> 16) & 0xFF
    nonce[3] = (session_cnt >> 24) & 0xFF
    copy_len = min(len(salt.salt), REQUIRED_NONCE_LEN - 4)
    nonce[4:4 + copy_len] = salt.salt[:copy_len]
    return bytes(nonce)


