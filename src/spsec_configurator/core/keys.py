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

from .logging_util import log_error, log_info, log_debug
from .spsec_definitions import KEY_LEN, SALT_LEN
import secrets


@dataclass
class SPsecKey:
    key: bytearray
    key_id: int


@dataclass
class SPsecSalt:
    salt: bytearray


@dataclass
class CommunicationKeys:
    spsec_salt: list[Optional[SPsecSalt]]
    spsec_keys: list[Optional[SPsecKey]]
    current_key: bytearray
    prepared_key: bytearray
    last_key_ts: int
    last_23_bit_state: bool


def spseckey_new(key_id: int, data: bytes) -> SPsecKey:
    if len(data) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    return SPsecKey(bytearray(data), key_id)

def generate_key_id() -> int:
    """Random Key ID in 1..0xFFFFFFFE (0=not installed, 0xFFFFFFFF=reserved
    invalidation value, REQ-CFG-006/007)."""
    return secrets.randbelow(0xFFFFFFFE) + 1


def spsecsalt_new(data: bytes) -> SPsecSalt:
    if len(data) > SALT_LEN:
        data = data[:SALT_LEN]
    elif len(data) < SALT_LEN:
        raise ValueError(f"salt must be at least {SALT_LEN} bytes")
    return SPsecSalt(bytearray(data))


def communication_keys_init() -> CommunicationKeys:
    # index: 0 zero, 1 provisioning, 2 integrator, 3 seed
    salts: list[Optional[SPsecSalt]] = [None, None, None, None]
    keys: list[Optional[SPsecKey]] = [None, None, None, None]
    keys[0] = spseckey_new(0, bytes(KEY_LEN))
    salts[0] = spsecsalt_new(bytes(SALT_LEN))
    # Detailed zero key/salt state
    log_debug("keys", "Current Zero key address: 0x%x", id(keys[0]))
    log_debug("keys", "Current Zero key data [%s]", " ".join(f"{b:02X}" for b in keys[0].key))
    log_debug("keys", "Current Zero salt address: 0x%x", id(salts[0]))
    log_debug("keys", "Current Zero salt data [%s]", " ".join(f"{b:02X}" for b in salts[0].salt))
    comm = CommunicationKeys(
        spsec_salt=salts,
        spsec_keys=keys,
        current_key=bytearray(KEY_LEN),
        prepared_key=bytearray(KEY_LEN),
        last_key_ts=0,
        last_23_bit_state=False,
    )
    log_info("keys", "Communication keys initialized successfully")
    return comm


def parse_hex_bytes(hex_str: str) -> bytes:
    s = hex_str.strip().replace(" ", "")
    if len(s) % 2 != 0:
        raise ValueError("hex length must be even")
    return bytes(int(s[i : i + 2], 16) for i in range(0, len(s), 2))


def load_kv_hex_file(path: str, key: str) -> "bytes | None":
    try:
        with open(path, "r") as f:
            for line in f:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                if k.strip() != key:
                    continue
                raw = v.strip()
                data = parse_hex_bytes(raw)
                # Match C logger name without leaking secret key material
                log_info("spsec_common", "Value %s found in file %s", key, path)
                return data
    except Exception as e:
        log_error("keys", "Failed to open %s: %s", path, e)
        return None
    log_error("keys", "Value %s not found in file %s", key, path)
    return None


