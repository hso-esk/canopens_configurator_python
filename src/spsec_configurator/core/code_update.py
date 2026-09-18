# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Authenticated code update transport: capabilities/pubkey/chunks (regs 0x90-0x92)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .configurator import (
    Configurator,
    configurator_read_register,
    configurator_write_register,
)
from .logging_util import log_info, log_error, log_warning
from .spsec_definitions import KEY_LEN

SPSEC_REG_CODE_UPDATE_CAPABILITIES = 0x90
SPSEC_REG_PUBLIC_AUTH_KEY = 0x91
SPSEC_REG_CODE_UPDATE_FILE = 0x92

#: Maximum firmware image size accepted by register 92h (4096 bytes).
MAX_IMAGE_BYTES = 4096


@dataclass
class CodeUpdateCapabilities:
    """Decoded 90h word (SPsec302 §2.3.7.1)."""

    raw: int
    update_capable: bool
    manufacturer: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "CodeUpdateCapabilities":
        raw = int.from_bytes(data[:4], "little")
        return cls(
            raw=raw,
            update_capable=bool(raw & 0x1),
            manufacturer=(raw >> 24) & 0xFF,
        )


def read_code_update_capabilities(
    cfg: Configurator, target_pid: int
) -> Optional[CodeUpdateCapabilities]:
    """Read and decode 90h. Returns None if the register cannot be read."""
    buf = bytearray(4)
    ret = configurator_read_register(
        cfg, target_pid, SPSEC_REG_CODE_UPDATE_CAPABILITIES, buf, 4
    )
    if ret != 0:
        log_error("code_update", "Failed to read code update capabilities: %d", ret)
        return None
    caps = CodeUpdateCapabilities.from_bytes(bytes(buf))
    log_info(
        "code_update",
        "PID %d code update: capable=%s, manufacturer bits=0x%02X",
        target_pid, caps.update_capable, caps.manufacturer,
    )
    return caps


def read_public_auth_key(cfg: Configurator, target_pid: int) -> Optional[bytes]:
    """Read 91h (the key the device verifies images against) so an operator
    can confirm the trusted signer; this module doesn't verify anything itself."""
    buf = bytearray(KEY_LEN)
    ret = configurator_read_register(
        cfg, target_pid, SPSEC_REG_PUBLIC_AUTH_KEY, buf, KEY_LEN
    )
    if ret != 0:
        log_error("code_update", "Failed to read public authentication key: %d", ret)
        return None
    return bytes(buf)


def upload_code_update_file(
    cfg: Configurator,
    target_pid: int,
    image: bytes,
    check_capability: bool = True,
) -> int:
    """Write `image` to 92h. Success means bytes were stored, NOT verified -
    image format/signature scheme is undefined in SPsec302 §2.3.7.3."""
    if not image:
        log_error("code_update", "Refusing to upload an empty image")
        return -1
    if len(image) > MAX_IMAGE_BYTES:
        log_error(
            "code_update",
            "Image is %d bytes, above the %d byte transfer limit",
            len(image), MAX_IMAGE_BYTES,
        )
        return -1

    if check_capability:
        caps = read_code_update_capabilities(cfg, target_pid)
        if caps is None:
            return -2
        if not caps.update_capable:
            log_error(
                "code_update",
                "PID %d reports no code update capability (90h bit 0 clear)",
                target_pid,
            )
            return -3

        # Check public key availability before starting firmware transfer.
        if read_public_auth_key(cfg, target_pid) is None:
            log_warning(
                "code_update",
                "Could not read the public authentication key (91h); the "
                "participant may refuse the upload",
            )

    log_info("code_update", "Uploading %d byte image to PID %d", len(image), target_pid)
    ret = configurator_write_register(
        cfg, target_pid, SPSEC_REG_CODE_UPDATE_FILE, image, len(image)
    )
    if ret != 0:
        log_error("code_update", "Code update upload failed: %d", ret)
        return ret

    log_info(
        "code_update",
        "Image stored on PID %d; it is applied on the next power cycle. "
        "Acceptance is NOT a signature verification.",
        target_pid,
    )
    return 0
