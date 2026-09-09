# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Discover/enumerate devices on the CAN network via register reads."""

from __future__ import annotations

import time
from typing import List, Optional, Dict
from dataclasses import dataclass

from .configurator import Configurator, configurator_init, configurator_destroy
from .configurator import configurator_start_session, configurator_read_register, configurator_terminate_session
from .spsec_definitions import (
    SPSEC_REG_STATUS,
    SPSEC_REG_CORE_VERSION_INFO,
    SPSEC_REG_MAPPING_VERSION_INFO,
    SPSEC_KEY_SELECTOR_ZERO_KEY,
    SPSEC_KEY_SELECTOR_PROVISIONING_KEY,
    SPSEC_KEY_SELECTOR_INTEGRATOR_KEY,
)
from .logging_util import log_info, log_error, log_debug
from .group_manager import DeviceInfo, GroupManager


@dataclass
class DiscoveredDevice:
    """Information about a discovered device"""
    participant_id: int
    device_type: Optional[str] = None
    firmware_version: Optional[str] = None
    core_version: Optional[str] = None
    mapping_version: Optional[str] = None
    device_identification: Optional[str] = None
    mcu_serial_number: Optional[str] = None
    provisioning_key_id: Optional[int] = None
    integrator_key_id: Optional[int] = None
    seed_key_id: Optional[int] = None
    status: Optional[int] = None
    last_security_event: Optional[int] = None
    reachable: bool = False
    response_time_ms: float = 0.0


def discover_device(
    cfg: Configurator,
    participant_id: int,
    timeout_seconds: float = 2.0,
    key_selector: int = SPSEC_KEY_SELECTOR_ZERO_KEY,
) -> Optional[DiscoveredDevice]:
    """Query a device (None if no ClientHello reply). Seed key (13) is NOT
    valid here - it derives Comm Keys and can't open a session."""
    from .spsec_definitions import (
        SPSEC_REG_PROVISIONING_KEY_ID,
        SPSEC_REG_INTEGRATOR_KEY_ID,
        SPSEC_REG_SEED_KEY_ID,
        SPSEC_REG_DEVICE_IDENTIFICATION,
        SPSEC_REG_MCU_SERIAL_NUMBER,
        SPSEC_REG_LAST_SECURITY_EVENT,
    )
    import struct

    start_time = time.time()
    
    device = DiscoveredDevice(participant_id=participant_id)
    
    # Try to establish session using selected key
    log_debug("device_discovery", "Trying key selector %d for device %d", key_selector, participant_id)
    # Use float timeout directly to allow sub-second deadlines
    ret = configurator_start_session(cfg, participant_id, key_selector, timeout_seconds)
    if ret < 0:
        log_debug("device_discovery", "Device %d not reachable (session failed: %d)", participant_id, ret)
        return None
    
    device.reachable = True

    def _read_reg_bytes(reg: int, length: int) -> Optional[bytearray]:
        """Read a register, returning None on failure without aborting."""
        buf = bytearray(length)
        r = configurator_read_register(cfg, participant_id, reg, buf, length)
        if r == 0:
            return buf
        log_debug("device_discovery", "Register 0x%02X read skipped for PID %d (ret=%d)", reg, participant_id, r)
        return None

    try:
        # Read status register (0x50)
        data = _read_reg_bytes(SPSEC_REG_STATUS, 1)
        if data is not None:
            device.status = data[0]

        # Read last security event (0x51)
        data = _read_reg_bytes(SPSEC_REG_LAST_SECURITY_EVENT, 2)
        if data is not None:
            device.last_security_event = struct.unpack("<H", data)[0]

        # Read core version info (0x58)
        data = _read_reg_bytes(SPSEC_REG_CORE_VERSION_INFO, 16)
        if data is not None:
            try:
                device.core_version = bytes(data).split(b"\x00", 1)[0].decode(errors="ignore")
            except Exception:
                pass

        # Read mapping version info (0x59)
        data = _read_reg_bytes(SPSEC_REG_MAPPING_VERSION_INFO, 16)
        if data is not None:
            try:
                device.mapping_version = bytes(data).split(b"\x00", 1)[0].decode(errors="ignore")
            except Exception:
                pass

        # Read device identification (0x81)
        data = _read_reg_bytes(SPSEC_REG_DEVICE_IDENTIFICATION, 32)
        if data is not None:
            try:
                device.device_identification = bytes(data).split(b"\x00", 1)[0].decode(errors="ignore")
            except Exception:
                pass

        # Read MCU serial number (0x82, 16 bytes)
        data = _read_reg_bytes(SPSEC_REG_MCU_SERIAL_NUMBER, 16)
        if data is not None:
            raw = bytes(data)
            device.mcu_serial_number = raw.hex() if any(raw) else None

        # Read Provisioning Key ID (0x41) — may not be set on unprovisioned device
        data = _read_reg_bytes(SPSEC_REG_PROVISIONING_KEY_ID, 4)
        if data is not None:
            device.provisioning_key_id = struct.unpack("<I", data)[0]

        # Read Integrator Key ID (0x42) — optional, device may not have integrator key
        data = _read_reg_bytes(SPSEC_REG_INTEGRATOR_KEY_ID, 4)
        if data is not None:
            device.integrator_key_id = struct.unpack("<I", data)[0]

        # Read Seed Key ID (0x43) — optional
        data = _read_reg_bytes(SPSEC_REG_SEED_KEY_ID, 4)
        if data is not None:
            device.seed_key_id = struct.unpack("<I", data)[0]

    except Exception as exc:
        log_error("device_discovery", "Exception during register reads for PID %d: %s", participant_id, exc)
    finally:
        # Always attempt to terminate — terminate has its own timeout now
        configurator_terminate_session(cfg, participant_id)

    device.response_time_ms = (time.time() - start_time) * 1000

    log_info(
        "device_discovery",
        "Discovered device %d: core=%s, mapping=%s, status=0x%02X, id=%s, keys(P:0x%s, I:0x%s, S:0x%s)",
        participant_id,
        device.core_version or "?",
        device.mapping_version or "?",
        device.status or 0,
        device.device_identification or "?",
        f"{device.provisioning_key_id:08X}" if device.provisioning_key_id is not None else "None",
        f"{device.integrator_key_id:08X}" if device.integrator_key_id is not None else "None",
        f"{device.seed_key_id:08X}" if device.seed_key_id is not None else "None",
    )

    return device




def scan_network(
    cfg: Configurator,
    pid_range: range = range(1, 128),
    timeout_per_device: float = 1.0,
    key_selector: int = SPSEC_KEY_SELECTOR_ZERO_KEY,
) -> List[DiscoveredDevice]:
    """Probe pid_range and return the devices that responded."""
    discovered: List[DiscoveredDevice] = []
    
    key_name = {1: "Zero", 15: "Provisioning", 14: "Integrator", 13: "Seed"}.get(key_selector, f"Key {key_selector}")
    log_info("device_discovery", "Scanning network for devices in range %d-%d using %s key...", 
             pid_range.start, pid_range.stop - 1, key_name)
    
    for pid in pid_range:
        device = discover_device(cfg, pid, timeout_per_device, key_selector)
        if device and device.reachable:
            discovered.append(device)
            log_info("device_discovery", "Found device: PID %d (response: %.2f ms)", pid, device.response_time_ms)
    
    log_info("device_discovery", "Scan complete: found %d device(s)", len(discovered))
    return discovered


def discover_and_register(
    cfg: Configurator,
    group_manager: GroupManager,
    pid_range: range = range(1, 128),
    timeout_per_device: float = 1.0,
    key_selector: int = SPSEC_KEY_SELECTOR_ZERO_KEY,
) -> Dict[int, DiscoveredDevice]:
    """Scan pid_range and register each found device. Default key_selector
    is the Zero Key, scoped to read-only discovery registers."""
    # Scan network with the requested key selector
    discovered = scan_network(cfg, pid_range, timeout_per_device, key_selector=key_selector)
    result: Dict[int, DiscoveredDevice] = {}
    
    for device in discovered:
        # Register device in group manager
        device_info = group_manager.register_device(
            device.participant_id,
            device_type=device.device_type,
            firmware_version=device.core_version,
        )
        result[device.participant_id] = device
        
        log_info("device_discovery", "Registered device PID %d in group manager", device.participant_id)
    
    return result


def get_device_info(
    cfg: Configurator,
    participant_id: int,
    timeout_seconds: float = 2.0,
) -> Optional[DiscoveredDevice]:
    """Alias for discover_device()."""
    return discover_device(cfg, participant_id, timeout_seconds)


def device_is_unprovisioned(device) -> bool:
    """True if the device has no usable Provisioning Key (None, or the
    erased sentinel FFFFFFFFh/0, same as register_is_key_set() on-device)."""
    if device is None:
        return False
    key_id = device.provisioning_key_id
    return key_id is None or key_id in (0x00000000, 0xFFFFFFFF)
