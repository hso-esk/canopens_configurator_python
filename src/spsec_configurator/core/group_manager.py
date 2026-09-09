# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Software-side group management; keys distributed via existing register ops."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional, List, Dict
from pathlib import Path

from .logging_util import log_info, log_error, log_debug
from .spsec_definitions import KEY_LEN, SALT_LEN


@dataclass
class GroupKeys:
    """Keys associated with a group"""
    integrator_key: bytes
    integrator_salt: bytes
    integrator_key_id: int
    seed_key: bytes
    seed_salt: bytes
    seed_key_id: int

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "integrator_key": self.integrator_key.hex(),
            "integrator_salt": self.integrator_salt.hex(),
            "integrator_key_id": self.integrator_key_id,
            "seed_key": self.seed_key.hex(),
            "seed_salt": self.seed_salt.hex(),
            "seed_key_id": self.seed_key_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> GroupKeys:
        """Create from dictionary"""
        return cls(
            integrator_key=bytes.fromhex(data["integrator_key"]),
            integrator_salt=bytes.fromhex(data["integrator_salt"]),
            integrator_key_id=data["integrator_key_id"],
            seed_key=bytes.fromhex(data["seed_key"]),
            seed_salt=bytes.fromhex(data["seed_salt"]),
            seed_key_id=data["seed_key_id"],
        )


@dataclass
class Group:
    """Represents a group of field devices"""
    group_id: int
    name: str
    description: Optional[str] = None
    member_pids: List[int] = field(default_factory=list)
    group_keys: Optional[GroupKeys] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        result = {
            "group_id": self.group_id,
            "name": self.name,
            "description": self.description,
            "member_pids": self.member_pids,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        if self.group_keys:
            result["group_keys"] = self.group_keys.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: dict) -> Group:
        """Create from dictionary"""
        group = cls(
            group_id=data["group_id"],
            name=data["name"],
            description=data.get("description"),
            member_pids=data.get("member_pids", []),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
        )
        if "group_keys" in data:
            group.group_keys = GroupKeys.from_dict(data["group_keys"])
        return group

    def add_member(self, pid: int) -> bool:
        """Add a participant to the group"""
        if pid not in self.member_pids:
            self.member_pids.append(pid)
            self.updated_at = datetime.now(timezone.utc).isoformat()
            log_info("group_manager", "Added PID %d to group %d (%s)", pid, self.group_id, self.name)
            return True
        return False

    def remove_member(self, pid: int) -> bool:
        """Remove a participant from the group"""
        if pid in self.member_pids:
            self.member_pids.remove(pid)
            self.updated_at = datetime.now(timezone.utc).isoformat()
            log_info("group_manager", "Removed PID %d from group %d (%s)", pid, self.group_id, self.name)
            return True
        return False

    def has_member(self, pid: int) -> bool:
        """Check if participant is in the group"""
        return pid in self.member_pids


@dataclass
class DeviceInfo:
    """Information about a field device"""
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
    groups: List[int] = field(default_factory=list)
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_heartbeat: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "participant_id": self.participant_id,
            "device_type": self.device_type,
            "firmware_version": self.firmware_version,
            "core_version": self.core_version,
            "mapping_version": self.mapping_version,
            "device_identification": self.device_identification,
            "mcu_serial_number": self.mcu_serial_number,
            "provisioning_key_id": self.provisioning_key_id,
            "integrator_key_id": self.integrator_key_id,
            "seed_key_id": self.seed_key_id,
            "status": self.status,
            "last_security_event": self.last_security_event,
            "groups": self.groups,
            "last_seen": self.last_seen,
            "last_heartbeat": self.last_heartbeat,
        }

    @classmethod
    def from_dict(cls, data: dict) -> DeviceInfo:
        """Create from dictionary"""
        return cls(
            participant_id=data["participant_id"],
            device_type=data.get("device_type"),
            firmware_version=data.get("firmware_version"),
            core_version=data.get("core_version"),
            mapping_version=data.get("mapping_version"),
            device_identification=data.get("device_identification"),
            mcu_serial_number=data.get("mcu_serial_number"),
            provisioning_key_id=data.get("provisioning_key_id"),
            integrator_key_id=data.get("integrator_key_id"),
            seed_key_id=data.get("seed_key_id"),
            status=data.get("status"),
            last_security_event=data.get("last_security_event"),
            groups=data.get("groups", []),
            last_seen=data.get("last_seen", datetime.now(timezone.utc).isoformat()),
            last_heartbeat=data.get("last_heartbeat"),
        )


class GroupManager:
    """Manages groups of field devices"""

    def __init__(self, config_file: str = "groups_config.json"):
        """Initialize group manager with configuration file"""
        self.config_file = Path(config_file)
        self.groups: Dict[int, Group] = {}
        self.devices: Dict[int, DeviceInfo] = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration from file"""
        if not self.config_file.exists():
            log_info("group_manager", "Configuration file %s does not exist, starting with empty configuration", str(self.config_file))
            return

        try:
            with open(self.config_file, "r") as f:
                data = json.load(f)

            # Load groups
            if "groups" in data:
                for group_data in data["groups"]:
                    group = Group.from_dict(group_data)
                    self.groups[group.group_id] = group
                    log_debug("group_manager", "Loaded group %d: %s (%d members)", group.group_id, group.name, len(group.member_pids))

            # Load devices
            if "devices" in data:
                for device_data in data["devices"]:
                    device = DeviceInfo.from_dict(device_data)
                    self.devices[device.participant_id] = device
                    log_debug("group_manager", "Loaded device PID %d", device.participant_id)

            log_info("group_manager", "Loaded configuration: %d groups, %d devices", len(self.groups), len(self.devices))
        except Exception as e:
            log_error("group_manager", "Failed to load configuration: %s", e)
            self.groups = {}
            self.devices = {}

    def _save_config(self) -> bool:
        """Save configuration to file"""
        try:
            # Create a backup snapshot before overwriting configuration
            from .config_history import snapshot
            snapshot(self.config_file)

            # Ensure directory exists
            self.config_file.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "version": "1.0",
                "groups": [group.to_dict() for group in self.groups.values()],
                "devices": [device.to_dict() for device in self.devices.values()],
            }

            # Write to temporary file first, then rename (atomic operation)
            temp_file = self.config_file.with_suffix(".tmp")
            fd = os.open(temp_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with open(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(temp_file, 0o600)

            temp_file.replace(self.config_file)
            log_debug("group_manager", "Saved configuration to %s", str(self.config_file))
            return True
        except Exception as e:
            log_error("group_manager", "Failed to save configuration: %s", e)
            return False

    def create_group(self, group_id: int, name: str, description: Optional[str] = None) -> Group:
        """Create a new group"""
        if group_id in self.groups:
            raise ValueError(f"Group {group_id} already exists")

        group = Group(
            group_id=group_id,
            name=name,
            description=description,
        )
        self.groups[group_id] = group
        self._save_config()
        log_info("group_manager", "Created group %d: %s", group_id, name)
        return group

    def delete_group(self, group_id: int) -> bool:
        """Delete a group and remove all members"""
        if group_id not in self.groups:
            return False

        group = self.groups[group_id]
        # Remove group from all devices
        for pid in list(group.member_pids):
            self.remove_device_from_group(group_id, pid)

        del self.groups[group_id]
        self._save_config()
        log_info("group_manager", "Deleted group %d: %s", group_id, group.name)
        return True

    def get_group(self, group_id: int) -> Optional[Group]:
        """Get a group by ID"""
        return self.groups.get(group_id)

    def list_groups(self) -> List[Group]:
        """List all groups"""
        return list(self.groups.values())

    def add_device_to_group(self, group_id: int, participant_id: int) -> bool:
        """Add a device to a group"""
        if group_id not in self.groups:
            log_error("group_manager", "Group %d does not exist", group_id)
            return False

        group = self.groups[group_id]
        if group.add_member(participant_id):
            # Update device info
            if participant_id not in self.devices:
                self.devices[participant_id] = DeviceInfo(participant_id=participant_id)
            device = self.devices[participant_id]
            if group_id not in device.groups:
                device.groups.append(group_id)
            self._save_config()
            return True
        return False

    def remove_device_from_group(self, group_id: int, participant_id: int) -> bool:
        """Remove a device from a group"""
        if group_id not in self.groups:
            return False

        group = self.groups[group_id]
        if group.remove_member(participant_id):
            # Update device info
            if participant_id in self.devices:
                device = self.devices[participant_id]
                if group_id in device.groups:
                    device.groups.remove(group_id)
            self._save_config()
            return True
        return False

    def list_group_members(self, group_id: int) -> List[int]:
        """List all member PIDs in a group"""
        if group_id not in self.groups:
            return []
        return list(self.groups[group_id].member_pids)

    def get_device_groups(self, participant_id: int) -> List[Group]:
        """Get all groups a device belongs to"""
        if participant_id not in self.devices:
            return []
        group_ids = self.devices[participant_id].groups
        return [self.groups[gid] for gid in group_ids if gid in self.groups]

    def is_device_in_group(self, group_id: int, participant_id: int) -> bool:
        """Check if device is in group"""
        if group_id not in self.groups:
            return False
        return self.groups[group_id].has_member(participant_id)

    def set_group_keys(self, group_id: int, keys: GroupKeys) -> bool:
        """Set keys for a group"""
        if group_id not in self.groups:
            return False
        self.groups[group_id].group_keys = keys
        self._save_config()
        log_info("group_manager", "Set keys for group %d", group_id)
        return True

    def get_group_keys(self, group_id: int) -> Optional[GroupKeys]:
        """Get keys for a group"""
        if group_id not in self.groups:
            return None
        return self.groups[group_id].group_keys

    def register_device(self, participant_id: int, **kwargs) -> DeviceInfo:
        """Register a device in the system"""
        if participant_id not in self.devices:
            self.devices[participant_id] = DeviceInfo(participant_id=participant_id)
        
        device = self.devices[participant_id]
        for key, value in kwargs.items():
            if hasattr(device, key) and value is not None:
                setattr(device, key, value)
        
        device.last_seen = datetime.now(timezone.utc).isoformat()
        self._save_config()
        return self.devices[participant_id]

    def get_device(self, participant_id: int) -> Optional[DeviceInfo]:
        """Get device information"""
        return self.devices.get(participant_id)

    def list_devices(self) -> List[DeviceInfo]:
        """List all registered devices"""
        return list(self.devices.values())

