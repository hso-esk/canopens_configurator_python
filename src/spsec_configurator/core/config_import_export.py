# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Import/export group configurations (and their keys) to JSON files."""

from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Dict, Optional, List

from .group_manager import GroupManager, Group, GroupKeys, DeviceInfo
from .logging_util import log_info, log_error, log_warning


def export_configuration(
    group_manager: GroupManager,
    filepath: str,
    format: str = "json",
) -> bool:
    """Write all groups and devices to filepath as JSON. Only "json" format
    is currently supported."""
    if format != "json":
        log_error("config_import_export", "Unsupported export format: %s", format)
        return False
    
    try:
        export_path = Path(filepath)
        export_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Build export data
        data = {
            "version": "1.0",
            "export_timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "groups": [group.to_dict() for group in group_manager.list_groups()],
            "devices": [device.to_dict() for device in group_manager.list_devices()],
        }
        
        # Write to file
        fd = os.open(export_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(export_path, 0o600)
        
        log_info("config_import_export", "Exported configuration to %s (%d groups, %d devices)",
                filepath, len(data["groups"]), len(data["devices"]))
        return True
    except Exception as e:
        log_error("config_import_export", "Failed to export configuration: %s", e)
        return False


def import_configuration(
    group_manager: GroupManager,
    filepath: str,
    format: str = "json",
    merge: bool = False,
) -> bool:
    """Load groups/devices from filepath. merge=False replaces existing
    groups first; merge=True updates in place."""
    if format != "json":
        log_error("config_import_export", "Unsupported import format: %s", format)
        return False
    
    try:
        import_path = Path(filepath)
        if not import_path.exists():
            log_error("config_import_export", "Import file does not exist: %s", filepath)
            return False
        
        # Read file
        with open(import_path, "r") as f:
            data = json.load(f)
        
        if not merge:
            # Clear existing groups (but keep devices for reference)
            for group in list(group_manager.list_groups()):
                group_manager.delete_group(group.group_id)
        
        # Import groups
        imported_groups = 0
        for group_data in data.get("groups", []):
            try:
                group = Group.from_dict(group_data)
                # Check if group exists
                existing = group_manager.get_group(group.group_id)
                if existing and not merge:
                    log_warning("config_import_export", "Group %d already exists, skipping", group.group_id)
                    continue
                elif existing and merge:
                    # Update existing group
                    existing.name = group.name
                    existing.description = group.description
                    if group.group_keys:
                        existing.group_keys = group.group_keys
                    group_manager._save_config()
                else:
                    # Create new group
                    group_manager.groups[group.group_id] = group
                    group_manager._save_config()
                imported_groups += 1
            except Exception as e:
                log_error("config_import_export", "Failed to import group: %s", e)
        
        # Import devices
        imported_devices = 0
        for device_data in data.get("devices", []):
            try:
                device = DeviceInfo.from_dict(device_data)
                group_manager.register_device(
                    device.participant_id,
                    device_type=device.device_type,
                    firmware_version=device.firmware_version,
                )
                # Update groups if specified
                if device.groups:
                    for group_id in device.groups:
                        if group_manager.get_group(group_id):
                            group_manager.add_device_to_group(group_id, device.participant_id)
                imported_devices += 1
            except Exception as e:
                log_error("config_import_export", "Failed to import device: %s", e)
        
        log_info("config_import_export", "Imported configuration from %s (%d groups, %d devices)",
                filepath, imported_groups, imported_devices)
        return True
    except Exception as e:
        log_error("config_import_export", "Failed to import configuration: %s", e)
        return False


def export_group_keys(
    group_manager: GroupManager,
    group_id: int,
    filepath: str,
) -> bool:
    """Export group_id's keys to filepath, for backup/transfer."""
    group = group_manager.get_group(group_id)
    if not group or not group.group_keys:
        log_error("config_import_export", "Group %d does not exist or has no keys", group_id)
        return False
    
    try:
        export_path = Path(filepath)
        export_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "group_id": group_id,
            "group_name": group.name,
            "keys": group.group_keys.to_dict(),
            "export_timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        }
        
        fd = os.open(export_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(export_path, 0o600)
        
        log_info("config_import_export", "Exported keys for group %d to %s", group_id, filepath)
        return True
    except Exception as e:
        log_error("config_import_export", "Failed to export group keys: %s", e)
        return False


def import_group_keys(
    group_manager: GroupManager,
    group_id: int,
    filepath: str,
) -> bool:
    """Import keys for group_id from filepath."""
    try:
        import_path = Path(filepath)
        if not import_path.exists():
            log_error("config_import_export", "Import file does not exist: %s", filepath)
            return False
        
        with open(import_path, "r") as f:
            data = json.load(f)
        
        if data.get("group_id") != group_id:
            log_warning("config_import_export", "File group_id (%d) does not match requested group_id (%d)",
                       data.get("group_id"), group_id)
        
        keys = GroupKeys.from_dict(data["keys"])
        group_manager.set_group_keys(group_id, keys)
        
        log_info("config_import_export", "Imported keys for group %d from %s", group_id, filepath)
        return True
    except Exception as e:
        log_error("config_import_export", "Failed to import group keys: %s", e)
        return False

