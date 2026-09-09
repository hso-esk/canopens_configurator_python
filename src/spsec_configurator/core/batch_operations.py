# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Batch versions of the single-device/group operations, for driving many
devices at once."""

from __future__ import annotations

from typing import List, Dict, Optional, Callable
from dataclasses import dataclass

from .configurator import Configurator
from .group_manager import GroupManager
from .group_operations import (
    add_device_to_group_with_keys,
    remove_device_from_group,
    distribute_group_keys,
    verify_group_keys,
)
from .configurator import configurator_bootstrap_device, configurator_factory_reset
from .group_manager import GroupKeys
from .logging_util import log_info, log_error, log_warning


@dataclass
class BatchResult:
    """Result of a batch operation"""
    total: int
    successful: int
    failed: int
    failed_items: List[int]
    errors: Dict[int, str]


def batch_bootstrap_devices(
    cfg: Configurator,
    participant_ids: List[int],
    integrator_key: bytes,
    integrator_salt: bytes,
    integrator_key_id: int,
    seed_key: bytes,
    seed_salt: bytes,
    seed_key_id: int,
) -> BatchResult:
    """Bootstrap every device in participant_ids with the same key set."""
    result = BatchResult(
        total=len(participant_ids),
        successful=0,
        failed=0,
        failed_items=[],
        errors={},
    )
    
    log_info("batch_operations", "Starting batch bootstrap for %d devices", len(participant_ids))
    
    for pid in participant_ids:
        log_info("batch_operations", "Bootstrapping device %d...", pid)
        ret = configurator_bootstrap_device(
            cfg,
            pid,
            integrator_key,
            integrator_salt,
            integrator_key_id,
            seed_key,
            seed_salt,
            seed_key_id,
        )
        
        if ret == 0:
            result.successful += 1
            log_info("batch_operations", "Successfully bootstrapped device %d", pid)
        else:
            result.failed += 1
            result.failed_items.append(pid)
            result.errors[pid] = f"Bootstrap failed with code {ret}"
            log_error("batch_operations", "Failed to bootstrap device %d: %d", pid, ret)
    
    log_info("batch_operations", "Batch bootstrap complete: %d successful, %d failed", result.successful, result.failed)
    return result


def batch_add_devices_to_group(
    cfg: Configurator,
    group_manager: GroupManager,
    group_id: int,
    participant_ids: List[int],
) -> BatchResult:
    """Add each device in participant_ids to group_id."""
    result = BatchResult(
        total=len(participant_ids),
        successful=0,
        failed=0,
        failed_items=[],
        errors={},
    )
    
    log_info("batch_operations", "Adding %d devices to group %d", len(participant_ids), group_id)
    
    for pid in participant_ids:
        log_info("batch_operations", "Adding device %d to group %d...", pid, group_id)
        ret = add_device_to_group_with_keys(cfg, group_manager, group_id, pid)
        
        if ret == 0:
            result.successful += 1
            log_info("batch_operations", "Successfully added device %d to group %d", pid, group_id)
        else:
            result.failed += 1
            result.failed_items.append(pid)
            result.errors[pid] = f"Add to group failed with code {ret}"
            log_error("batch_operations", "Failed to add device %d to group %d: %d", pid, group_id, ret)
    
    log_info("batch_operations", "Batch add complete: %d successful, %d failed", result.successful, result.failed)
    return result


def batch_remove_devices_from_group(
    cfg: Configurator,
    group_manager: GroupManager,
    group_id: int,
    participant_ids: List[int],
    reset_keys: bool = False,
    rekey_survivors: bool = True,
) -> BatchResult:
    """Remove each device in participant_ids from group_id."""
    result = BatchResult(
        total=len(participant_ids),
        successful=0,
        failed=0,
        failed_items=[],
        errors={},
    )
    
    log_info("batch_operations", "Removing %d devices from group %d", len(participant_ids), group_id)
    
    for pid in participant_ids:
        log_info("batch_operations", "Removing device %d from group %d...", pid, group_id)
        ret = remove_device_from_group(cfg, group_manager, group_id, pid, reset_keys=reset_keys, rekey_survivors=rekey_survivors)
        
        if ret == 0:
            result.successful += 1
            log_info("batch_operations", "Successfully removed device %d from group %d", pid, group_id)
        else:
            result.failed += 1
            result.failed_items.append(pid)
            result.errors[pid] = f"Remove from group failed with code {ret}"
            log_error("batch_operations", "Failed to remove device %d from group %d: %d", pid, group_id, ret)
    
    log_info("batch_operations", "Batch remove complete: %d successful, %d failed", result.successful, result.failed)
    return result


def batch_factory_reset(
    cfg: Configurator,
    participant_ids: List[int],
) -> BatchResult:
    """Factory-reset every device in participant_ids."""
    result = BatchResult(
        total=len(participant_ids),
        successful=0,
        failed=0,
        failed_items=[],
        errors={},
    )
    
    log_info("batch_operations", "Factory resetting %d devices", len(participant_ids))
    
    for pid in participant_ids:
        log_info("batch_operations", "Resetting device %d...", pid)
        ret = configurator_factory_reset(cfg, pid)
        
        if ret == 0:
            result.successful += 1
            log_info("batch_operations", "Successfully reset device %d", pid)
        else:
            result.failed += 1
            result.failed_items.append(pid)
            result.errors[pid] = f"Factory reset failed with code {ret}"
            log_error("batch_operations", "Failed to reset device %d: %d", pid, ret)
    
    log_info("batch_operations", "Batch factory reset complete: %d successful, %d failed", result.successful, result.failed)
    return result


def batch_distribute_keys(
    cfg: Configurator,
    group_manager: GroupManager,
    group_ids: List[int],
) -> Dict[int, BatchResult]:
    """Distribute stored keys to every group in group_ids."""
    results: Dict[int, BatchResult] = {}
    
    log_info("batch_operations", "Distributing keys to %d groups", len(group_ids))
    
    for group_id in group_ids:
        group = group_manager.get_group(group_id)
        if not group:
            log_warning("batch_operations", "Group %d does not exist", group_id)
            continue
        
        member_count = len(group.member_pids)
        result = BatchResult(
            total=member_count,
            successful=0,
            failed=0,
            failed_items=[],
            errors={},
        )
        
        log_info("batch_operations", "Distributing keys to group %d (%d members)...", group_id, member_count)
        ret = distribute_group_keys(cfg, group_manager, group_id)
        
        if ret == 0:
            result.successful = member_count
            log_info("batch_operations", "Successfully distributed keys to group %d", group_id)
        else:
            result.failed = member_count
            result.failed_items = list(group.member_pids)
            result.errors[group_id] = f"Key distribution failed with code {ret}"
            log_error("batch_operations", "Failed to distribute keys to group %d: %d", group_id, ret)
        
        results[group_id] = result
    
    return results

