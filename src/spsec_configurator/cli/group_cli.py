# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""CLI for managing groups of field devices."""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Optional

from ..core.logging_util import configure_logging, log_info, log_error
from ..core.configurator import configurator_init, configurator_destroy
from ..core.group_manager import GroupManager, GroupKeys
from ..core.group_operations import (
    distribute_group_keys,
    add_device_to_group_with_keys,
    remove_device_from_group,
    verify_group_keys,
    update_group_keys,
)
from ..core.spsec_definitions import (
    KEY_LEN,
    SALT_LEN,
    SPSEC_KEY_SELECTOR_ZERO_KEY,
    SPSEC_KEY_SELECTOR_PROVISIONING_KEY,
    SPSEC_KEY_SELECTOR_INTEGRATOR_KEY,
)
from ..core.keys import generate_key_id
from ..core.device_discovery import device_is_unprovisioned

# CLI names for key selectors (Seed key cannot open configuration sessions)
_KEY_SELECTOR_BY_NAME = {
    "zero": SPSEC_KEY_SELECTOR_ZERO_KEY,
    "provisioning": SPSEC_KEY_SELECTOR_PROVISIONING_KEY,
    "integrator": SPSEC_KEY_SELECTOR_INTEGRATOR_KEY,
}


def generate_group_keys() -> GroupKeys:
    """Generate new random keys for a group"""
    import secrets
    
    return GroupKeys(
        integrator_key=secrets.token_bytes(KEY_LEN),
        integrator_salt=secrets.token_bytes(SALT_LEN),
        integrator_key_id=generate_key_id(),
        seed_key=secrets.token_bytes(KEY_LEN),
        seed_salt=secrets.token_bytes(SALT_LEN),
        seed_key_id=generate_key_id(),
    )


def cmd_create_group(args, group_manager: GroupManager) -> int:
    """Create a new group"""
    try:
        group = group_manager.create_group(args.group_id, args.name, args.description)
        log_info("group_cli", "Created group %d: %s", group.group_id, group.name)
        
        # Generate and set keys if requested
        if args.generate_keys:
            keys = generate_group_keys()
            group_manager.set_group_keys(args.group_id, keys)
            log_info("group_cli", "Generated keys for group %d", args.group_id)
        
        return 0
    except ValueError as e:
        log_error("group_cli", "Failed to create group: %s", e)
        return -1


def cmd_delete_group(args, group_manager: GroupManager) -> int:
    """Delete a group"""
    if group_manager.delete_group(args.group_id):
        log_info("group_cli", "Deleted group %d", args.group_id)
        return 0
    else:
        log_error("group_cli", "Group %d does not exist", args.group_id)
        return -1


def cmd_list_groups(args, group_manager: GroupManager) -> int:
    """List all groups"""
    groups = group_manager.list_groups()
    if not groups:
        print("No groups defined")
        return 0
    
    print(f"\nGroups ({len(groups)}):")
    print("-" * 80)
    for group in groups:
        print(f"  Group ID: {group.group_id}")
        print(f"  Name: {group.name}")
        if group.description:
            print(f"  Description: {group.description}")
        print(f"  Members: {len(group.member_pids)} device(s)")
        if group.member_pids:
            print(f"    PIDs: {', '.join(map(str, group.member_pids))}")
        print(f"  Created: {group.created_at}")
        print(f"  Updated: {group.updated_at}")
        print(f"  Has Keys: {'Yes' if group.group_keys else 'No'}")
        print()
    
    return 0


def cmd_add_device(args, group_manager: GroupManager) -> int:
    """Add a device to a group"""
    cfg = configurator_init(args.interface, args.keys_file)
    cfg.tx_delay_us = max(0, int(args.tx_delay_us or 0))
    
    try:
        ret = add_device_to_group_with_keys(cfg, group_manager, args.group_id, args.pid)
        if ret == 0:
            log_info("group_cli", "Successfully added PID %d to group %d", args.pid, args.group_id)
        return ret
    finally:
        configurator_destroy(cfg)


def cmd_remove_device(args, group_manager: GroupManager) -> int:
    """Remove a device from a group"""
    cfg = configurator_init(args.interface, args.keys_file)
    cfg.tx_delay_us = max(0, int(args.tx_delay_us or 0))

    try:
        ret = remove_device_from_group(cfg, group_manager, args.group_id, args.pid, args.reset_keys, rekey_survivors=args.rekey)
        if ret == 0:
            log_info("group_cli", "Successfully removed PID %d from group %d", args.pid, args.group_id)
        return ret
    finally:
        configurator_destroy(cfg)


def cmd_distribute_keys(args, group_manager: GroupManager) -> int:
    """Distribute keys to all group members"""
    cfg = configurator_init(args.interface, args.keys_file)
    cfg.tx_delay_us = max(0, int(args.tx_delay_us or 0))
    
    try:
        ret = distribute_group_keys(cfg, group_manager, args.group_id)
        if ret == 0:
            log_info("group_cli", "Successfully distributed keys to group %d", args.group_id)
        return ret
    finally:
        configurator_destroy(cfg)


def cmd_verify_keys(args, group_manager: GroupManager) -> int:
    """Verify keys for all group members"""
    cfg = configurator_init(args.interface, args.keys_file)
    cfg.tx_delay_us = max(0, int(args.tx_delay_us or 0))
    
    try:
        all_valid, failed_pids = verify_group_keys(cfg, group_manager, args.group_id)
        if all_valid:
            log_info("group_cli", "All devices in group %d have correct keys", args.group_id)
            return 0
        else:
            log_error("group_cli", "Some devices in group %d have incorrect keys: %s", args.group_id, failed_pids)
            return -1
    finally:
        configurator_destroy(cfg)


def cmd_list_members(args, group_manager: GroupManager) -> int:
    """List members of a group"""
    group = group_manager.get_group(args.group_id)
    if not group:
        log_error("group_cli", "Group %d does not exist", args.group_id)
        return -1
    
    print(f"\nGroup {args.group_id} ({group.name}):")
    print(f"  Members: {len(group.member_pids)} device(s)")
    if group.member_pids:
        for pid in group.member_pids:
            device = group_manager.get_device(pid)
            if device:
                print(f"    PID {pid}: {device.device_type or 'Unknown'} (v{device.firmware_version or '?'})")
            else:
                print(f"    PID {pid}")
    else:
        print("    (no members)")
    print()
    
    return 0


def cmd_factory_reset(args, group_manager: GroupManager) -> int:
    """Factory reset a device"""
    from ..core.configurator import configurator_factory_reset
    
    cfg = configurator_init(args.interface, args.keys_file)
    cfg.tx_delay_us = max(0, int(args.tx_delay_us or 0))
    
    try:
        ret = configurator_factory_reset(cfg, args.pid)
        if ret == 0:
            log_info("group_cli", "Successfully reset PID %d to factory defaults", args.pid)
            # Remove from all groups
            device = group_manager.get_device(args.pid)
            if device:
                for group_id in list(device.groups):
                    group_manager.remove_device_from_group(group_id, args.pid)
        return ret
    finally:
        configurator_destroy(cfg)


def cmd_bootstrap(args, group_manager: GroupManager) -> int:
    """Bootstrap a device"""
    from ..core.configurator import configurator_bootstrap_device
    
    # Load keys from keys file or use provided values
    if args.keys_file:
        from ..core.keys import load_kv_hex_file
        
        integrator_key = load_kv_hex_file(args.keys_file, "integrator_key")
        integrator_salt = load_kv_hex_file(args.keys_file, "integrator_salt")
        seed_key = load_kv_hex_file(args.keys_file, "seed_key")
        seed_salt = load_kv_hex_file(args.keys_file, "seed_salt")
        
        if not all([integrator_key, integrator_salt, seed_key, seed_salt]):
            log_error("group_cli", "Missing required keys in keys file")
            return -1
        
        # Read key IDs from file or use defaults
        integrator_key_id = 1
        seed_key_id = 2
        
        cfg = configurator_init(args.interface, args.keys_file)
    else:
        log_error("group_cli", "Keys file required for bootstrapping")
        return -1
    
    cfg.tx_delay_us = max(0, int(args.tx_delay_us or 0))
    
    try:
        ret = configurator_bootstrap_device(
            cfg,
            args.pid,
            integrator_key,
            integrator_salt,
            integrator_key_id,
            seed_key,
            seed_salt,
            seed_key_id,
        )
        if ret == 0:
            log_info("group_cli", "Successfully bootstrapped PID %d", args.pid)
            # Register device
            group_manager.register_device(args.pid)
        return ret
    finally:
        configurator_destroy(cfg)


def cmd_provision_discovered(args, group_manager: GroupManager) -> int:
    """Scan the bus and run the key ladder against every unprovisioned device."""
    from ..core.device_discovery import scan_network
    from ..core.configurator import configurator_establish_keys_sequential

    if not args.keys_file:
        log_error("group_cli", "Keys file required for provisioning")
        return -1

    cfg = configurator_init(args.interface, args.keys_file)
    cfg.tx_delay_us = max(0, int(args.tx_delay_us or 0))

    try:
        pid_range = range(args.start_pid, args.end_pid + 1)
        # Probe using Zero Key so unconfigured devices respond
        discovered = scan_network(
            cfg, pid_range, args.timeout, key_selector=SPSEC_KEY_SELECTOR_ZERO_KEY
        )

        unprovisioned = [d for d in discovered if device_is_unprovisioned(d)]
        already = [d for d in discovered if not device_is_unprovisioned(d)]

        print(f"\nFound {len(discovered)} device(s): "
              f"{len(unprovisioned)} unprovisioned, {len(already)} already provisioned")
        for d in already:
            print(f"  PID {d.participant_id}: skipped "
                  f"(provisioning key 0x{d.provisioning_key_id:08X} already installed)")
        if not unprovisioned:
            print("Nothing to provision.\n")
            return 0

        pids = [d.participant_id for d in unprovisioned]
        print(f"Provisioning: {pids}")
        if args.dry_run:
            print("--dry-run given, stopping before any write.\n")
            return 0
    finally:
        # Close the scan session before provisioning
        configurator_destroy(cfg)

    # Allow nodes time to close scan sessions before provisioning
    time.sleep(args.settle_delay)

    # Run key ladder for each unprovisioned device using fresh sessions
    def _key(c, idx):
        return c.comm_keys.spsec_keys[idx].key if c.comm_keys.spsec_keys[idx] else None

    def _salt(c, idx):
        return c.comm_keys.spsec_salt[idx].salt if c.comm_keys.spsec_salt[idx] else None

    def _key_id_of(c, idx):
        return c.comm_keys.spsec_keys[idx].key_id if c.comm_keys.spsec_keys[idx] else None

    succeeded = 0
    for pid in pids:
        cfg = configurator_init(args.interface, args.keys_file)
        cfg.tx_delay_us = max(0, int(args.tx_delay_us or 0))
        try:
            ret = configurator_establish_keys_sequential(
                cfg, pid, SPSEC_KEY_SELECTOR_ZERO_KEY,
                provisioning_key=_key(cfg, 1), provisioning_salt=_salt(cfg, 1),
                provisioning_key_id=_key_id_of(cfg, 1),
                integrator_key=_key(cfg, 2), integrator_salt=_salt(cfg, 2),
                integrator_key_id=args.integrator_key_id,
                seed_key=_key(cfg, 3), seed_salt=_salt(cfg, 3),
                seed_key_id=args.seed_key_id,
            )
            if ret == 0:
                print(f"  PID {pid}: provisioned")
                group_manager.register_device(pid)
                succeeded += 1
            else:
                print(f"  PID {pid}: FAILED (code {ret})")
        finally:
            configurator_destroy(cfg)

    print(f"\n{succeeded}/{len(pids)} device(s) provisioned\n")
    return 0 if succeeded == len(pids) else -1


def cmd_rekey_seed(args, group_manager: GroupManager) -> int:
    """Install a new Seed key on an already-provisioned device."""
    from ..core.configurator import configurator_establish_keys_sequential

    if not args.keys_file:
        log_error("group_cli", "Keys file required for rekeying")
        return -1

    cfg = configurator_init(args.interface, args.keys_file)
    cfg.tx_delay_us = max(0, int(args.tx_delay_us or 0))
    try:
        def _key(idx):
            return cfg.comm_keys.spsec_keys[idx].key if cfg.comm_keys.spsec_keys[idx] else None

        def _salt(idx):
            return cfg.comm_keys.spsec_salt[idx].salt if cfg.comm_keys.spsec_salt[idx] else None

        if not _key(2) or not _salt(2):
            log_error("group_cli", "Integrator key/salt missing from keys file - "
                                   "they are needed to open the session that writes the Seed key")
            return -1
        if not _key(3) or not _salt(3):
            log_error("group_cli", "Seed key/salt missing from keys file")
            return -1

        ret = configurator_establish_keys_sequential(
            cfg, args.pid, SPSEC_KEY_SELECTOR_INTEGRATOR_KEY,
            integrator_key=_key(2), integrator_salt=_salt(2),
            integrator_key_id=args.integrator_key_id,
            seed_key=_key(3), seed_salt=_salt(3),
            seed_key_id=args.seed_key_id,
        )
        if ret != 0:
            print(f"  PID {args.pid}: seed rekey FAILED (code {ret})")
            if ret == -6:
                print("    No answer to the Integrator-key handshake. Check that "
                      "the device is provisioned and that the Integrator key in "
                      "the keys file is the one actually installed "
                      "(discover --key zero reports the installed key IDs).")
            return ret

        print(f"  PID {args.pid}: seed key rekeyed (key ID {args.seed_key_id})")
        return 0
    finally:
        configurator_destroy(cfg)


def cmd_code_update(args, group_manager: GroupManager) -> int:
    """Read code-update capabilities, and optionally upload an image (90h-92h)."""
    from ..core.code_update import (
        read_code_update_capabilities,
        read_public_auth_key,
        upload_code_update_file,
    )

    cfg = configurator_init(args.interface, args.keys_file)
    cfg.tx_delay_us = max(0, int(args.tx_delay_us or 0))

    try:
        from ..core.configurator import (
            configurator_start_session, configurator_terminate_session,
        )
        ret = configurator_start_session(
            cfg, args.pid, _KEY_SELECTOR_BY_NAME[args.key], 5.0)
        if ret < 0:
            log_error("group_cli", "Could not open a session with PID %d: %d", args.pid, ret)
            return ret

        try:
            caps = read_code_update_capabilities(cfg, args.pid)
            if caps is None:
                return -1
            print(f"\nPID {args.pid} code update capabilities (90h): 0x{caps.raw:08X}")
            print(f"  update capable      : {'yes' if caps.update_capable else 'no'}")
            print(f"  manufacturer bits   : 0x{caps.manufacturer:02X}")

            pub = read_public_auth_key(cfg, args.pid)
            print(f"  public auth key(91h): {pub.hex() if pub else 'unavailable'}")

            if not args.file:
                print("\nNo --file given; nothing uploaded.\n")
                return 0

            with open(args.file, "rb") as fh:
                image = fh.read()
            print(f"\nUploading {args.file} ({len(image)} bytes)...")
            ret = upload_code_update_file(cfg, args.pid, image)
            if ret != 0:
                print("Upload FAILED\n")
                return ret
            print("Image stored; it will be applied on the next power cycle.\n")
            return 0
        finally:
            configurator_terminate_session(cfg, args.pid)
    finally:
        configurator_destroy(cfg)


def cmd_history(args, group_manager: GroupManager) -> int:
    """List archived versions of the group configuration."""
    from ..core.config_history import list_versions, summarize, diff_versions

    versions = list_versions(args.config_file)
    if not versions:
        print("No configuration history yet "
              "(a snapshot is taken each time the configuration changes).")
        return 0

    if args.diff:
        lines = diff_versions(args.config_file, args.diff)
        if lines is None:
            log_error("group_cli", "No such version: %s", args.diff)
            return -1
        print(f"\nChanges since version {args.diff}:")
        print("-" * 80)
        for line in lines or ["  (no differences)"]:
            print(f"  {line}")
        print()
        return 0

    print(f"\nConfiguration history for {args.config_file} ({len(versions)} version(s)):")
    print("-" * 80)
    for vid, path in versions:
        info = summarize(path)
        groups = info.get("groups", {})
        members = sum(len(g["members"]) for g in groups.values()) if groups else 0
        print(f"  {vid}  groups={len(groups)} members={members} "
              f"devices={len(info.get('devices', []))}")
    print("\nRoll back with:  group_cli rollback <version>\n")
    return 0


def cmd_rollback(args, group_manager: GroupManager) -> int:
    """Restore the group configuration from an archived version."""
    from ..core.config_history import restore, diff_versions

    lines = diff_versions(args.config_file, args.version)
    if lines is None:
        log_error("group_cli", "No such version: %s", args.version)
        return -1

    print(f"\nRolling back to {args.version}. Changes that will be undone:")
    for line in lines or ["  (no differences)"]:
        print(f"  {line}")

    if args.dry_run:
        print("\n--dry-run given, nothing written.\n")
        return 0

    if not restore(args.config_file, args.version):
        return -1
    print("\nRolled back. The previous configuration was archived first, so "
          "this is itself reversible.\n")
    return 0


def cmd_discover(args, group_manager: GroupManager) -> int:
    """Discover devices on network"""
    from ..core.device_discovery import scan_network, discover_and_register
    
    cfg = configurator_init(args.interface, args.keys_file)
    cfg.tx_delay_us = max(0, int(args.tx_delay_us or 0))
    
    try:
        pid_range = range(args.start_pid, args.end_pid + 1)
        
        key_selector = _KEY_SELECTOR_BY_NAME[args.key]

        if args.register:
            discovered_dict = discover_and_register(
                cfg, group_manager, pid_range, args.timeout, key_selector=key_selector
            )
            discovered = list(discovered_dict.values())
        else:
            discovered = scan_network(cfg, pid_range, args.timeout, key_selector=key_selector)

        print(f"\nDiscovered {len(discovered)} device(s) using the {args.key} key:")
        print("-" * 80)
        for device in discovered:
            pid = device.participant_id
            core = device.core_version or "?"
            mapping = device.mapping_version or "?"
            status = f"0x{device.status:02X}" if device.status is not None else "?"
            response_time = f"{device.response_time_ms:.2f}ms" if device.response_time_ms > 0 else "?"
            print(f"  PID {pid}: core={core}, mapping={mapping}, status={status}, response={response_time}")
            # Identity and key IDs were collected all along but never printed.
            ident = device.device_identification or "?"
            serial = device.mcu_serial_number or "?"
            print(f"      identification={ident}, serial={serial}")

            def _key_id(value: Optional[int]) -> str:
                if value is None:
                    return "not set"
                return f"0x{value:08X}"

            print(
                f"      key IDs: provisioning={_key_id(device.provisioning_key_id)}, "
                f"integrator={_key_id(device.integrator_key_id)}, "
                f"seed={_key_id(device.seed_key_id)}"
            )
            if device.provisioning_key_id is None:
                print("      -> unprovisioned (no provisioning key installed)")
        print()

        return 0
    finally:
        configurator_destroy(cfg)


def cmd_export_config(args, group_manager: GroupManager) -> int:
    """Export configuration"""
    from ..core.config_import_export import export_configuration
    
    if export_configuration(group_manager, args.filepath, args.format):
        log_info("group_cli", "Configuration exported to %s", args.filepath)
        return 0
    else:
        return -1


def cmd_import_config(args, group_manager: GroupManager) -> int:
    """Import configuration"""
    from ..core.config_import_export import import_configuration
    
    if import_configuration(group_manager, args.filepath, args.format, args.merge):
        log_info("group_cli", "Configuration imported from %s", args.filepath)
        return 0
    else:
        return -1


def cmd_batch_bootstrap(args, group_manager: GroupManager) -> int:
    """Bootstrap multiple devices"""
    from ..core.batch_operations import batch_bootstrap_devices
    from ..core.keys import load_kv_hex_file
    
    cfg = configurator_init(args.interface, args.keys_file)
    cfg.tx_delay_us = max(0, int(args.tx_delay_us or 0))
    
    try:
        # Load keys
        integrator_key = load_kv_hex_file(args.keys_file, "integrator_key")
        integrator_salt = load_kv_hex_file(args.keys_file, "integrator_salt")
        seed_key = load_kv_hex_file(args.keys_file, "seed_key")
        seed_salt = load_kv_hex_file(args.keys_file, "seed_salt")
        
        if not all([integrator_key, integrator_salt, seed_key, seed_salt]):
            log_error("group_cli", "Missing required keys in keys file")
            return -1
        
        pids = [int(x) for x in args.pids.split(",")]
        result = batch_bootstrap_devices(
            cfg,
            pids,
            integrator_key,
            integrator_salt,
            1,  # integrator_key_id
            seed_key,
            seed_salt,
            2,  # seed_key_id
        )
        
        print(f"\nBatch bootstrap results:")
        print(f"  Total: {result.total}")
        print(f"  Successful: {result.successful}")
        print(f"  Failed: {result.failed}")
        if result.failed_items:
            print(f"  Failed PIDs: {result.failed_items}")
        print()
        
        return 0 if result.failed == 0 else -1
    finally:
        configurator_destroy(cfg)


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point"""
    argv = argv if argv is not None else sys.argv[1:]
    
    parser = argparse.ArgumentParser(description="SPsec Group Management CLI")
    parser.add_argument("-i", "--interface", default="vcan0", help="CAN interface")
    parser.add_argument("-k", "--keys-file", default="keys.txt", help="Keys file path")
    parser.add_argument("-c", "--config-file", default="groups_config.json", help="Group configuration file")
    parser.add_argument("-l", "--log-level", default="INFO", help="Log level")
    parser.add_argument("-d", "--tx-delay-us", type=int, default=0, help="TX delay in microseconds")
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Create group
    create_parser = subparsers.add_parser("create-group", help="Create a new group")
    create_parser.add_argument("group_id", type=int, help="Group ID")
    create_parser.add_argument("name", help="Group name")
    create_parser.add_argument("-d", "--description", help="Group description")
    create_parser.add_argument("-g", "--generate-keys", action="store_true", help="Generate keys for group")
    
    # Delete group
    delete_parser = subparsers.add_parser("delete-group", help="Delete a group")
    delete_parser.add_argument("group_id", type=int, help="Group ID")
    
    # List groups
    subparsers.add_parser("list-groups", help="List all groups")
    
    # Add device
    add_parser = subparsers.add_parser("add-device", help="Add device to group")
    add_parser.add_argument("group_id", type=int, help="Group ID")
    add_parser.add_argument("pid", type=int, help="Participant ID")
    
    # Remove device
    remove_parser = subparsers.add_parser("remove-device", help="Remove device from group")
    remove_parser.add_argument("group_id", type=int, help="Group ID")
    remove_parser.add_argument("pid", type=int, help="Participant ID")
    remove_parser.add_argument("-r", "--reset-keys", action="store_true", help="Reset device keys")
    remove_parser.add_argument("--rekey", action="store_true", help="Re-key surviving members to revoke the removed device's access")
    
    # Distribute keys
    dist_parser = subparsers.add_parser("distribute-keys", help="Distribute keys to group members")
    dist_parser.add_argument("group_id", type=int, help="Group ID")
    
    # Verify keys
    verify_parser = subparsers.add_parser("verify-keys", help="Verify keys for group members")
    verify_parser.add_argument("group_id", type=int, help="Group ID")
    
    # List members
    members_parser = subparsers.add_parser("list-members", help="List group members")
    members_parser.add_argument("group_id", type=int, help="Group ID")
    
    # Factory reset
    reset_parser = subparsers.add_parser("factory-reset", help="Factory reset a device")
    reset_parser.add_argument("pid", type=int, help="Participant ID")
    
    # Bootstrap
    bootstrap_parser = subparsers.add_parser("bootstrap", help="Bootstrap a device")
    bootstrap_parser.add_argument("pid", type=int, help="Participant ID")

    # Discover + provision in one automated pass
    prov_parser = subparsers.add_parser(
        "provision-discovered",
        help="Scan the bus and bootstrap every device that has no Provisioning Key yet",
    )
    prov_parser.add_argument("--start-pid", type=int, default=1, help="Start PID range")
    prov_parser.add_argument("--end-pid", type=int, default=127, help="End PID range")
    prov_parser.add_argument("--timeout", type=float, default=1.0, help="Timeout per device")
    prov_parser.add_argument("--integrator-key-id", type=int, default=1, help="Integrator Key ID to install")
    prov_parser.add_argument("--seed-key-id", type=int, default=2, help="Seed Key ID to install")
    prov_parser.add_argument(
        "--settle-delay", type=float, default=1.0,
        help="Seconds to wait between the scan and provisioning, so the bus "
             "and participants quiesce after the scan's session teardown",
    )
    prov_parser.add_argument(
        "--dry-run", action="store_true",
        help="List what would be provisioned, then stop before writing anything",
    )


    # Seed rekey on an already-provisioned device (Integrator-key session)
    rekey_parser = subparsers.add_parser(
        "rekey-seed",
        help="Install a new Seed key on a provisioned device",
    )
    rekey_parser.add_argument("pid", type=int, help="Target participant ID")
    rekey_parser.add_argument("--integrator-key-id", type=int, default=1,
                              help="Integrator Key ID currently installed")
    rekey_parser.add_argument("--seed-key-id", type=int, default=2,
                              help="Seed Key ID to install")

    # Authenticated code update transport (90h-92h)
    cu_parser = subparsers.add_parser(
        "code-update",
        help="Read code-update capabilities (90h/91h) and optionally upload an image (92h)")
    cu_parser.add_argument("pid", type=int, help="Target participant ID")
    cu_parser.add_argument("--file", help="Image to upload to 92h (omit to just report)")
    cu_parser.add_argument(
        "--key", choices=sorted(_KEY_SELECTOR_BY_NAME), default="integrator",
        help="Key selector for the session (default: integrator)")

    # Configuration history / rollback
    history_parser = subparsers.add_parser(
        "history", help="List archived versions of the group configuration")
    history_parser.add_argument(
        "--diff", metavar="VERSION",
        help="Show what changed between VERSION and the live configuration")

    rollback_parser = subparsers.add_parser(
        "rollback", help="Restore the group configuration from an archived version")
    rollback_parser.add_argument("version", help="Version ID from `history`")
    rollback_parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be undone, then stop")

    # Discover devices
    discover_parser = subparsers.add_parser("discover", help="Discover devices on network")
    discover_parser.add_argument("--start-pid", type=int, default=1, help="Start PID range")
    discover_parser.add_argument("--end-pid", type=int, default=127, help="End PID range")
    discover_parser.add_argument("--timeout", type=float, default=1.0, help="Timeout per device")
    discover_parser.add_argument("--register", action="store_true", help="Register discovered devices")
    discover_parser.add_argument(
        "--key",
        choices=sorted(_KEY_SELECTOR_BY_NAME),
        default="zero",
        help="Key selector to probe with (default: zero)",
    )
    
    # Export configuration
    export_parser = subparsers.add_parser("export-config", help="Export configuration")
    export_parser.add_argument("filepath", help="Export file path")
    export_parser.add_argument("--format", default="json", help="Export format (json)")
    
    # Import configuration
    import_parser = subparsers.add_parser("import-config", help="Import configuration")
    import_parser.add_argument("filepath", help="Import file path")
    import_parser.add_argument("--format", default="json", help="Import format (json)")
    import_parser.add_argument("--merge", action="store_true", help="Merge with existing configuration")
    
    # Batch bootstrap
    batch_bootstrap_parser = subparsers.add_parser("batch-bootstrap", help="Bootstrap multiple devices")
    batch_bootstrap_parser.add_argument("pids", help="Comma-separated list of PIDs")
    
    args = parser.parse_args(argv)
    
    if not args.command:
        parser.print_help()
        return 1
    
    configure_logging(args.log_level)
    
    group_manager = GroupManager(args.config_file)
    
    # Route to command handler
    if args.command == "create-group":
        return cmd_create_group(args, group_manager)
    elif args.command == "delete-group":
        return cmd_delete_group(args, group_manager)
    elif args.command == "list-groups":
        return cmd_list_groups(args, group_manager)
    elif args.command == "add-device":
        return cmd_add_device(args, group_manager)
    elif args.command == "remove-device":
        return cmd_remove_device(args, group_manager)
    elif args.command == "distribute-keys":
        return cmd_distribute_keys(args, group_manager)
    elif args.command == "verify-keys":
        return cmd_verify_keys(args, group_manager)
    elif args.command == "list-members":
        return cmd_list_members(args, group_manager)
    elif args.command == "factory-reset":
        return cmd_factory_reset(args, group_manager)
    elif args.command == "bootstrap":
        return cmd_bootstrap(args, group_manager)
    elif args.command == "provision-discovered":
        return cmd_provision_discovered(args, group_manager)
    elif args.command == "rekey-seed":
        return cmd_rekey_seed(args, group_manager)
    elif args.command == "code-update":
        return cmd_code_update(args, group_manager)
    elif args.command == "history":
        return cmd_history(args, group_manager)
    elif args.command == "rollback":
        return cmd_rollback(args, group_manager)
    elif args.command == "discover":
        return cmd_discover(args, group_manager)
    elif args.command == "export-config":
        return cmd_export_config(args, group_manager)
    elif args.command == "import-config":
        return cmd_import_config(args, group_manager)
    elif args.command == "batch-bootstrap":
        return cmd_batch_bootstrap(args, group_manager)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

