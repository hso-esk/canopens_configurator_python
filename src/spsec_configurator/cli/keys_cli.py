#!/usr/bin/env python3

# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""CLI for managing the encrypted key store (see core/secure_keys.py)."""

from __future__ import annotations

import sys
import argparse
import getpass
import secrets
from pathlib import Path
from typing import Optional


def cmd_create(args) -> int:
    """Create a new encrypted key store"""
    from ..core.secure_keys import SecureKeyStore
    
    path = Path(args.file)
    if path.exists() and not args.force:
        print(f"Error: File already exists: {path}")
        print("Use --force to overwrite")
        return 1
    
    # Get password
    password = getpass.getpass("Create password: ")
    password2 = getpass.getpass("Confirm password: ")
    
    if password != password2:
        print("Error: Passwords don't match")
        return 1
    
    if len(password) < 8:
        print("Error: Password must be at least 8 characters")
        return 1
    
    store = SecureKeyStore(str(path))
    store.create(password)
    
    if args.generate:
        # Generate standard keys
        print("Generating cryptographic keys...")
        
        store.set_key("provisioning_key", secrets.token_bytes(32),
                     description="Device provisioning key", key_type="provisioning")
        store.set_key("provisioning_salt", secrets.token_bytes(16),
                     description="Device provisioning salt", key_type="provisioning")
        store.set_key("integrator_key", secrets.token_bytes(32),
                     description="Integrator key", key_type="integrator")
        store.set_key("integrator_salt", secrets.token_bytes(16),
                     description="Integrator salt", key_type="integrator")
        store.set_key("seed_key", secrets.token_bytes(32),
                     description="Seed key", key_type="seed")
        store.set_key("seed_salt", secrets.token_bytes(16),
                     description="Seed salt", key_type="seed")
    
    store.save()
    print(f"Created encrypted key store: {path}")
    
    if args.generate:
        print(f"Generated {len(store.list_keys())} keys")
    
    return 0


def cmd_import(args) -> int:
    """Import from plain text file"""
    from ..core.secure_keys import SecureKeyStore
    
    source = Path(args.source)
    dest = Path(args.dest)
    
    if not source.exists():
        print(f"Error: Source file not found: {source}")
        return 1
    
    if dest.exists() and not args.force:
        print(f"Error: Destination file exists: {dest}")
        print("Use --force to overwrite")
        return 1
    
    # Get password
    password = getpass.getpass("Create password for encrypted store: ")
    password2 = getpass.getpass("Confirm password: ")
    
    if password != password2:
        print("Error: Passwords don't match")
        return 1
    
    store = SecureKeyStore(str(dest))
    if store.import_from_plain_text(str(source), password):
        print(f"Imported {len(store.list_keys())} keys from {source}")
        print(f"Created encrypted store: {dest}")
        
        if args.delete_source:
            source.unlink()
            print(f"Deleted plain text file: {source}")
        
        return 0
    
    return 1


def cmd_export(args) -> int:
    """Export to plain text file"""
    from ..core.secure_keys import SecureKeyStore
    
    source = Path(args.source)
    dest = Path(args.dest)
    
    if not source.exists():
        print(f"Error: Key store not found: {source}")
        return 1
    
    if dest.exists() and not args.force:
        print(f"Error: Destination file exists: {dest}")
        print("Use --force to overwrite")
        return 1
    
    # Warn about security
    print("WARNING: Exporting to plain text file!")
    print("The exported file will contain unencrypted keys.")
    confirm = input("Continue? [y/N] ")
    if confirm.lower() != "y":
        print("Aborted")
        return 1
    
    password = getpass.getpass("Enter key store password: ")
    
    store = SecureKeyStore(str(source))
    if not store.load(password):
        print("Error: Failed to load key store")
        return 1
    
    if store.export_to_plain_text(str(dest)):
        print(f"Exported {len(store.list_keys())} keys to {dest}")
        return 0
    
    return 1


def cmd_list(args) -> int:
    """List keys in store"""
    from ..core.secure_keys import SecureKeyStore
    
    path = Path(args.file)
    if not path.exists():
        print(f"Error: Key store not found: {path}")
        return 1
    
    password = getpass.getpass("Enter password: ")
    
    store = SecureKeyStore(str(path))
    if not store.load(password):
        print("Error: Failed to load key store (wrong password?)")
        return 1
    
    print(f"\nKey Store: {path}")
    print(f"Active Profile: {store.active_profile}")
    print(f"Profiles: {', '.join(store.list_profiles())}")
    print()
    
    keys = store.list_keys()
    if not keys:
        print("No keys in store")
        return 0
    
    print(f"Keys ({len(keys)}):")
    print("-" * 60)
    
    for key_name in sorted(keys):
        info = store.get_key_info(key_name)
        if info:
            key_type = info.get("key_type", "raw")
            size = info.get("size", 0)
            desc = info.get("description", "")
            print(f"  {key_name}")
            print(f"    Type: {key_type}, Size: {size} bytes")
            if desc:
                print(f"    Description: {desc}")
    
    return 0


def cmd_show(args) -> int:
    """Show a specific key value"""
    from ..core.secure_keys import SecureKeyStore
    
    path = Path(args.file)
    if not path.exists():
        print(f"Error: Key store not found: {path}")
        return 1
    
    password = getpass.getpass("Enter password: ")
    
    store = SecureKeyStore(str(path))
    if not store.load(password):
        print("Error: Failed to load key store")
        return 1
    
    value = store.get_key(args.key)
    if value is None:
        print(f"Error: Key not found: {args.key}")
        return 1
    
    if args.format == "hex":
        print(value.hex())
    elif args.format == "base64":
        import base64
        print(base64.b64encode(value).decode())
    else:
        print(value.hex())
    
    return 0


def cmd_set(args) -> int:
    """Set a key value"""
    from ..core.secure_keys import SecureKeyStore
    
    path = Path(args.file)
    if not path.exists():
        print(f"Error: Key store not found: {path}")
        return 1
    
    password = getpass.getpass("Enter password: ")
    
    store = SecureKeyStore(str(path))
    if not store.load(password):
        print("Error: Failed to load key store")
        return 1
    
    # Get value
    if args.value:
        try:
            value = bytes.fromhex(args.value.replace(" ", ""))
        except ValueError:
            print("Error: Invalid hex value")
            return 1
    elif args.generate:
        value = secrets.token_bytes(args.size)
        print(f"Generated {args.size}-byte random value")
    else:
        hex_input = input("Enter value (hex): ").strip()
        try:
            value = bytes.fromhex(hex_input.replace(" ", ""))
        except ValueError:
            print("Error: Invalid hex value")
            return 1
    
    store.set_key(args.key, value, 
                  description=args.description or "",
                  key_type=args.type or "raw")
    store.save()
    
    print(f"Set key: {args.key} ({len(value)} bytes)")
    return 0


def cmd_delete(args) -> int:
    """Delete a key"""
    from ..core.secure_keys import SecureKeyStore
    
    path = Path(args.file)
    if not path.exists():
        print(f"Error: Key store not found: {path}")
        return 1
    
    password = getpass.getpass("Enter password: ")
    
    store = SecureKeyStore(str(path))
    if not store.load(password):
        print("Error: Failed to load key store")
        return 1
    
    if store.delete_key(args.key):
        store.save()
        print(f"Deleted key: {args.key}")
        return 0
    else:
        print(f"Error: Key not found: {args.key}")
        return 1


def cmd_change_password(args) -> int:
    """Change the master password"""
    from ..core.secure_keys import SecureKeyStore
    
    path = Path(args.file)
    if not path.exists():
        print(f"Error: Key store not found: {path}")
        return 1
    
    old_password = getpass.getpass("Enter current password: ")
    
    store = SecureKeyStore(str(path))
    if not store.load(old_password):
        print("Error: Failed to load key store")
        return 1
    
    new_password = getpass.getpass("Enter new password: ")
    new_password2 = getpass.getpass("Confirm new password: ")
    
    if new_password != new_password2:
        print("Error: Passwords don't match")
        return 1
    
    if len(new_password) < 8:
        print("Error: Password must be at least 8 characters")
        return 1
    
    if store.change_password(old_password, new_password):
        print("Password changed successfully")
        return 0
    
    return 1


def main(argv: "list[str] | None" = None) -> int:
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Secure Key Store Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples: %(prog)s create keys.enc --generate | import keys.txt keys.enc""",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # create
    create_parser = subparsers.add_parser("create", help="Create new key store")
    create_parser.add_argument("file", help="Output file path")
    create_parser.add_argument("-g", "--generate", action="store_true",
                               help="Generate standard keys")
    create_parser.add_argument("-f", "--force", action="store_true",
                               help="Overwrite existing file")
    
    # import
    import_parser = subparsers.add_parser("import", help="Import from plain text")
    import_parser.add_argument("source", help="Source plain text file")
    import_parser.add_argument("dest", help="Destination encrypted file")
    import_parser.add_argument("-f", "--force", action="store_true",
                               help="Overwrite existing file")
    import_parser.add_argument("--delete-source", action="store_true",
                               help="Delete source file after import")
    
    # export
    export_parser = subparsers.add_parser("export", help="Export to plain text")
    export_parser.add_argument("source", help="Source encrypted file")
    export_parser.add_argument("dest", help="Destination plain text file")
    export_parser.add_argument("-f", "--force", action="store_true",
                               help="Overwrite existing file")
    
    # list
    list_parser = subparsers.add_parser("list", help="List keys in store")
    list_parser.add_argument("file", help="Key store file")
    
    # show
    show_parser = subparsers.add_parser("show", help="Show a key value")
    show_parser.add_argument("file", help="Key store file")
    show_parser.add_argument("key", help="Key name")
    show_parser.add_argument("--format", choices=["hex", "base64"], default="hex",
                            help="Output format")
    
    # set
    set_parser = subparsers.add_parser("set", help="Set a key value")
    set_parser.add_argument("file", help="Key store file")
    set_parser.add_argument("key", help="Key name")
    set_parser.add_argument("-v", "--value", help="Hex value")
    set_parser.add_argument("-g", "--generate", action="store_true",
                           help="Generate random value")
    set_parser.add_argument("-s", "--size", type=int, default=32,
                           help="Size for generated value")
    set_parser.add_argument("-d", "--description", help="Key description")
    set_parser.add_argument("-t", "--type", 
                           choices=["raw", "provisioning", "integrator", "seed"],
                           help="Key type")
    
    # delete
    delete_parser = subparsers.add_parser("delete", help="Delete a key")
    delete_parser.add_argument("file", help="Key store file")
    delete_parser.add_argument("key", help="Key name")
    
    # change-password
    passwd_parser = subparsers.add_parser("change-password", 
                                          help="Change master password")
    passwd_parser.add_argument("file", help="Key store file")
    
    args = parser.parse_args(argv)
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Route to command handler
    handlers = {
        "create": cmd_create,
        "import": cmd_import,
        "export": cmd_export,
        "list": cmd_list,
        "show": cmd_show,
        "set": cmd_set,
        "delete": cmd_delete,
        "change-password": cmd_change_password,
    }
    
    handler = handlers.get(args.command)
    if handler:
        return handler(args)
    
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())

