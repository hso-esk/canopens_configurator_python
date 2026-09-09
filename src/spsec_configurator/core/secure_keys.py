# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Password-encrypted key storage (AES-256-GCM + PBKDF2), with profiles and
plain-text import for migrating old key files."""

from __future__ import annotations

import json
import os
import base64
import hashlib
import getpass
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from .logging_util import log_info, log_error, log_debug, log_warning


# Constants
SECURE_KEY_VERSION = 1
PBKDF2_ITERATIONS = 600000  # OWASP 2023 recommendation
SALT_SIZE = 32
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256


@dataclass
class KeyEntry:
    """A single key entry with metadata"""
    name: str
    value: bytes
    description: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    key_type: str = "raw"  # "raw", "provisioning", "integrator", "seed"
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "value": base64.b64encode(self.value).decode("ascii"),
            "description": self.description,
            "created_at": self.created_at,
            "key_type": self.key_type,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "KeyEntry":
        return cls(
            name=data["name"],
            value=base64.b64decode(data["value"]),
            description=data.get("description", ""),
            created_at=data.get("created_at", ""),
            key_type=data.get("key_type", "raw"),
        )


@dataclass  
class KeyProfile:
    """A profile containing multiple keys (e.g., development, production)"""
    name: str
    description: str = ""
    keys: Dict[str, KeyEntry] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "keys": {k: v.to_dict() for k, v in self.keys.items()},
            "created_at": self.created_at,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "KeyProfile":
        profile = cls(
            name=data["name"],
            description=data.get("description", ""),
            created_at=data.get("created_at", ""),
        )
        for key_name, key_data in data.get("keys", {}).items():
            profile.keys[key_name] = KeyEntry.from_dict(key_data)
        return profile


class SecureKeyStore:
    """Encrypted key store. On-disk: magic(8) + version(1) + salt(32) +
    nonce(12) + AES-256-GCM(JSON payload, tag included)."""
    
    MAGIC = b"SPSECKEY"
    
    def __init__(self, path: str = "keys.enc"):
        self.path = Path(path)
        self.profiles: Dict[str, KeyProfile] = {}
        self.active_profile: str = "default"
        self.metadata: Dict[str, Any] = {
            "version": SECURE_KEY_VERSION,
            "created_at": None,
            "modified_at": None,
        }
        self._encryption_key: Optional[bytes] = None
        self._salt: Optional[bytes] = None
        self._is_loaded = False
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))
    
    def _encrypt(self, data: bytes) -> tuple:
        """Encrypt data using AES-256-GCM. Returns (nonce, ciphertext)"""
        if self._encryption_key is None:
            raise RuntimeError("No encryption key set")
        
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(self._encryption_key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce, ciphertext
    
    def _decrypt(self, nonce: bytes, ciphertext: bytes) -> bytes:
        """Decrypt data using AES-256-GCM"""
        if self._encryption_key is None:
            raise RuntimeError("No encryption key set")
        
        aesgcm = AESGCM(self._encryption_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def create(self, password: str, profile_name: str = "default") -> None:
        """Create a new encrypted key store"""
        self._salt = os.urandom(SALT_SIZE)
        self._encryption_key = self._derive_key(password, self._salt)
        
        # Create default profile
        self.profiles = {
            profile_name: KeyProfile(
                name=profile_name,
                description="Default key profile",
            )
        }
        self.active_profile = profile_name
        self.metadata["created_at"] = datetime.now(timezone.utc).isoformat()
        self.metadata["modified_at"] = self.metadata["created_at"]
        self._is_loaded = True
        
        log_info("secure_keys", "Created new secure key store: %s", str(self.path))
    
    def load(self, password: str) -> bool:
        """Load and decrypt key store from file"""
        if not self.path.exists():
            log_error("secure_keys", "Key store file not found: %s", str(self.path))
            return False
        
        try:
            with open(self.path, "rb") as f:
                # Read and verify magic
                magic = f.read(8)
                if magic != self.MAGIC:
                    log_error("secure_keys", "Invalid key store file format")
                    return False
                
                # Read version
                version = f.read(1)[0]
                if version > SECURE_KEY_VERSION:
                    log_error("secure_keys", "Unsupported key store version: %d", version)
                    return False
                
                # Read salt and nonce
                self._salt = f.read(SALT_SIZE)
                nonce = f.read(NONCE_SIZE)
                
                # Read encrypted data
                ciphertext = f.read()
            
            # Derive key and decrypt
            self._encryption_key = self._derive_key(password, self._salt)
            
            try:
                plaintext = self._decrypt(nonce, ciphertext)
            except Exception:
                log_error("secure_keys", "Failed to decrypt key store (wrong password?)")
                self._encryption_key = None
                return False
            
            # Parse JSON
            data = json.loads(plaintext.decode("utf-8"))
            
            self.metadata = data.get("metadata", self.metadata)
            self.active_profile = data.get("active_profile", "default")
            
            self.profiles = {}
            for profile_data in data.get("profiles", []):
                profile = KeyProfile.from_dict(profile_data)
                self.profiles[profile.name] = profile
            
            self._is_loaded = True
            log_info("secure_keys", "Loaded secure key store: %s (%d profiles)", 
                    str(self.path), len(self.profiles))
            return True
            
        except Exception as e:
            log_error("secure_keys", "Failed to load key store: %s", str(e))
            return False
    
    def save(self) -> bool:
        """Save encrypted key store to file"""
        if not self._is_loaded:
            log_error("secure_keys", "No key store loaded")
            return False
        
        if self._encryption_key is None or self._salt is None:
            log_error("secure_keys", "No encryption key set")
            return False
        
        try:
            # Update modification time
            self.metadata["modified_at"] = datetime.now(timezone.utc).isoformat()
            
            # Build JSON data
            data = {
                "metadata": self.metadata,
                "active_profile": self.active_profile,
                "profiles": [p.to_dict() for p in self.profiles.values()],
            }
            
            plaintext = json.dumps(data, indent=2).encode("utf-8")
            
            # Encrypt
            nonce, ciphertext = self._encrypt(plaintext)
            
            # Write to file
            temp_path = self.path.with_suffix(".tmp")
            fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with open(fd, "wb") as f:
                f.write(self.MAGIC)
                f.write(bytes([SECURE_KEY_VERSION]))
                f.write(self._salt)
                f.write(nonce)
                f.write(ciphertext)
            os.chmod(temp_path, 0o600)
            # Atomic rename
            temp_path.replace(self.path)
            
            log_info("secure_keys", "Saved secure key store: %s", str(self.path))
            return True
            
        except Exception as e:
            log_error("secure_keys", "Failed to save key store: %s", str(e))
            return False
    
    def _get_active_profile(self) -> KeyProfile:
        """Get active profile, creating if necessary"""
        if self.active_profile not in self.profiles:
            self.profiles[self.active_profile] = KeyProfile(name=self.active_profile)
        return self.profiles[self.active_profile]
    
    # Key operations
    
    def set_key(self, name: str, value: bytes, description: str = "", 
                key_type: str = "raw") -> None:
        """Set a key in the active profile"""
        profile = self._get_active_profile()
        profile.keys[name] = KeyEntry(
            name=name,
            value=value,
            description=description,
            key_type=key_type,
        )
        log_debug("secure_keys", "Set key: %s (%d bytes)", name, len(value))
    
    def get_key(self, name: str) -> Optional[bytes]:
        """Get a key from the active profile"""
        profile = self._get_active_profile()
        entry = profile.keys.get(name)
        return entry.value if entry else None
    
    def delete_key(self, name: str) -> bool:
        """Delete a key from the active profile"""
        profile = self._get_active_profile()
        if name in profile.keys:
            del profile.keys[name]
            log_debug("secure_keys", "Deleted key: %s", name)
            return True
        return False
    
    def list_keys(self) -> List[str]:
        """List all keys in active profile"""
        profile = self._get_active_profile()
        return list(profile.keys.keys())
    
    def get_key_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get key metadata (without the actual key value)"""
        profile = self._get_active_profile()
        entry = profile.keys.get(name)
        if entry:
            return {
                "name": entry.name,
                "size": len(entry.value),
                "description": entry.description,
                "created_at": entry.created_at,
                "key_type": entry.key_type,
            }
        return None
    
    # Profile operations
    
    def create_profile(self, name: str, description: str = "") -> None:
        """Create a new key profile"""
        if name in self.profiles:
            raise ValueError(f"Profile '{name}' already exists")
        self.profiles[name] = KeyProfile(name=name, description=description)
        log_info("secure_keys", "Created profile: %s", name)
    
    def delete_profile(self, name: str) -> bool:
        """Delete a key profile"""
        if name == self.active_profile:
            log_error("secure_keys", "Cannot delete active profile")
            return False
        if name in self.profiles:
            del self.profiles[name]
            log_info("secure_keys", "Deleted profile: %s", name)
            return True
        return False
    
    def switch_profile(self, name: str) -> bool:
        """Switch to a different profile"""
        if name not in self.profiles:
            log_error("secure_keys", "Profile not found: %s", name)
            return False
        self.active_profile = name
        log_info("secure_keys", "Switched to profile: %s", name)
        return True
    
    def list_profiles(self) -> List[str]:
        """List all profiles"""
        return list(self.profiles.keys())
    
    # Import/Export
    
    def import_from_plain_text(self, plain_file: str, password: str) -> bool:
        """Import keys from plain text file and create encrypted store"""
        try:
            keys = {}
            path = Path(plain_file)
            
            if not path.exists():
                log_error("secure_keys", "Plain text file not found: %s", plain_file)
                return False
            
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    
                    name, value = line.split(":", 1)
                    name = name.strip()
                    value = value.strip()
                    
                    # Parse hex value
                    try:
                        key_bytes = bytes.fromhex(value.replace(" ", ""))
                        keys[name] = key_bytes
                    except ValueError as e:
                        log_warning("secure_keys", "Skipping invalid key %s: %s", name, e)
            
            if not keys:
                log_error("secure_keys", "No valid keys found in %s", plain_file)
                return False
            
            # Create store with imported keys
            self.create(password)
            
            for name, value in keys.items():
                # Determine key type from name
                if "provisioning" in name.lower():
                    key_type = "provisioning"
                elif "integrator" in name.lower():
                    key_type = "integrator"
                elif "seed" in name.lower():
                    key_type = "seed"
                else:
                    key_type = "raw"
                
                self.set_key(name, value, key_type=key_type)
            
            self.save()
            log_info("secure_keys", "Imported %d keys from %s", len(keys), plain_file)
            return True
            
        except Exception as e:
            log_error("secure_keys", "Failed to import from plain text: %s", str(e))
            return False
    
    def export_to_plain_text(self, plain_file: str) -> bool:
        """Export keys to plain text file (for compatibility)"""
        log_debug("secure_keys", "export_to_plain_text called, target: %s", plain_file)
        log_debug("secure_keys", "Store loaded: %s, Active profile: %s", 
                 self._is_loaded, self.active_profile)
        
        if not self._is_loaded:
            log_error("secure_keys", "No key store loaded")
            return False
        
        try:
            profile = self._get_active_profile()
            log_debug("secure_keys", "Exporting %d keys from profile '%s'", 
                     len(profile.keys), profile.name)
            
            with open(plain_file, "w") as f:
                for entry in profile.keys.values():
                    hex_value = entry.value.hex()
                    f.write(f"{entry.name}:{hex_value}\n")

            # Set file permissions to owner read/write only (0o600)
            os.chmod(plain_file, 0o600)

            for entry in profile.keys.values():
                log_debug("secure_keys", "Exported key: %s (%d bytes)",
                         entry.name, len(entry.value))
            
            log_info("secure_keys", "Exported %d keys to temp file: %s", 
                    len(profile.keys), plain_file)
            return True
            
        except Exception as e:
            log_error("secure_keys", "Failed to export to plain text: %s", str(e))
            import traceback
            log_debug("secure_keys", "Traceback: %s", traceback.format_exc())
            return False
    
    def change_password(self, old_password: str, new_password: str) -> bool:
        """Change the master password"""
        if not self._is_loaded:
            log_error("secure_keys", "No key store loaded")
            return False
        
        # Verify old password by trying to decrypt
        test_key = self._derive_key(old_password, self._salt)
        if test_key != self._encryption_key:
            log_error("secure_keys", "Incorrect old password")
            return False
        
        # Generate new salt and key
        self._salt = os.urandom(SALT_SIZE)
        self._encryption_key = self._derive_key(new_password, self._salt)
        
        # Save with new encryption
        if self.save():
            log_info("secure_keys", "Password changed successfully")
            return True
        return False
    
    # Convenience method for compatibility with existing code
    
    def get_key_hex(self, name: str) -> Optional[str]:
        """Get a key as hex string"""
        value = self.get_key(name)
        return value.hex() if value else None


def load_keys_interactive(path: str = "keys.enc") -> Optional[SecureKeyStore]:
    """Interactively load a key store (prompts for password); falls back
    to plain text if no encrypted store is found."""
    store = SecureKeyStore(path)
    enc_path = Path(path)
    
    # Check for encrypted store
    if enc_path.exists():
        password = getpass.getpass("Enter key store password: ")
        if store.load(password):
            return store
        else:
            print("Failed to load key store")
            return None
    
    # Check for plain text fallback
    plain_path = enc_path.with_suffix(".txt")
    if plain_path.exists():
        print(f"Encrypted store not found. Import from {plain_path}? [y/N] ", end="")
        if input().strip().lower() == "y":
            password = getpass.getpass("Create password for encrypted store: ")
            password2 = getpass.getpass("Confirm password: ")
            if password != password2:
                print("Passwords don't match")
                return None
            
            if store.import_from_plain_text(str(plain_path), password):
                return store
    
    return None


def create_keys_interactive(path: str = "keys.enc") -> Optional[SecureKeyStore]:
    """Interactively create a new key store with generated keys"""
    import secrets
    
    password = getpass.getpass("Create password for new key store: ")
    password2 = getpass.getpass("Confirm password: ")
    
    if password != password2:
        print("Passwords don't match")
        return None
    
    store = SecureKeyStore(path)
    store.create(password)
    
    # Generate standard keys
    print("Generating cryptographic keys...")
    
    store.set_key(
        "provisioning_key",
        secrets.token_bytes(32),
        description="Device provisioning key",
        key_type="provisioning",
    )
    store.set_key(
        "provisioning_salt",
        secrets.token_bytes(16),
        description="Device provisioning salt",
        key_type="provisioning",
    )
    store.set_key(
        "integrator_key",
        secrets.token_bytes(32),
        description="Integrator key",
        key_type="integrator",
    )
    store.set_key(
        "integrator_salt",
        secrets.token_bytes(16),
        description="Integrator salt",
        key_type="integrator",
    )
    store.set_key(
        "seed_key",
        secrets.token_bytes(32),
        description="Seed key",
        key_type="seed",
    )
    store.set_key(
        "seed_salt",
        secrets.token_bytes(16),
        description="Seed salt",
        key_type="seed",
    )
    
    store.save()
    print(f"Created encrypted key store: {path}")
    
    return store


# Compatibility adapter for existing code
class KeyStoreAdapter:
    """Adapter: same interface as load_kv_hex_file, backed by SecureKeyStore."""
    
    _instance: Optional["KeyStoreAdapter"] = None
    _store: Optional[SecureKeyStore] = None
    _plain_text_path: Optional[str] = None
    
    @classmethod
    def initialize(cls, store: SecureKeyStore) -> None:
        """Initialize adapter with a loaded key store"""
        cls._store = store
        cls._plain_text_path = None
    
    @classmethod
    def initialize_plain_text(cls, path: str) -> None:
        """Initialize adapter with plain text file (backward compatibility)"""
        cls._store = None
        cls._plain_text_path = path
    
    @classmethod
    def get_key(cls, name: str) -> Optional[bytes]:
        """Get a key by name"""
        if cls._store:
            return cls._store.get_key(name)
        elif cls._plain_text_path:
            from .keys import load_kv_hex_file
            return load_kv_hex_file(cls._plain_text_path, name)
        return None
    
    @classmethod
    def is_secure(cls) -> bool:
        """Check if using secure storage"""
        return cls._store is not None


def load_key_compat(path: str, key: str) -> Optional[bytes]:
    """Load a key: tries secure store (.enc) first, falls back to plain text (.txt)."""
    # Check for secure store
    enc_path = Path(path)
    if enc_path.suffix == ".enc" and enc_path.exists():
        if KeyStoreAdapter._store is not None:
            return KeyStoreAdapter.get_key(key)
        else:
            log_warning("secure_keys", "Secure store exists but not initialized")
    
    # Fall back to plain text
    if enc_path.suffix == ".enc":
        plain_path = enc_path.with_suffix(".txt")
    else:
        plain_path = enc_path
    
    if plain_path.exists():
        from .keys import load_kv_hex_file
        return load_kv_hex_file(str(plain_path), key)
    
    return None

