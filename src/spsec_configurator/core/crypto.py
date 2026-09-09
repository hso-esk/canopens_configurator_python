# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

from Crypto.Cipher import AES  # pycryptodome
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .logging_util import log_error, log_info, log_debug, log_array, log_warning, LOG_LEVEL_DEBUG

try:
    from .wolfssl_ascon import ascon_encrypt, ascon_decrypt
    HAS_ASCON = True
    log_info("crypto", "Using wolfSSL ASCON-128 implementation via wolfssl-py library")
except ImportError as e:
    HAS_ASCON = False
    log_warning("crypto", "wolfSSL ASCON wrapper not available, ASCON-128 support disabled: %s", str(e))


class CryptoAlgorithm(IntEnum):
    """AEAD algorithm enumeration matching C implementation"""
    CRYPTO_ALGO_AES_GCM = 0
    CRYPTO_ALGO_CHACHA20_POLY1305 = 1
    CRYPTO_ALGO_ASCON128 = 2


def crypto_algorithm_name(algorithm: CryptoAlgorithm) -> str:
    """Get human-readable name for algorithm"""
    if algorithm == CryptoAlgorithm.CRYPTO_ALGO_AES_GCM:
        return "AES-GCM"
    elif algorithm == CryptoAlgorithm.CRYPTO_ALGO_CHACHA20_POLY1305:
        return "ChaCha20-Poly1305"
    elif algorithm == CryptoAlgorithm.CRYPTO_ALGO_ASCON128:
        return "ASCON-128"
    else:
        return "Unknown"


def crypto_algorithm_from_string(value: Optional[str]) -> CryptoAlgorithm:
    """Parse algorithm from string (case-insensitive, accepts variations)"""
    if not value or not value.strip():
        return CryptoAlgorithm.CRYPTO_ALGO_AES_GCM  # Default
    
    # Normalize: remove non-alphanumeric, convert to uppercase
    normalized = ''.join(c.upper() if c.isalnum() else '' for c in value)
    
    if normalized == "AESGCM":
        return CryptoAlgorithm.CRYPTO_ALGO_AES_GCM
    elif normalized == "CHACHA20POLY1305":
        return CryptoAlgorithm.CRYPTO_ALGO_CHACHA20_POLY1305
    elif normalized == "ASCON128":
        return CryptoAlgorithm.CRYPTO_ALGO_ASCON128
    else:
        log_warning("crypto", "Unknown AEAD algorithm '%s', defaulting to AES-GCM", value)
        return CryptoAlgorithm.CRYPTO_ALGO_AES_GCM


@dataclass
class CryptoHandler:
    """SPsec crypto state. Nonces are always 16 bytes (SPsec302); shorter
    algorithm nonces (e.g. ChaCha20's 12) derive from that buffer."""
    key: bytes | None = None
    nonce: bytes | None = None
    mac_len: int = 8
    algorithm: CryptoAlgorithm = CryptoAlgorithm.CRYPTO_ALGO_AES_GCM


def crypto_handler_set_context(handler: CryptoHandler, key: bytes, nonce: bytes, nonce_len: int, tag_len: int, algorithm: Optional[CryptoAlgorithm] = None) -> int:
    if len(nonce) != nonce_len:
        return -1
    handler.key = bytes(key)
    handler.nonce = bytes(nonce)
    handler.mac_len = tag_len
    if algorithm is not None:
        handler.algorithm = algorithm
    log_debug("crypto", "%s key set successfully", crypto_algorithm_name(handler.algorithm))
    log_array(LOG_LEVEL_DEBUG, "crypto", "Nonce", handler.nonce, len(handler.nonce))
    log_debug("crypto", "Tag length set: %d", handler.mac_len)
    return 0


def _encrypt_aes_gcm(handler: CryptoHandler, plaintext: bytes, plaintext_len: int,
                     ciphertext_out: bytearray, tag_out: bytearray, assoc_data: bytes, assoc_len: int) -> int:
    """Encrypt using AES-GCM"""
    # AES-GCM uses the full 16-byte nonce (supports non-standard nonce lengths via GHASH IV derivation).
    nonce_16 = handler.nonce[:16]
    cipher = AES.new(handler.key, AES.MODE_GCM, nonce=nonce_16, mac_len=handler.mac_len)
    cipher.update(assoc_data[:assoc_len])
    pt = plaintext[:plaintext_len]
    ct, tag = cipher.encrypt_and_digest(pt)
    ciphertext_out[: len(ct)] = ct
    tag_out[: handler.mac_len] = tag
    return 0


def _encrypt_chachapoly(handler: CryptoHandler, plaintext: bytes, plaintext_len: int,
                        ciphertext_out: bytearray, tag_out: bytearray, assoc_data: bytes, assoc_len: int) -> int:
    """Encrypt using ChaCha20-Poly1305"""
    # ChaCha20-Poly1305 extracts least significant 12 bytes (LSB, bytes 0-11) to include timestamp/counter.
    # This matches C participant behavior and ensures timestamp/counter is included in the nonce.
    nonce_12 = handler.nonce[:12]
    chacha = ChaCha20Poly1305(handler.key)
    pt = plaintext[:plaintext_len]
    ad = assoc_data[:assoc_len] if assoc_len > 0 else None
    ct_with_tag = chacha.encrypt(nonce_12, pt, ad)
    # ChaCha20Poly1305 returns ciphertext + 16-byte tag
    ct = ct_with_tag[:-16]
    full_tag = ct_with_tag[-16:]
    ciphertext_out[: len(ct)] = ct
    # Truncate tag to requested length
    tag_out[: handler.mac_len] = full_tag[: handler.mac_len]
    return 0


def _encrypt_ascon(handler: CryptoHandler, plaintext: bytes, plaintext_len: int,
                   ciphertext_out: bytearray, tag_out: bytearray, assoc_data: bytes, assoc_len: int) -> int:
    """Encrypt using ASCON-128 via wolfSSL"""
    if not HAS_ASCON:
        log_error("crypto", "ASCON-128 not available (wolfSSL wrapper not available)")
        return -1
    # ASCON-128 uses all 16 bytes of nonce.
    nonce_16 = handler.nonce[:16]
    # ASCON-128 uses least significant 16 bytes (last 16 bytes) of the 32-byte key
    key_16 = handler.key[16:32]
    pt = plaintext[:plaintext_len]
    ad = assoc_data[:assoc_len] if assoc_len > 0 else b""
    try:
        # Use wolfSSL wrapper which calls the same C library as the participant
        ct, full_tag = ascon_encrypt(key_16, nonce_16, ad, pt)
        ciphertext_out[: len(ct)] = ct
        # Truncate tag to requested length (max 16 bytes)
        tag_len = min(handler.mac_len, 16)
        tag_out[: tag_len] = full_tag[: tag_len]
        return 0
    except Exception as e:
        log_error("crypto", "ASCON-128 encryption failed: %s", str(e))
        return -1


def crypto_handler_encrypt_with_assoc_data(handler: CryptoHandler, plaintext: bytes, plaintext_len: int,
                                           ciphertext_out: bytearray, tag_out: bytearray, assoc_data: bytes, assoc_len: int) -> int:
    if handler.key is None or handler.nonce is None:
        return -1
    log_array(LOG_LEVEL_DEBUG, "crypto", "Associated data", assoc_data, assoc_len)
    log_array(LOG_LEVEL_DEBUG, "crypto", "Plaintext", plaintext[:plaintext_len], plaintext_len)
    
    if handler.algorithm == CryptoAlgorithm.CRYPTO_ALGO_AES_GCM:
        ret = _encrypt_aes_gcm(handler, plaintext, plaintext_len, ciphertext_out, tag_out, assoc_data, assoc_len)
    elif handler.algorithm == CryptoAlgorithm.CRYPTO_ALGO_CHACHA20_POLY1305:
        ret = _encrypt_chachapoly(handler, plaintext, plaintext_len, ciphertext_out, tag_out, assoc_data, assoc_len)
    elif handler.algorithm == CryptoAlgorithm.CRYPTO_ALGO_ASCON128:
        ret = _encrypt_ascon(handler, plaintext, plaintext_len, ciphertext_out, tag_out, assoc_data, assoc_len)
    else:
        log_error("crypto", "Unknown algorithm: %d", handler.algorithm)
        return -1
    
    if ret == 0:
        log_array(LOG_LEVEL_DEBUG, "crypto", "Ciphertext", ciphertext_out[:plaintext_len], plaintext_len)
        log_array(LOG_LEVEL_DEBUG, "crypto", "Auth tag", tag_out[:handler.mac_len], handler.mac_len)
    return ret


def _decrypt_aes_gcm(handler: CryptoHandler, ciphertext: bytes, cipher_len: int, tag: bytes,
                     plaintext_out: bytearray, assoc_data: bytes, assoc_len: int) -> int:
    """Decrypt using AES-GCM"""
    try:
        # AES-GCM uses the full 16-byte nonce (supports non-standard nonce lengths via GHASH IV derivation).
        nonce_16 = handler.nonce[:16]
        cipher = AES.new(handler.key, AES.MODE_GCM, nonce=nonce_16, mac_len=len(tag))
        cipher.update(assoc_data[:assoc_len])
        pt = cipher.decrypt_and_verify(ciphertext[:cipher_len], tag)
        plaintext_out[: len(pt)] = pt
        return 0
    except Exception:
        return -5


def _decrypt_chachapoly(handler: CryptoHandler, ciphertext: bytes, cipher_len: int, tag: bytes,
                        plaintext_out: bytearray, assoc_data: bytes, assoc_len: int) -> int:
    """Decrypt using ChaCha20-Poly1305 with truncated tag verification (re-encrypt and compare)."""
    try:
        nonce_12 = handler.nonce[:12]
        chacha = ChaCha20Poly1305(handler.key)
        ct = ciphertext[:cipher_len]
        ad = assoc_data[:assoc_len] if assoc_len > 0 else None

        # Decrypt payload and verify truncated Poly1305 authentication tag
        pt = chacha.encrypt(nonce_12, ct, ad)[:cipher_len]

        ct_with_tag = chacha.encrypt(nonce_12, pt, ad)
        computed_tag_full = ct_with_tag[-16:]
        computed_tag_truncated = computed_tag_full[:len(tag)]

        if not hmac.compare_digest(computed_tag_truncated, tag):
            log_error("crypto", "ChaCha20-Poly1305 tag verification failed")
            return -5

        plaintext_out[:len(pt)] = pt
        return 0
    except Exception as e:
        log_error("crypto", "ChaCha20-Poly1305 decryption error: %s", str(e))
        return -5


def _decrypt_ascon(handler: CryptoHandler, ciphertext: bytes, cipher_len: int, tag: bytes,
                   plaintext_out: bytearray, assoc_data: bytes, assoc_len: int) -> int:
    """Decrypt using ASCON-128 via wolfSSL"""
    if not HAS_ASCON:
        log_error("crypto", "ASCON-128 not available (wolfSSL wrapper not available)")
        return -1
    try:
        # ASCON-128 uses all 16 bytes of nonce.
        nonce_16 = handler.nonce[:16]
        # ASCON-128 uses least significant 16 bytes (last 16 bytes) of the 32-byte key
        key_16 = handler.key[16:32]
        ct = ciphertext[:cipher_len]
        ad = assoc_data[:assoc_len] if assoc_len > 0 else b""
        # Use wolfSSL wrapper which calls the same C library as the participant
        # ascon_decrypt now handles variable-length tags (8 or 16 bytes)
        pt = ascon_decrypt(key_16, nonce_16, ad, ct, tag)
        plaintext_out[: len(pt)] = pt
        return 0
    except RuntimeError as e:
        if "tag mismatch" in str(e) or "DecryptFinal" in str(e):
            log_error("crypto", "ASCON-128 tag verification failed")
            return -5
        log_error("crypto", "ASCON-128 decryption failed: %s", str(e))
        return -5
    except Exception as e:
        log_error("crypto", "ASCON-128 decryption failed: %s", str(e))
        return -5


def crypto_handler_decrypt_with_assoc_data(handler: CryptoHandler, ciphertext: bytes, cipher_len: int, tag: bytes,
                                           plaintext_out: bytearray, assoc_data: bytes, assoc_len: int) -> int:
    if handler.key is None or handler.nonce is None:
        return -1
    try:
        log_debug("crypto", "=== CRYPTO DECRYPTION DEBUG START ===")
        log_array(LOG_LEVEL_DEBUG, "crypto", "Nonce for decryption", handler.nonce, len(handler.nonce))
        log_array(LOG_LEVEL_DEBUG, "crypto", "Input auth tag", tag, len(tag))
        log_array(LOG_LEVEL_DEBUG, "crypto", "Associated data", assoc_data, assoc_len)
        log_array(LOG_LEVEL_DEBUG, "crypto", "Ciphertext", ciphertext, cipher_len)
        
        if handler.algorithm == CryptoAlgorithm.CRYPTO_ALGO_AES_GCM:
            ret = _decrypt_aes_gcm(handler, ciphertext, cipher_len, tag, plaintext_out, assoc_data, assoc_len)
        elif handler.algorithm == CryptoAlgorithm.CRYPTO_ALGO_CHACHA20_POLY1305:
            ret = _decrypt_chachapoly(handler, ciphertext, cipher_len, tag, plaintext_out, assoc_data, assoc_len)
        elif handler.algorithm == CryptoAlgorithm.CRYPTO_ALGO_ASCON128:
            ret = _decrypt_ascon(handler, ciphertext, cipher_len, tag, plaintext_out, assoc_data, assoc_len)
        else:
            log_error("crypto", "Unknown algorithm: %d", handler.algorithm)
            return -1
        
        if ret != 0:
            log_error("crypto", "Authentication verification FAILED!")
            return ret
        
        # Compute and log a verification tag (by re-encrypting plaintext) to mirror C logs
        try:
            pt = bytes(plaintext_out[:len(plaintext_out)])
            if handler.algorithm == CryptoAlgorithm.CRYPTO_ALGO_AES_GCM:
                # Use full 16-byte nonce for consistency
                nonce_16 = handler.nonce[:16]
                cipher2 = AES.new(handler.key, AES.MODE_GCM, nonce=nonce_16, mac_len=len(tag))
                cipher2.update(assoc_data[:assoc_len])
                _ct2, tag2 = cipher2.encrypt_and_digest(pt)
                log_array(LOG_LEVEL_DEBUG, "crypto", "Computed auth tag", tag2, len(tag2))
            log_debug("crypto", "Authentication verification PASSED")
            log_debug("crypto", "=== CRYPTO DECRYPTION DEBUG END (SUCCESS) ===")
        except Exception:
            pass
        return 0
    except Exception as e:
        log_error("crypto", "Decryption error: %s", str(e))
        return -5


def hkdf_sha256(ikm: bytes, salt: bytes, length: int) -> bytes:
    hk = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=None,
    )
    out = hk.derive(ikm)
    log_array(LOG_LEVEL_DEBUG, "crypto", "HKDF salt", salt, len(salt))
    log_array(LOG_LEVEL_DEBUG, "crypto", "HKDF output key", out, len(out))
    return out


def compute_tag_only(key: bytes, nonce: bytes, assoc_data: bytes, mac_len: int, algorithm: CryptoAlgorithm = CryptoAlgorithm.CRYPTO_ALGO_AES_GCM) -> bytes:
    """Compute authentication tag only (no plaintext encryption)"""
    if algorithm == CryptoAlgorithm.CRYPTO_ALGO_AES_GCM:
        # Use full nonce length
        # mbedTLS/PyCryptodome will handle non-96-bit nonces by deriving IV via GHASH
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
        cipher.update(assoc_data)
        _, tag = cipher.encrypt_and_digest(b"")
        log_info("crypto", "AES-GCM digest with length: %d retrieved successfully", mac_len)
        return tag
    elif algorithm == CryptoAlgorithm.CRYPTO_ALGO_CHACHA20_POLY1305:
        # ChaCha20-Poly1305 extracts least significant 12 bytes (includes timestamp/counter) from the 16-byte buffer.
        nonce_12 = nonce[:12]
        chacha = ChaCha20Poly1305(key)
        # Encrypt empty plaintext to get tag
        ct_with_tag = chacha.encrypt(nonce_12, b"", assoc_data if assoc_data else None)
        full_tag = ct_with_tag[-16:]  # Last 16 bytes are the tag
        tag = full_tag[:mac_len]  # Truncate to requested length
        log_info("crypto", "ChaCha20-Poly1305 digest with length: %d retrieved successfully", mac_len)
        return tag
    elif algorithm == CryptoAlgorithm.CRYPTO_ALGO_ASCON128:
        if not HAS_ASCON:
            log_error("crypto", "ASCON-128 not available (wolfSSL wrapper not available)")
            raise RuntimeError("ASCON-128 not available")
        # ASCON-128 uses all 16 bytes of nonce.
        nonce_16 = nonce[:16]
        # ASCON-128 uses least significant 16 bytes (last 16 bytes) of the 32-byte key
        key_16 = key[16:32]
        # Use wolfSSL wrapper for tag computation
        try:
            _, full_tag = ascon_encrypt(key_16, nonce_16, assoc_data if assoc_data else b"", b"")
            tag = full_tag[:min(mac_len, 16)]  # Truncate to requested length (max 16)
        except Exception as e:
            log_error("crypto", "ASCON-128 tag computation failed: %s", str(e))
            raise
        log_info("crypto", "ASCON-128 digest with length: %d retrieved successfully", mac_len)
        return tag
    else:
        log_error("crypto", "Unknown algorithm for compute_tag_only: %d", algorithm)
        raise ValueError(f"Unknown algorithm: {algorithm}")


