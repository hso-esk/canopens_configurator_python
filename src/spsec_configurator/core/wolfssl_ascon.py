# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""wolfSSL ASCON ctypes wrapper calling the wolfSSL C library directly."""

import ctypes
import hmac
import os
from pathlib import Path

# Try to find the wolfSSL library
# First try the local build (used by participant)
_wolfssl_lib = None
_wolfssl_paths = [
    # Explicit environment variable override
    *( [Path(os.environ["WOLFSSL_LIB_PATH"])] if "WOLFSSL_LIB_PATH" in os.environ else [] ),
    # Monolith project build path
    Path(__file__).parents[4] / "build" / "external" / "wolfssl" / "libwolfssl.so",
    # Relative to configurator directory (from src/spsec_configurator/core/)
    Path(__file__).parents[3] / "external" / "wolfssl" / "build" / "wolfssl" / "libwolfssl.so",
    Path(__file__).parents[3] / "external" / "wolfssl" / "build" / "wolfssl" / "libwolfssl.so.44",
    Path(__file__).parents[3] / "external" / "wolfssl" / "build" / "wolfssl" / "libwolfssl.so.44.0.1",
    # System paths (where wolfssl-py might install it) - convert strings to Path objects
    Path("/usr/lib/libwolfssl.so"),
    Path("/usr/local/lib/libwolfssl.so"),
]

for path in _wolfssl_paths:
    if path.exists():
        try:
            test_lib = ctypes.CDLL(str(path))
            # Check if required ASCON symbols exist
            if hasattr(test_lib, "wc_AsconAEAD128_Init"):
                _wolfssl_lib = test_lib
                break
            # Library exists but lacks ASCON symbols, try next
        except OSError:
            continue

if _wolfssl_lib is None:
    raise ImportError(
        "Could not load wolfSSL library with ASCON support. Please ensure wolfSSL is built with ASCON enabled and available.\n"
        "The wolfSSL library should be at: spsec_participant_linux/build/external/wolfssl/libwolfssl.so\n"
        "Note: System-installed wolfSSL libraries may not have ASCON support compiled in."
    )

# Initialize wolfCrypt if needed (participant does this)
if hasattr(_wolfssl_lib, 'wolfCrypt_Init'):
    _wolfssl_lib.wolfCrypt_Init.restype = ctypes.c_int
    ret = _wolfssl_lib.wolfCrypt_Init()
    if ret != 0:
        import warnings
        warnings.warn(f"wolfCrypt_Init() returned {ret}, ASCON operations may fail")

# Constants
ASCON_AEAD128_KEY_SZ = 16
ASCON_AEAD128_NONCE_SZ = 16
ASCON_AEAD128_TAG_SZ = 16

# Define types
class AsconState(ctypes.Union):
    _fields_ = [
        ("s64", ctypes.c_uint64 * 5),
        ("s32", ctypes.c_uint32 * 10),
        ("s16", ctypes.c_uint16 * 20),
        ("s8", ctypes.c_uint8 * 40),
    ]

class wc_AsconAEAD128(ctypes.Structure):
    _fields_ = [
        ("key", ctypes.c_uint64 * 2),  # 16 bytes = 2 * 64-bit words
        ("state", AsconState),
        ("lastBlkSz", ctypes.c_uint8),
        ("keySet", ctypes.c_uint8, 1),
        ("nonceSet", ctypes.c_uint8, 1),
        ("adSet", ctypes.c_uint8, 1),
        ("op", ctypes.c_uint8, 2),
    ]

# Define function signatures
_wolfssl_lib.wc_AsconAEAD128_Init.argtypes = [ctypes.POINTER(wc_AsconAEAD128)]
_wolfssl_lib.wc_AsconAEAD128_Init.restype = ctypes.c_int

_wolfssl_lib.wc_AsconAEAD128_Clear.argtypes = [ctypes.POINTER(wc_AsconAEAD128)]
_wolfssl_lib.wc_AsconAEAD128_Clear.restype = None

_wolfssl_lib.wc_AsconAEAD128_SetKey.argtypes = [ctypes.POINTER(wc_AsconAEAD128), ctypes.POINTER(ctypes.c_uint8)]
_wolfssl_lib.wc_AsconAEAD128_SetKey.restype = ctypes.c_int

_wolfssl_lib.wc_AsconAEAD128_SetNonce.argtypes = [ctypes.POINTER(wc_AsconAEAD128), ctypes.POINTER(ctypes.c_uint8)]
_wolfssl_lib.wc_AsconAEAD128_SetNonce.restype = ctypes.c_int

_wolfssl_lib.wc_AsconAEAD128_SetAD.argtypes = [ctypes.POINTER(wc_AsconAEAD128), ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32]
_wolfssl_lib.wc_AsconAEAD128_SetAD.restype = ctypes.c_int

_wolfssl_lib.wc_AsconAEAD128_EncryptUpdate.argtypes = [ctypes.POINTER(wc_AsconAEAD128), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32]
_wolfssl_lib.wc_AsconAEAD128_EncryptUpdate.restype = ctypes.c_int

_wolfssl_lib.wc_AsconAEAD128_EncryptFinal.argtypes = [ctypes.POINTER(wc_AsconAEAD128), ctypes.POINTER(ctypes.c_uint8)]
_wolfssl_lib.wc_AsconAEAD128_EncryptFinal.restype = ctypes.c_int

_wolfssl_lib.wc_AsconAEAD128_DecryptUpdate.argtypes = [ctypes.POINTER(wc_AsconAEAD128), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32]
_wolfssl_lib.wc_AsconAEAD128_DecryptUpdate.restype = ctypes.c_int

_wolfssl_lib.wc_AsconAEAD128_DecryptFinal.argtypes = [ctypes.POINTER(wc_AsconAEAD128), ctypes.POINTER(ctypes.c_uint8)]
_wolfssl_lib.wc_AsconAEAD128_DecryptFinal.restype = ctypes.c_int


def ascon_encrypt(key: bytes, nonce: bytes, associateddata: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """ASCON-128 encrypt via wolfSSL. Returns (ciphertext, 16-byte tag)."""
    if len(key) != ASCON_AEAD128_KEY_SZ:
        raise ValueError(f"Key must be {ASCON_AEAD128_KEY_SZ} bytes, got {len(key)}")
    if len(nonce) != ASCON_AEAD128_NONCE_SZ:
        raise ValueError(f"Nonce must be {ASCON_AEAD128_NONCE_SZ} bytes, got {len(nonce)}")
    
    ctx = wc_AsconAEAD128()
    
    # Initialize
    ret = _wolfssl_lib.wc_AsconAEAD128_Init(ctypes.byref(ctx))
    if ret != 0:
        raise RuntimeError(f"wc_AsconAEAD128_Init failed: {ret}")
    
    try:
        # Set key
        key_array = (ctypes.c_uint8 * ASCON_AEAD128_KEY_SZ).from_buffer_copy(key)
        ret = _wolfssl_lib.wc_AsconAEAD128_SetKey(ctypes.byref(ctx), key_array)
        if ret != 0:
            raise RuntimeError(f"wc_AsconAEAD128_SetKey failed: {ret}")
        
        # Set nonce
        nonce_array = (ctypes.c_uint8 * ASCON_AEAD128_NONCE_SZ).from_buffer_copy(nonce)
        ret = _wolfssl_lib.wc_AsconAEAD128_SetNonce(ctypes.byref(ctx), nonce_array)
        if ret != 0:
            raise RuntimeError(f"wc_AsconAEAD128_SetNonce failed: {ret}")
        
        # Set associated data
        ad_len = len(associateddata)
        if ad_len > 0:
            ad_array = (ctypes.c_uint8 * ad_len).from_buffer_copy(associateddata)
            ret = _wolfssl_lib.wc_AsconAEAD128_SetAD(ctypes.byref(ctx), ad_array, ctypes.c_uint32(ad_len))
        else:
            ret = _wolfssl_lib.wc_AsconAEAD128_SetAD(ctypes.byref(ctx), None, ctypes.c_uint32(0))
        if ret != 0:
            raise RuntimeError(f"wc_AsconAEAD128_SetAD failed: {ret}")
        
        # Encrypt plaintext
        pt_len = len(plaintext)
        if pt_len > 0:
            pt_array = (ctypes.c_uint8 * pt_len).from_buffer_copy(plaintext)
            ct_array = (ctypes.c_uint8 * pt_len)()
            ret = _wolfssl_lib.wc_AsconAEAD128_EncryptUpdate(ctypes.byref(ctx), ct_array, pt_array, ctypes.c_uint32(pt_len))
            ciphertext = bytes(ct_array)
        else:
            # Empty plaintext: call with dummy values (as participant does)
            dummy_in = ctypes.c_uint8(0)
            dummy_out = ctypes.c_uint8(0)
            ret = _wolfssl_lib.wc_AsconAEAD128_EncryptUpdate(ctypes.byref(ctx), ctypes.byref(dummy_out), ctypes.byref(dummy_in), ctypes.c_uint32(0))
            ciphertext = b""
        if ret != 0:
            raise RuntimeError(f"wc_AsconAEAD128_EncryptUpdate failed: {ret}")
        
        # Finalize and get tag
        tag_array = (ctypes.c_uint8 * ASCON_AEAD128_TAG_SZ)()
        ret = _wolfssl_lib.wc_AsconAEAD128_EncryptFinal(ctypes.byref(ctx), tag_array)
        if ret != 0:
            raise RuntimeError(f"wc_AsconAEAD128_EncryptFinal failed: {ret}")
        
        tag = bytes(tag_array)
        return ciphertext, tag
    
    finally:
        _wolfssl_lib.wc_AsconAEAD128_Clear(ctypes.byref(ctx))


def ascon_decrypt(key: bytes, nonce: bytes, associateddata: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """ASCON-128 decrypt via wolfSSL. tag may be 8 or 16 bytes."""
    if len(key) != ASCON_AEAD128_KEY_SZ:
        raise ValueError(f"Key must be {ASCON_AEAD128_KEY_SZ} bytes, got {len(key)}")
    if len(nonce) != ASCON_AEAD128_NONCE_SZ:
        raise ValueError(f"Nonce must be {ASCON_AEAD128_NONCE_SZ} bytes, got {len(nonce)}")
    # Tag can be 8 or 16 bytes (comparison applies only to the provided length)
    if len(tag) > ASCON_AEAD128_TAG_SZ:
        raise ValueError(f"Tag must be at most {ASCON_AEAD128_TAG_SZ} bytes, got {len(tag)}")
    
    ctx = wc_AsconAEAD128()
    
    # Initialize
    ret = _wolfssl_lib.wc_AsconAEAD128_Init(ctypes.byref(ctx))
    if ret != 0:
        raise RuntimeError(f"wc_AsconAEAD128_Init failed: {ret}")
    
    try:
        # Set key
        key_array = (ctypes.c_uint8 * ASCON_AEAD128_KEY_SZ).from_buffer_copy(key)
        ret = _wolfssl_lib.wc_AsconAEAD128_SetKey(ctypes.byref(ctx), key_array)
        if ret != 0:
            raise RuntimeError(f"wc_AsconAEAD128_SetKey failed: {ret}")
        
        # Set nonce
        nonce_array = (ctypes.c_uint8 * ASCON_AEAD128_NONCE_SZ).from_buffer_copy(nonce)
        ret = _wolfssl_lib.wc_AsconAEAD128_SetNonce(ctypes.byref(ctx), nonce_array)
        if ret != 0:
            raise RuntimeError(f"wc_AsconAEAD128_SetNonce failed: {ret}")
        
        # Set associated data
        ad_len = len(associateddata)
        if ad_len > 0:
            ad_array = (ctypes.c_uint8 * ad_len).from_buffer_copy(associateddata)
            ret = _wolfssl_lib.wc_AsconAEAD128_SetAD(ctypes.byref(ctx), ad_array, ctypes.c_uint32(ad_len))
        else:
            ret = _wolfssl_lib.wc_AsconAEAD128_SetAD(ctypes.byref(ctx), None, ctypes.c_uint32(0))
        if ret != 0:
            raise RuntimeError(f"wc_AsconAEAD128_SetAD failed: {ret}")
        
        # Decrypt ciphertext
        ct_len = len(ciphertext)
        if ct_len > 0:
            ct_array = (ctypes.c_uint8 * ct_len).from_buffer_copy(ciphertext)
            pt_array = (ctypes.c_uint8 * ct_len)()
            ret = _wolfssl_lib.wc_AsconAEAD128_DecryptUpdate(ctypes.byref(ctx), pt_array, ct_array, ctypes.c_uint32(ct_len))
            plaintext = bytes(pt_array)
        else:
            # Empty ciphertext: call with dummy values
            dummy_in = ctypes.c_uint8(0)
            dummy_out = ctypes.c_uint8(0)
            ret = _wolfssl_lib.wc_AsconAEAD128_DecryptUpdate(ctypes.byref(ctx), ctypes.byref(dummy_out), ctypes.byref(dummy_in), ctypes.c_uint32(0))
            plaintext = b""
        if ret != 0:
            raise RuntimeError(f"wc_AsconAEAD128_DecryptUpdate failed: {ret}")
        
        # Clear decryption context (participant doesn't call DecryptFinal, just clears and re-encrypts)
        _wolfssl_lib.wc_AsconAEAD128_Clear(ctypes.byref(ctx))
        
        # Now re-encrypt to verify tag (matching participant's approach exactly)
        enc_ctx = wc_AsconAEAD128()
        ret = _wolfssl_lib.wc_AsconAEAD128_Init(ctypes.byref(enc_ctx))
        if ret != 0:
            raise RuntimeError(f"wc_AsconAEAD128_Init (enc) failed: {ret}")
        
        try:
            # Set key, nonce, and AD for re-encryption
            ret = _wolfssl_lib.wc_AsconAEAD128_SetKey(ctypes.byref(enc_ctx), key_array)
            if ret != 0:
                raise RuntimeError(f"wc_AsconAEAD128_SetKey (enc) failed: {ret}")
            
            ret = _wolfssl_lib.wc_AsconAEAD128_SetNonce(ctypes.byref(enc_ctx), nonce_array)
            if ret != 0:
                raise RuntimeError(f"wc_AsconAEAD128_SetNonce (enc) failed: {ret}")
            
            if ad_len > 0:
                ret = _wolfssl_lib.wc_AsconAEAD128_SetAD(ctypes.byref(enc_ctx), ad_array, ctypes.c_uint32(ad_len))
            else:
                ret = _wolfssl_lib.wc_AsconAEAD128_SetAD(ctypes.byref(enc_ctx), None, ctypes.c_uint32(0))
            if ret != 0:
                raise RuntimeError(f"wc_AsconAEAD128_SetAD (enc) failed: {ret}")
            
            # Re-encrypt the plaintext
            if ct_len > 0:
                scratch_array = (ctypes.c_uint8 * ct_len)()
                pt_array_for_enc = (ctypes.c_uint8 * ct_len).from_buffer_copy(plaintext)
                ret = _wolfssl_lib.wc_AsconAEAD128_EncryptUpdate(ctypes.byref(enc_ctx), scratch_array, pt_array_for_enc, ctypes.c_uint32(ct_len))
            else:
                dummy_in = ctypes.c_uint8(0)
                dummy_out = ctypes.c_uint8(0)
                ret = _wolfssl_lib.wc_AsconAEAD128_EncryptUpdate(ctypes.byref(enc_ctx), ctypes.byref(dummy_out), ctypes.byref(dummy_in), ctypes.c_uint32(0))
            if ret != 0:
                raise RuntimeError(f"wc_AsconAEAD128_EncryptUpdate (enc) failed: {ret}")
            
            # Get the computed tag
            computed_tag = (ctypes.c_uint8 * ASCON_AEAD128_TAG_SZ)()
            ret = _wolfssl_lib.wc_AsconAEAD128_EncryptFinal(ctypes.byref(enc_ctx), computed_tag)
            if ret != 0:
                raise RuntimeError(f"wc_AsconAEAD128_EncryptFinal (enc) failed: {ret}")
            
            # Compare tags constant-time (only compare the length of the provided tag, not full 16 bytes)
            tag_len = len(tag)
            computed_tag_bytes = bytes(computed_tag)
            if not hmac.compare_digest(computed_tag_bytes[:tag_len], tag):
                raise RuntimeError("wc_AsconAEAD128_DecryptFinal failed (tag mismatch)")
        finally:
            _wolfssl_lib.wc_AsconAEAD128_Clear(ctypes.byref(enc_ctx))
        
        return plaintext
    
    finally:
        _wolfssl_lib.wc_AsconAEAD128_Clear(ctypes.byref(ctx))
