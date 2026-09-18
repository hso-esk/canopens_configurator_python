#
# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.
#

"""Unit tests for crypto primitives (CONFIGURATOR_REQUIREMENTS.md §11 A, TC-CFG-001/002/003/004/009).
Note: SPsec uses 256-bit keys, so AES suite is AES-256-GCM with 8-byte truncated tags.
"""

import hashlib
import hmac
import os
import tempfile
import unittest

from spsec_configurator.core.crypto import (
    CryptoHandler,
    CryptoAlgorithm,
    HAS_ASCON,
    crypto_handler_set_context,
    crypto_handler_encrypt_with_assoc_data,
    crypto_handler_decrypt_with_assoc_data,
    hkdf_sha256,
)
from spsec_configurator.core.spsec_definitions import KEY_LEN, AUTH_TAG_SIZE


def _rfc5869_hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Independent HKDF-SHA256 (RFC 5869) so TC-CFG-001 doesn't compare the lib to itself."""
    hash_len = 32
    if not salt:
        salt = b"\x00" * hash_len
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()  # extract
    okm, block, counter = b"", b"", 1
    while len(okm) < length:                            # expand
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


class TestHkdf(unittest.TestCase):
    """TC-CFG-001: HKDF-SHA256 key derivation."""

    def test_matches_independent_rfc5869_implementation(self):
        ikm = bytes(range(32))
        salt = bytes(range(64, 76))
        # hkdf_sha256() passes info=None, i.e. an empty info string.
        for length in (16, KEY_LEN, 64):
            with self.subTest(length=length):
                self.assertEqual(
                    hkdf_sha256(ikm, salt, length),
                    _rfc5869_hkdf_sha256(ikm, salt, b"", length),
                )

    def test_session_key_is_key_len_bytes(self):
        """The session key is 256-bit - see _derive_session_key()."""
        self.assertEqual(len(hkdf_sha256(os.urandom(32), os.urandom(12), KEY_LEN)), 32)

    def test_distinct_salts_give_distinct_keys(self):
        ikm = os.urandom(32)
        a = hkdf_sha256(ikm, b"salt-one", KEY_LEN)
        b = hkdf_sha256(ikm, b"salt-two", KEY_LEN)
        self.assertNotEqual(a, b)


class _AeadRoundTripMixin:
    """Shared round-trip + tamper assertions for one AEAD algorithm."""

    algorithm = None
    nonce_len = 16

    def _context(self, handler, key, nonce):
        return crypto_handler_set_context(
            handler, key, nonce, self.nonce_len, AUTH_TAG_SIZE, self.algorithm
        )

    def test_roundtrip(self):
        handler = CryptoHandler()
        key, nonce = os.urandom(KEY_LEN), os.urandom(self.nonce_len)
        assoc = b"\x81\x01\x00\x00\x08"       # CAN ID + size, the real AD shape
        plaintext = b"SPsec app data payload, 0123456789"

        self.assertEqual(self._context(handler, key, nonce), 0)
        ct, tag = bytearray(len(plaintext)), bytearray(AUTH_TAG_SIZE)
        self.assertEqual(
            crypto_handler_encrypt_with_assoc_data(
                handler, plaintext, len(plaintext), ct, tag, assoc, len(assoc)
            ), 0,
        )
        self.assertNotEqual(bytes(ct), plaintext, "ciphertext must not equal plaintext")

        pt = bytearray(len(plaintext))
        self.assertEqual(self._context(handler, key, nonce), 0)
        self.assertEqual(
            crypto_handler_decrypt_with_assoc_data(
                handler, bytes(ct), len(ct), bytes(tag), pt, assoc, len(assoc)
            ), 0,
        )
        self.assertEqual(bytes(pt), plaintext)

    def test_tampered_tag_is_rejected(self):
        handler = CryptoHandler()
        key, nonce = os.urandom(KEY_LEN), os.urandom(self.nonce_len)
        assoc = b"\x81\x01\x00\x00\x08"
        plaintext = b"authenticate me"

        self.assertEqual(self._context(handler, key, nonce), 0)
        ct, tag = bytearray(len(plaintext)), bytearray(AUTH_TAG_SIZE)
        crypto_handler_encrypt_with_assoc_data(
            handler, plaintext, len(plaintext), ct, tag, assoc, len(assoc)
        )

        tag[0] ^= 0x01  # flip one bit
        pt = bytearray(len(plaintext))
        self.assertEqual(self._context(handler, key, nonce), 0)
        self.assertNotEqual(
            crypto_handler_decrypt_with_assoc_data(
                handler, bytes(ct), len(ct), bytes(tag), pt, assoc, len(assoc)
            ), 0,
            "a corrupted auth tag must not verify",
        )

    def test_tampered_assoc_data_is_rejected(self):
        handler = CryptoHandler()
        key, nonce = os.urandom(KEY_LEN), os.urandom(self.nonce_len)
        plaintext = b"bind me to my associated data"

        self.assertEqual(self._context(handler, key, nonce), 0)
        ct, tag = bytearray(len(plaintext)), bytearray(AUTH_TAG_SIZE)
        crypto_handler_encrypt_with_assoc_data(
            handler, plaintext, len(plaintext), ct, tag,
            b"\x81\x01\x00\x00\x08", 5,
        )

        pt = bytearray(len(plaintext))
        self.assertEqual(self._context(handler, key, nonce), 0)
        self.assertNotEqual(
            crypto_handler_decrypt_with_assoc_data(
                handler, bytes(ct), len(ct), bytes(tag), pt,
                b"\x82\x01\x00\x00\x08", 5,   # different CAN ID
            ), 0,
            "AD is authenticated: changing it must fail verification",
        )


class TestAesGcm(_AeadRoundTripMixin, unittest.TestCase):
    """TC-CFG-002: AES-256-GCM."""
    algorithm = CryptoAlgorithm.CRYPTO_ALGO_AES_GCM


class TestChaCha20Poly1305(_AeadRoundTripMixin, unittest.TestCase):
    """TC-CFG-003: ChaCha20-Poly1305 with an 8-byte truncated tag."""
    algorithm = CryptoAlgorithm.CRYPTO_ALGO_CHACHA20_POLY1305


@unittest.skipUnless(HAS_ASCON, "Ascon backend not available")
class TestAsconAead128(_AeadRoundTripMixin, unittest.TestCase):
    """TC-CFG-004: Ascon-AEAD128 (NIST SP 800-232)."""
    algorithm = CryptoAlgorithm.CRYPTO_ALGO_ASCON128


class TestSecureKeyStore(unittest.TestCase):
    """TC-CFG-009: at-rest key protection (PBKDF2 + AES-256-GCM)."""

    def setUp(self):
        from spsec_configurator.core.secure_keys import SecureKeyStore
        self._cls = SecureKeyStore
        self._dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._dir.name, "keys.enc")

    def tearDown(self):
        self._dir.cleanup()

    def test_create_store_and_roundtrip_a_key(self):
        store = self._cls(self.path)
        store.create("correct horse battery")
        secret = os.urandom(KEY_LEN)
        store.set_key("seed_key", secret, description="unit test", key_type="seed")
        store.save()
        self.assertTrue(os.path.exists(self.path))

        reopened = self._cls(self.path)
        self.assertTrue(reopened.load("correct horse battery"))
        self.assertEqual(reopened.get_key("seed_key"), secret)
        self.assertIn("seed_key", reopened.list_keys())

    def test_wrong_password_is_rejected(self):
        store = self._cls(self.path)
        store.create("right password")
        store.set_key("seed_key", os.urandom(KEY_LEN))
        store.save()

        self.assertFalse(self._cls(self.path).load("wrong password"))

    def test_key_material_is_not_stored_in_the_clear(self):
        """The whole point of the store: the file must not leak the key."""
        store = self._cls(self.path)
        store.create("a password")
        secret = bytes(range(32))
        store.set_key("seed_key", secret)
        store.save()

        with open(self.path, "rb") as fh:
            blob = fh.read()
        self.assertNotIn(secret, blob)
        self.assertNotIn(secret.hex().encode(), blob)

    def test_change_password(self):
        store = self._cls(self.path)
        store.create("old password")
        secret = os.urandom(KEY_LEN)
        store.set_key("seed_key", secret)
        store.save()

        store.change_password("old password", "new password")

        self.assertFalse(self._cls(self.path).load("old password"))
        reopened = self._cls(self.path)
        self.assertTrue(reopened.load("new password"))
        self.assertEqual(reopened.get_key("seed_key"), secret)

    def test_delete_key(self):
        store = self._cls(self.path)
        store.create("pw")
        store.set_key("seed_key", os.urandom(KEY_LEN))
        self.assertTrue(store.delete_key("seed_key"))
        self.assertIsNone(store.get_key("seed_key"))


if __name__ == "__main__":
    unittest.main()
