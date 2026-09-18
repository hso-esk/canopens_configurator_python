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

"""Cross-implementation AEAD known-answer test.
Verifies this Python crypto matches the C implementation byte-for-byte using shared vectors from ../../test_vectors/aead_kat.json.
"""
import json
import os
import unittest

from spsec_configurator.core.crypto import (
    CryptoHandler,
    CryptoAlgorithm,
    crypto_handler_set_context,
    crypto_handler_encrypt_with_assoc_data,
)

# Vendored copy covers standalone clones; parent copy wins and is diffed
# against it when both exist, so the vendored one can't drift silently.
SHARED_VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "test_vectors", "aead_kat.json"
)
VENDORED_VECTORS_PATH = os.path.join(os.path.dirname(__file__), "aead_kat.json")
VECTORS_PATH = (
    SHARED_VECTORS_PATH
    if os.path.isfile(SHARED_VECTORS_PATH)
    else VENDORED_VECTORS_PATH
)

ALGO_NAME_TO_ENUM = {
    "AES_GCM": CryptoAlgorithm.CRYPTO_ALGO_AES_GCM,
    "CHACHA20_POLY1305": CryptoAlgorithm.CRYPTO_ALGO_CHACHA20_POLY1305,
    "ASCON128": CryptoAlgorithm.CRYPTO_ALGO_ASCON128,
}


@unittest.skipUnless(
    os.path.isfile(VECTORS_PATH),
    "no AEAD KAT vectors found (neither the shared test_vectors/aead_kat.json "
    "nor the vendored tests/aead_kat.json)",
)
class TestKatVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(VECTORS_PATH) as f:
            cls.data = json.load(f)

    def test_vendored_copy_matches_shared(self):
        """The vendored copy must not drift from the shared source of truth."""
        if not os.path.isfile(SHARED_VECTORS_PATH):
            self.skipTest("shared vectors not present (standalone clone)")
        if not os.path.isfile(VENDORED_VECTORS_PATH):
            self.fail("vendored tests/aead_kat.json is missing")
        with open(SHARED_VECTORS_PATH) as f:
            shared = json.load(f)
        with open(VENDORED_VECTORS_PATH) as f:
            vendored = json.load(f)
        self.assertEqual(
            shared,
            vendored,
            "tests/aead_kat.json has drifted from ../../test_vectors/aead_kat.json - "
            "re-copy it so standalone clones test the same vectors",
        )

    def test_vectors(self):
        key = bytes.fromhex(self.data["key_hex"])
        nonce = bytes.fromhex(self.data["nonce_hex"])
        plaintext = bytes.fromhex(self.data["plaintext_hex"])
        aad = bytes.fromhex(self.data["aad_hex"])
        auth_tag_size = self.data["auth_tag_size"]

        for vector in self.data["vectors"]:
            algo = ALGO_NAME_TO_ENUM[vector["algorithm"]]
            with self.subTest(algorithm=vector["algorithm"]):
                handler = CryptoHandler()
                res = crypto_handler_set_context(
                    handler, key, nonce, len(nonce), auth_tag_size, algo
                )
                if res != 0:
                    self.skipTest(
                        f"{vector['algorithm']} unsupported by this backend"
                    )

                ct = bytearray(len(plaintext))
                tag = bytearray(auth_tag_size)
                res = crypto_handler_encrypt_with_assoc_data(
                    handler, plaintext, len(plaintext), ct, tag, aad, len(aad)
                )
                self.assertEqual(res, 0, f"{vector['algorithm']} encrypt failed")
                self.assertEqual(
                    bytes(ct).hex(),
                    vector["ciphertext_hex"],
                    f"{vector['algorithm']} ciphertext diverges from the "
                    "shared known-answer vector - check nonce/key/AAD handling",
                )
                self.assertEqual(
                    bytes(tag).hex(),
                    vector["tag_hex"],
                    f"{vector['algorithm']} tag diverges from the shared "
                    "known-answer vector",
                )


if __name__ == "__main__":
    unittest.main()
