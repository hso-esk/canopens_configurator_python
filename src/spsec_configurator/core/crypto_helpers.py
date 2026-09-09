# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

from __future__ import annotations

from .crypto import CryptoHandler, crypto_handler_set_context, crypto_handler_encrypt_with_assoc_data, crypto_handler_decrypt_with_assoc_data
from .messages import generate_nonce_from_session_cnt
from .spsec_definitions import REQUIRED_NONCE_LEN


def spsec_encrypt_with_session(handler: CryptoHandler, session_key: bytes, session_cnt: int, salt,
                               assoc_data: bytes, assoc_len: int,
                               plaintext: bytes, plaintext_len: int,
                               ciphertext_out: bytearray, tag_out: bytearray, tag_len: int) -> int:
    nonce = generate_nonce_from_session_cnt(session_cnt, salt)
    # Preserve the handler's algorithm when setting context
    ret = crypto_handler_set_context(handler, session_key, nonce, REQUIRED_NONCE_LEN, tag_len, handler.algorithm)
    if ret < 0:
        return ret
    return crypto_handler_encrypt_with_assoc_data(handler, plaintext, plaintext_len, ciphertext_out, tag_out, assoc_data, assoc_len)


def spsec_decrypt_with_session(handler: CryptoHandler, session_key: bytes, session_cnt: int, salt,
                               assoc_data: bytes, assoc_len: int,
                               ciphertext: bytes, ciphertext_len: int,
                               tag: bytes,
                               plaintext_out: bytearray, tag_len: int) -> int:
    nonce = generate_nonce_from_session_cnt(session_cnt, salt)
    # Preserve the handler's algorithm when setting context
    ret = crypto_handler_set_context(handler, session_key, nonce, REQUIRED_NONCE_LEN, tag_len, handler.algorithm)
    if ret < 0:
        return ret
    return crypto_handler_decrypt_with_assoc_data(handler, ciphertext, ciphertext_len, tag, plaintext_out, assoc_data, assoc_len)


