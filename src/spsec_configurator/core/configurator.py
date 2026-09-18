# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

from __future__ import annotations

import time
import os
from dataclasses import dataclass
from typing import Optional
import hmac

from .logging_util import configure_logging, log_info, log_warning, log_error, log_debug, LOG_LEVEL_INFO, log_array, LOG_LEVEL_DEBUG
from .spsec_definitions import (
    AUTH_TAG_SIZE,
    RANDOM_SIZE,
    KEY_LEN,
    SALT_LEN,
    REQUIRED_NONCE_LEN,
    SPSEC_MSGTYPE_APP_DATA,
    SPSEC_MSGTYPE_SERVER_HELLO,
    SPSEC_MSGTYPE_SERVER_FINISHED,
    SPSEC_MSGTYPE_SERVER_READ_INITIATE,
    SPSEC_MSGTYPE_SERVER_READ_SEGMENT,
    SPSEC_MSGTYPE_SERVER_WRITE_INITIATE,
    SPSEC_MSGTYPE_SERVER_WRITE_SEGMENT,
    SPSEC_MSGTYPE_SERVER_TERMINATE,
    SPSEC_REG_STATUS,
    SPSEC_REG_LAST_SECURITY_EVENT,
    SPSEC_REG_CORE_VERSION_INFO,
    SPSEC_REG_MAPPING_VERSION_INFO,
    SPSEC_REG_PROVISIONING_KEY,
    SPSEC_REG_INTEGRATOR_KEY,
    SPSEC_REG_SEED_KEY,
    SPSEC_REG_PROVISIONING_KEY_SALT,
    SPSEC_REG_INTEGRATOR_KEY_SALT,
    SPSEC_REG_SEED_KEY_SALT,
    SPSEC_REG_PROVISIONING_KEY_ID,
    SPSEC_REG_INTEGRATOR_KEY_ID,
    SPSEC_REG_SEED_KEY_ID,
    SPSEC_REG_SECURE_HEARTBEAT_MONITOR,
    SPSEC_KEY_SELECTORS,
    SPSEC_KEY_SELECTOR_ZERO_KEY,
    SPSEC_KEY_SELECTOR_PROVISIONING_KEY,
    SPSEC_KEY_SELECTOR_INTEGRATOR_KEY,
    SPSEC_KEY_SELECTOR_SEED_KEY,
    SPSEC_REG_MANUFACTURER_RESET,
    SPSEC_MANUFACTURER_RESET_MAGIC,
    SESSION_TIMEOUT_S,
    SPSEC_REG_SYNC_ROLE_ACTIVATION,
)
from .can_interface import can_channel_init, can_channel_destroy, can_channel_receive
from .can_interface import channel_send_appdata
from .messages import (
    SPsecMessage,
    AppData,
    SPsecClientHelloMessage,
    spsecclienthello_new,
    SPsecServerHelloMessage,
    SPsecClientFinishedMessage,
    SPsecReadInitiateMessage,
    SPsecClientReadSegmentRequest,
    SPsecServerReadSegmentResponse,
    SPsecWriteInitiateMessage,
    SPsecClientWriteSegmentRequest,
    SPsecClientWriteSegmentResponse,
    SPsecSessionTerminateMessage,
    ConfigurationSessionAuthTagData,
    authtagparticipantdata_new,
    calculate_shared_cnt,
    generate_nonce_from_session_cnt,
)
from .configurator_channel import (
    SPsecCommChannel,
    configurator_channel_send_client_hello,
    set_client_finished_address,
    configurator_channel_send_client_finished,
    set_read_initiate_request_address,
    configurator_channel_send_read_initiate_request,
    set_read_segment_request_address,
    configurator_channel_send_read_segment_request,
    set_write_initiate_request_address,
    configurator_channel_send_write_initiate_request,
    set_segment_write_request_address,
    configurator_channel_send_write_segment_request,
    set_session_terminate_request_address,
    configurator_channel_send_session_terminate_request,
)
from .crypto import CryptoHandler, CryptoAlgorithm, crypto_algorithm_from_string, crypto_algorithm_name, hkdf_sha256, crypto_handler_set_context, compute_tag_only
from .crypto_helpers import spsec_encrypt_with_session, spsec_decrypt_with_session
from .keys import CommunicationKeys, communication_keys_init, load_kv_hex_file, spseckey_new, spsecsalt_new

# Maximum plaintext payload bytes per segment in a single Write Segment request
MAX_SEG_DATA = 32

@dataclass
class Configurator:
    channel: SPsecCommChannel
    crypto_handler: CryptoHandler
    session_key: bytearray
    session_cnt: int
    in_session: bool
    comm_keys: CommunicationKeys
    session_auth_tag_data: ConfigurationSessionAuthTagData
    tx_delay_us: int
    last_tx_monotonic_ns: int
    last_rx_monotonic_ns: int
    algorithm: CryptoAlgorithm = CryptoAlgorithm.CRYPTO_ALGO_AES_GCM


    
def configurator_init(interface_name: str, keys_file: str, algorithm: Optional[CryptoAlgorithm] = None) -> Configurator:
    
    # Determine algorithm: parameter > environment variable > default
    if algorithm is None:
        env_algo = os.getenv("SPSEC_AEAD_ALGO")
        if env_algo:
            algorithm = crypto_algorithm_from_string(env_algo)
            log_info("main_configurator", "SPSEC_AEAD_ALGO=%s -> %s", env_algo, crypto_algorithm_name(algorithm))
        else:
            algorithm = CryptoAlgorithm.CRYPTO_ALGO_AES_GCM
            log_info("main_configurator", "Using default AEAD algorithm %s", crypto_algorithm_name(algorithm))
    else:
        log_info("main_configurator", "Using AEAD algorithm %s", crypto_algorithm_name(algorithm))
    
    log_info("main_configurator", "Try to start configurator on interface %s", interface_name)
    comm = SPsecCommChannel(channel=can_channel_init(interface_name))
    crypto = CryptoHandler(algorithm=algorithm)
    comm_keys = communication_keys_init()

    # Load required keys/salts
    def _load_key(name: str, idx: int) -> None:
        data = load_kv_hex_file(keys_file, name)
        if data is None or len(data) != KEY_LEN:
            raise RuntimeError(f"Key {name} missing or invalid length")
        comm_keys.spsec_keys[idx] = spseckey_new(idx, data)

    def _load_salt(name: str, idx: int) -> None:
        data = load_kv_hex_file(keys_file, name)
        if data is None or len(data) < SALT_LEN:
            raise RuntimeError(f"Salt {name} missing or too short (need {SALT_LEN} bytes, got {len(data) if data else 0})")
        comm_keys.spsec_salt[idx] = spsecsalt_new(data[:SALT_LEN])

    _load_key("provisioning_key", 1)
    _load_salt("provisioning_salt", 1)
    _load_key("integrator_key", 2)
    _load_salt("integrator_salt", 2)
    _load_key("seed_key", 3)
    _load_salt("seed_salt", 3)

    cfg = Configurator(
        channel=comm,
        crypto_handler=crypto,
        session_key=bytearray(KEY_LEN),
        session_cnt=0,
        in_session=False,
        comm_keys=comm_keys,
        session_auth_tag_data=authtagparticipantdata_new(),
        tx_delay_us=0,
        algorithm=algorithm,
        last_tx_monotonic_ns=0,
        last_rx_monotonic_ns=0,
    )
    log_info("main_configurator", "Configurator initialized on interface %s. Starting configuration", interface_name)
    return cfg


def configurator_destroy(cfg: Configurator) -> None:
    can_channel_destroy(cfg.channel.channel)


def configurator_receive(cfg: Configurator, timeout_ms: int) -> Optional[SPsecMessage]:
    msg = can_channel_receive(cfg.channel.channel, timeout_ms)
    if msg:
        cfg.last_rx_monotonic_ns = time.time_ns()
    return msg


def _enforce_tx_delay(cfg: Configurator) -> None:
    if cfg.tx_delay_us <= 0:
        return
    now = time.time_ns()
    min_interval_ns = cfg.tx_delay_us * 1000
    if cfg.last_tx_monotonic_ns > 0:
        due = cfg.last_tx_monotonic_ns + min_interval_ns
        if now < due:
            time.sleep((due - now) / 1_000_000_000)


def _send_appdata(cfg: Configurator, ad: AppData) -> int:
    _enforce_tx_delay(cfg)
    ret = channel_send_appdata(cfg.channel.channel, ad)
    if ret == 0 and cfg.tx_delay_us > 0:
        cfg.last_tx_monotonic_ns = time.time_ns()
    return ret


def _initialize_session_auth_data(cfg: Configurator, client_random: bytes, key_selector_value: int) -> None:
    cfg.session_auth_tag_data.cli_random[:] = client_random
    cfg.session_auth_tag_data.key_selector[0] = key_selector_value
    cfg.session_auth_tag_data.key_selector[1] = 0xFF
    cfg.session_auth_tag_data.key_selector[2] = 0xFF
    cfg.session_auth_tag_data.key_selector[3] = 0xFF
    # bind salt pointer by selector mapping index
    for i, sel in enumerate(SPSEC_KEY_SELECTORS):
        if sel == key_selector_value:
            cfg.session_auth_tag_data.spsec_salt = cfg.comm_keys.spsec_salt[i]
            break


def _derive_session_key(cfg: Configurator, salt: bytes, key_idx: int) -> int:
    base_key = cfg.comm_keys.spsec_keys[key_idx]
    if base_key is None:
        return -1
    out = hkdf_sha256(bytes(base_key.key), salt, KEY_LEN)
    cfg.session_key[:] = out
    return 0


def configurator_send_client_finished(cfg: Configurator, target_pid: int) -> int:
    cfg.session_cnt = calculate_shared_cnt(cfg.session_auth_tag_data)
    cfg.session_cnt += 1
    fin = SPsecClientFinishedMessage(target_pid, cfg.session_cnt, bytearray(AUTH_TAG_SIZE), 0)
    set_client_finished_address(fin)
    cfg.session_auth_tag_data.address = fin.address

    assoc = bytes(cfg.session_auth_tag_data.key_selector) + bytes(cfg.session_auth_tag_data.cli_random) + bytes(cfg.session_auth_tag_data.srv_random) + fin.address.to_bytes(4, "little")
    # Build nonce from session_cnt and salt


    nonce = generate_nonce_from_session_cnt(cfg.session_cnt, cfg.session_auth_tag_data.spsec_salt)
    tag = compute_tag_only(bytes(cfg.session_key), nonce, assoc, AUTH_TAG_SIZE, cfg.algorithm)
    fin.auth_tag[:] = tag

    # Store for ServerFinished verification
    cfg.session_auth_tag_data.cli_auth_tag[:] = tag

    ad = AppData(fin.address, bytes(fin.auth_tag))
    return _send_appdata(cfg, ad)



def _clear_session(cfg: Configurator) -> None:
    """Zeroize temporary session keys and reset session parameters per SPsec201 REQ-CFG-014."""
    if cfg.session_key:
        for i in range(len(cfg.session_key)):
            cfg.session_key[i] = 0
    cfg.session_cnt = 0
    cfg.in_session = False
    if cfg.session_auth_tag_data:
        if cfg.session_auth_tag_data.cli_random:
            for i in range(len(cfg.session_auth_tag_data.cli_random)):
                cfg.session_auth_tag_data.cli_random[i] = 0
        if cfg.session_auth_tag_data.srv_random:
            for i in range(len(cfg.session_auth_tag_data.srv_random)):
                cfg.session_auth_tag_data.srv_random[i] = 0
        if cfg.session_auth_tag_data.cli_auth_tag:
            for i in range(len(cfg.session_auth_tag_data.cli_auth_tag)):
                cfg.session_auth_tag_data.cli_auth_tag[i] = 0

def configurator_start_session(cfg: Configurator, target_pid: int, key_selector_value: int, timeout_seconds: float) -> int:
    client_random = os.urandom(RANDOM_SIZE)
    _initialize_session_auth_data(cfg, client_random, key_selector_value)

    hello = spsecclienthello_new(target_pid, key_selector_value, client_random)
    ret = configurator_channel_send_client_hello(cfg.channel, hello)
    # Log details about client hello content
    log_array(LOG_LEVEL_DEBUG, "conf_session_management", "Client random for salt:", client_random, RANDOM_SIZE)
    if ret < 0:
        return ret

    # Wait for server hello
    end = time.time() + timeout_seconds
    srv_hello: Optional[SPsecServerHelloMessage] = None
    while time.time() < end:
        msg = configurator_receive(cfg, 100)
        if not msg:
            continue
        if msg.msg_type != SPSEC_MSGTYPE_SERVER_HELLO:
            continue
        srv_hello = msg.msg_content  # type: ignore
        if srv_hello.participant_id != target_pid:
            continue
        break
    if srv_hello is None:
        _clear_session(cfg)
        return -6
    # Derive session key using HKDF with salt = client_random || server_random
    salt = bytes(client_random) + bytes(srv_hello.random)
    # find key index by selector
    key_idx = next((i for i, sel in enumerate(SPSEC_KEY_SELECTORS) if sel == key_selector_value), None)
    if key_idx is None:
        return -1
    ret = _derive_session_key(cfg, salt, key_idx)
    if ret < 0:
        return ret
    cfg.session_auth_tag_data.srv_random[:] = srv_hello.random

    ret = configurator_send_client_finished(cfg, target_pid)
    if ret < 0:
        return ret

    # Wait for server finished
    end = time.time() + timeout_seconds
    while time.time() < end:
        msg = configurator_receive(cfg, 100)
        if not msg:
            continue
        if msg.msg_type != SPSEC_MSGTYPE_SERVER_FINISHED:
            continue
        # Verify auth tag
        sf = msg.msg_content  # type: ignore
        if sf.participant_id != target_pid:
            continue
        cfg.session_cnt += 1
        assoc = (
            cfg.session_auth_tag_data.address.to_bytes(4, "little")
            + bytes(cfg.session_auth_tag_data.cli_random)
            + bytes(cfg.session_auth_tag_data.srv_random)
            + bytes(cfg.session_auth_tag_data.cli_auth_tag)
            + sf.address.to_bytes(4, "little")
        )

        nonce = generate_nonce_from_session_cnt(cfg.session_cnt, cfg.session_auth_tag_data.spsec_salt)
        ret = crypto_handler_set_context(cfg.crypto_handler, bytes(cfg.session_key), nonce, REQUIRED_NONCE_LEN, AUTH_TAG_SIZE, cfg.algorithm)
        if ret < 0:
            return -1
        # compute tag via selected algorithm with AD-only data
        tag = compute_tag_only(bytes(cfg.session_key), nonce, assoc, AUTH_TAG_SIZE, cfg.algorithm)
        if not hmac.compare_digest(bytes(tag), bytes(sf.auth_tag)):
            _clear_session(cfg)
            return -1
        cfg.in_session = True
        return 0
    _clear_session(cfg)
    return -6


def _wait_for_types(cfg: Configurator, per_attempt_ms: int, overall_ms: int, desired: set[int], ignore: set[int]) -> Optional[SPsecMessage]:
    attempts = max(1, overall_ms // per_attempt_ms)
    for _ in range(attempts):
        msg = configurator_receive(cfg, per_attempt_ms)
        if not msg:
            continue
        t = msg.msg_type
        if t in desired:
            return msg
        if t in ignore:
            continue
    return None


def configurator_write_register(cfg: Configurator, target_pid: int, reg: int, data: bytes, data_len: int) -> int:
    # Write Initiate
    cfg.session_cnt += 1
    wi = SPsecWriteInitiateMessage(target_pid, cfg.session_cnt, reg, data_len)
    # Compose plaintext: [reg, 0xFF, 0xFF, 0xFF, len(LE 4 bytes)]
    wi.plaintext[0] = reg & 0xFF
    wi.plaintext[1] = 0xFF
    wi.plaintext[2] = 0xFF
    wi.plaintext[3] = 0xFF
    wi.plaintext[4] = data_len & 0xFF
    wi.plaintext[5] = (data_len >> 8) & 0xFF
    wi.plaintext[6] = (data_len >> 16) & 0xFF
    wi.plaintext[7] = (data_len >> 24) & 0xFF
    set_write_initiate_request_address(wi)
    assoc = wi.address.to_bytes(4, "little")
    ret = spsec_encrypt_with_session(cfg.crypto_handler, bytes(cfg.session_key), cfg.session_cnt, cfg.session_auth_tag_data.spsec_salt,
                                     assoc, 4, bytes(wi.plaintext), 8, wi.ciphertext, wi.auth_tag, AUTH_TAG_SIZE)
    if ret < 0:
        return ret
    ad = AppData(wi.address, bytes(wi.ciphertext) + bytes(wi.auth_tag))
    ret = _send_appdata(cfg, ad)
    if ret < 0:
        return ret
    msg = _wait_for_types(cfg, 300, 3000, {SPSEC_MSGTYPE_SERVER_WRITE_INITIATE}, {SPSEC_MSGTYPE_APP_DATA, SPSEC_MSGTYPE_SERVER_WRITE_SEGMENT})
    if not msg:
        return -8
    # Decrypt response header to check reg/len
    recv_wi: SPsecWriteInitiateMessage = msg.msg_content  # type: ignore
    cfg.session_cnt += 1
    if (recv_wi.cnt & 0xFF) != (cfg.session_cnt & 0xFF):
        log_error("configurator", "Counter LSB mismatch: expected 0x%02X, got 0x%02X", cfg.session_cnt & 0xFF, recv_wi.cnt & 0xFF)
        return -8
    assoc2 = recv_wi.address.to_bytes(4, "little")
    ret = spsec_decrypt_with_session(cfg.crypto_handler, bytes(cfg.session_key), cfg.session_cnt, cfg.session_auth_tag_data.spsec_salt,
                                     assoc2, 4, bytes(recv_wi.ciphertext), len(recv_wi.ciphertext), bytes(recv_wi.auth_tag), recv_wi.plaintext, AUTH_TAG_SIZE)
    if ret < 0:
        return ret

    # Write segment in chunks (up to MAX_SEG_DATA bytes)
    offset = 0
    while offset < data_len or (data_len == 0 and offset == 0):
        chunk_len = min(MAX_SEG_DATA, data_len - offset)
        chunk = data[offset:offset + chunk_len]

        cfg.session_cnt += 1
        ws = SPsecClientWriteSegmentRequest(target_pid, cfg.session_cnt, chunk, chunk_len)
        set_segment_write_request_address(ws)
        ws.ciphertext_ptr = bytearray(chunk_len)
        assoc3 = ws.address.to_bytes(4, "little")
        ret = spsec_encrypt_with_session(cfg.crypto_handler, bytes(cfg.session_key), cfg.session_cnt, cfg.session_auth_tag_data.spsec_salt,
                                         assoc3, 4, ws.dat, ws.data_len, ws.ciphertext_ptr, ws.auth_tag, AUTH_TAG_SIZE)
        if ret < 0:
            return ret
        ad2 = AppData(ws.address, bytes(ws.ciphertext_ptr) + bytes(ws.auth_tag))
        ret = _send_appdata(cfg, ad2)
        if ret < 0:
            return ret
        msg2 = _wait_for_types(cfg, 300, 3000, {SPSEC_MSGTYPE_SERVER_WRITE_SEGMENT}, {SPSEC_MSGTYPE_APP_DATA})
        if not msg2:
            return -9
        recv_ws: SPsecClientWriteSegmentResponse = msg2.msg_content  # type: ignore
        cfg.session_cnt += 1
        if (recv_ws.cnt & 0xFF) != (cfg.session_cnt & 0xFF):
            log_error("configurator", "Counter LSB mismatch: expected 0x%02X, got 0x%02X", cfg.session_cnt & 0xFF, recv_ws.cnt & 0xFF)
            return -8
        assoc4 = recv_ws.address.to_bytes(4, "little")
        pt = bytearray(4)
        ret = spsec_decrypt_with_session(cfg.crypto_handler, bytes(cfg.session_key), cfg.session_cnt, cfg.session_auth_tag_data.spsec_salt,
                                         assoc4, 4, bytes(recv_ws.ciphertext), len(recv_ws.ciphertext), bytes(recv_ws.auth_tag), pt, AUTH_TAG_SIZE)
        if ret < 0:
            return ret
        if pt[0] != 0:
            return -3
        offset += chunk_len
        if data_len == 0:
            break
    return 0


def configurator_read_register(cfg: Configurator, target_pid: int, reg: int, reg_bytes: bytearray, reg_bytes_len: int) -> int:
    # Read Initiate
    cfg.session_cnt += 1
    ri = SPsecReadInitiateMessage(target_pid, cfg.session_cnt, reg, reg_bytes_len)
    # Compose plaintext: [reg, 0xFF, 0xFF, 0xFF, len(LE 4 bytes)]
    ri.plaintext[0] = reg & 0xFF
    ri.plaintext[1] = 0xFF
    ri.plaintext[2] = 0xFF
    ri.plaintext[3] = 0xFF
    ri.plaintext[4] = reg_bytes_len & 0xFF
    ri.plaintext[5] = (reg_bytes_len >> 8) & 0xFF
    ri.plaintext[6] = (reg_bytes_len >> 16) & 0xFF
    ri.plaintext[7] = (reg_bytes_len >> 24) & 0xFF
    set_read_initiate_request_address(ri)
    assoc = ri.address.to_bytes(4, "little")
    ret = spsec_encrypt_with_session(cfg.crypto_handler, bytes(cfg.session_key), cfg.session_cnt, cfg.session_auth_tag_data.spsec_salt,
                                     assoc, 4, bytes(ri.plaintext), 8, ri.ciphertext, ri.auth_tag, AUTH_TAG_SIZE)
    if ret < 0:
        return ret
    ad = AppData(ri.address, bytes(ri.ciphertext) + bytes(ri.auth_tag))
    ret = _send_appdata(cfg, ad)
    if ret < 0:
        return ret
    msg = _wait_for_types(cfg, 100, 500, {SPSEC_MSGTYPE_SERVER_READ_INITIATE}, {SPSEC_MSGTYPE_APP_DATA})
    if not msg:
        return -7
    recv_ri: SPsecReadInitiateMessage = msg.msg_content  # type: ignore
    cfg.session_cnt += 1
    if (recv_ri.cnt & 0xFF) != (cfg.session_cnt & 0xFF):
        log_error("configurator", "Counter LSB mismatch: expected 0x%02X, got 0x%02X", cfg.session_cnt & 0xFF, recv_ri.cnt & 0xFF)
        return -8
    assoc2 = recv_ri.address.to_bytes(4, "little")
    ret = spsec_decrypt_with_session(cfg.crypto_handler, bytes(cfg.session_key), cfg.session_cnt, cfg.session_auth_tag_data.spsec_salt,
                                     assoc2, 4, bytes(recv_ri.ciphertext), len(recv_ri.ciphertext), bytes(recv_ri.auth_tag), recv_ri.plaintext, AUTH_TAG_SIZE)
    if ret < 0:
        return ret

    # Parse actual register length from Read-Initiate response
    if len(recv_ri.plaintext) < 8:
        log_error("configurator", "Read initiate response plaintext too short: %d", len(recv_ri.plaintext))
        return -4
    resp_reg = recv_ri.plaintext[0]
    actual_len = int.from_bytes(bytes(recv_ri.plaintext[4:8]), "little")
    if resp_reg != reg:
        log_error("configurator", "Read initiate response for unexpected register 0x%02X, expected 0x%02X", resp_reg, reg)
        return -4
    if actual_len > reg_bytes_len:
        log_error("configurator", "Read initiate response length %u larger than requested buffer %u", actual_len, reg_bytes_len)
        return -5
    if actual_len == 0:
        # Register is present but empty (e.g. an unset device identification
        # string). Nothing to fetch; report success with zero bytes copied.
        log_info("configurator", "Register 0x%02X is empty (length 0)", reg)
        return 0

    # Read Segment
    cfg.session_cnt += 1
    rs = SPsecClientReadSegmentRequest(target_pid, cfg.session_cnt)
    set_read_segment_request_address(rs)

    nonce = generate_nonce_from_session_cnt(cfg.session_cnt, cfg.session_auth_tag_data.spsec_salt)
    assoc3 = rs.address.to_bytes(4, "little")
    tag = compute_tag_only(bytes(cfg.session_key), nonce, assoc3, AUTH_TAG_SIZE, cfg.algorithm)
    rs.auth_tag[:] = tag
    ad2 = AppData(rs.address, bytes(rs.auth_tag))
    ret = _send_appdata(cfg, ad2)
    if ret < 0:
        return ret
    msg2 = _wait_for_types(cfg, 100, 500, {SPSEC_MSGTYPE_SERVER_READ_SEGMENT}, {SPSEC_MSGTYPE_APP_DATA})
    if not msg2:
        return -5
    recv_rs: SPsecServerReadSegmentResponse = msg2.msg_content  # type: ignore
    cfg.session_cnt += 1
    if (recv_rs.cnt & 0xFF) != (cfg.session_cnt & 0xFF):
        log_error("configurator", "Counter LSB mismatch: expected 0x%02X, got 0x%02X", cfg.session_cnt & 0xFF, recv_rs.cnt & 0xFF)
        return -8
    assoc4 = recv_rs.address.to_bytes(4, "little")
    # Slice ciphertext and tag based on negotiated actual_len
    raw = bytes(recv_rs.ciphertext_ptr or b"") + bytes(recv_rs.auth_tag)
    real_ct = raw[:actual_len]
    real_tag = raw[actual_len:actual_len + AUTH_TAG_SIZE]
    pt = bytearray(actual_len)
    ret = spsec_decrypt_with_session(cfg.crypto_handler, bytes(cfg.session_key), cfg.session_cnt, cfg.session_auth_tag_data.spsec_salt,
                                     assoc4, 4, real_ct, actual_len, real_tag, pt, AUTH_TAG_SIZE)
    if ret < 0:
        return ret
    # Returns 0 on success, not the byte count: callers test `ret == 0`
    # (device_discovery.py:107, cli/main.py:76,83,89,95).
    to_copy = min(actual_len, len(reg_bytes))
    reg_bytes[:to_copy] = pt[:to_copy]
    return 0


def configurator_write_key(cfg: Configurator, target_pid: int, key_selector: int) -> int:
    reg_map = {
        SPSEC_KEY_SELECTOR_PROVISIONING_KEY: SPSEC_REG_PROVISIONING_KEY,
        SPSEC_KEY_SELECTOR_INTEGRATOR_KEY: SPSEC_REG_INTEGRATOR_KEY,
        SPSEC_KEY_SELECTOR_SEED_KEY: SPSEC_REG_SEED_KEY
    }
    reg = reg_map.get(key_selector, 0)
    if reg == 0:
        return -2
        
    # Internal index mapping: PROV=1, INT=2, SEED=3
    internal_idx_map = {
        SPSEC_KEY_SELECTOR_PROVISIONING_KEY: 1,
        SPSEC_KEY_SELECTOR_INTEGRATOR_KEY: 2,
        SPSEC_KEY_SELECTOR_SEED_KEY: 3
    }
    idx = internal_idx_map.get(key_selector, 0)
    key = cfg.comm_keys.spsec_keys[idx]
    if key is None:
        return -3
    return configurator_write_register(cfg, target_pid, reg, bytes(key.key), len(key.key))


def configurator_set_sync_role(cfg: Configurator, target_pid: int, enable: bool) -> int:
    """Enable/disable Sync Master role (writes reg 0x63, SPsec102 REQ-CFG-004)."""
    val = bytes([1 if enable else 0])
    return configurator_write_register(cfg, target_pid, SPSEC_REG_SYNC_ROLE_ACTIVATION, val, 1)


def configurator_write_salt(cfg: Configurator, target_pid: int, salt_selector: int) -> int:
    reg_map = {
        SPSEC_KEY_SELECTOR_PROVISIONING_KEY: SPSEC_REG_PROVISIONING_KEY_SALT,
        SPSEC_KEY_SELECTOR_INTEGRATOR_KEY: SPSEC_REG_INTEGRATOR_KEY_SALT,
        SPSEC_KEY_SELECTOR_SEED_KEY: SPSEC_REG_SEED_KEY_SALT
    }
    reg = reg_map.get(salt_selector, 0)
    if reg == 0:
        return -2
        
    internal_idx_map = {
        SPSEC_KEY_SELECTOR_PROVISIONING_KEY: 1,
        SPSEC_KEY_SELECTOR_INTEGRATOR_KEY: 2,
        SPSEC_KEY_SELECTOR_SEED_KEY: 3
    }
    idx = internal_idx_map.get(salt_selector, 0)
    salt = cfg.comm_keys.spsec_salt[idx]
    if salt is None:
        return -3
    return configurator_write_register(cfg, target_pid, reg, bytes(salt.salt), len(salt.salt))


def configurator_write_key_id(cfg: Configurator, target_pid: int, key_selector: int) -> int:
    reg_map = {
        SPSEC_KEY_SELECTOR_PROVISIONING_KEY: SPSEC_REG_PROVISIONING_KEY_ID,
        SPSEC_KEY_SELECTOR_INTEGRATOR_KEY: SPSEC_REG_INTEGRATOR_KEY_ID,
        SPSEC_KEY_SELECTOR_SEED_KEY: SPSEC_REG_SEED_KEY_ID
    }
    reg = reg_map.get(key_selector, 0)
    if reg == 0:
        return -2
        
    internal_idx_map = {
        SPSEC_KEY_SELECTOR_PROVISIONING_KEY: 1,
        SPSEC_KEY_SELECTOR_INTEGRATOR_KEY: 2,
        SPSEC_KEY_SELECTOR_SEED_KEY: 3
    }
    idx = internal_idx_map.get(key_selector, 0)
    key = cfg.comm_keys.spsec_keys[idx]
    if key is None:
        return -3
    key_id_bytes = key.key_id.to_bytes(4, "little")
    return configurator_write_register(cfg, target_pid, reg, key_id_bytes, 4)


def configurator_terminate_session(cfg: Configurator, target_pid: int) -> int:
    cfg.session_cnt += 1
    msg = SPsecSessionTerminateMessage(target_pid, cfg.session_cnt)
    set_session_terminate_request_address(msg)

    nonce = generate_nonce_from_session_cnt(cfg.session_cnt, cfg.session_auth_tag_data.spsec_salt)
    assoc = msg.address.to_bytes(4, "little")
    tag = compute_tag_only(bytes(cfg.session_key), nonce, assoc, AUTH_TAG_SIZE, cfg.algorithm)
    msg.auth_tag[:] = tag
    # Log counter and address diagnostics prior to send
    cnt_lsb = msg.cnt & 0xFF
    addr_cnt_lsb = (msg.address >> 16) & 0xFF
    log_info("conf_session_management", "Terminate request: cnt=%u (lsb=%u), addr=%08x (lsb=%u)", msg.cnt, cnt_lsb, msg.address, addr_cnt_lsb)
    log_array(LOG_LEVEL_DEBUG, "conf_session_management", "Terminate nonce:", nonce, len(nonce))
    log_array(LOG_LEVEL_DEBUG, "conf_session_management", "Terminate assoc (addr LE):", assoc, len(assoc))
    log_array(LOG_LEVEL_DEBUG, "conf_session_management", "Terminate auth tag:", msg.auth_tag, len(msg.auth_tag))
    ad = AppData(msg.address, bytes(msg.auth_tag))
    ret = _send_appdata(cfg, ad)
    if ret < 0:
        return ret
    # Wait for server terminate response and verify tag — max 3 attempts
    for _ in range(3):
        inc = configurator_receive(cfg, 1000)
        if not inc:
            continue
        if inc.msg_type != SPSEC_MSGTYPE_SERVER_TERMINATE:
            continue
        # Validate tag similarly
        resp: SPsecSessionTerminateMessage = inc.msg_content  # type: ignore
        if resp.pid != target_pid:
            continue
        cfg.session_cnt += 1
        if (resp.cnt & 0xFF) != (cfg.session_cnt & 0xFF):
            _clear_session(cfg)
            return -8
        resp_cnt_lsb = resp.cnt & 0xFF
        resp_addr_cnt_lsb = (resp.address >> 16) & 0xFF
        log_info("conf_session_management", "Terminate response: cnt=%u (lsb=%u), addr=%08x (lsb=%u)", resp.cnt, resp_cnt_lsb, resp.address, resp_addr_cnt_lsb)
        nonce2 = generate_nonce_from_session_cnt(cfg.session_cnt, cfg.session_auth_tag_data.spsec_salt)
        tag2 = compute_tag_only(bytes(cfg.session_key), nonce2, resp.address.to_bytes(4, "little"), AUTH_TAG_SIZE, cfg.algorithm)
        log_array(LOG_LEVEL_DEBUG, "conf_session_management", "Terminate response nonce:", nonce2, len(nonce2))
        log_array(LOG_LEVEL_DEBUG, "conf_session_management", "Terminate response assoc (addr LE):", resp.address.to_bytes(4, "little"), 4)
        log_array(LOG_LEVEL_DEBUG, "conf_session_management", "Terminate response auth tag (computed):", tag2, len(tag2))
        log_array(LOG_LEVEL_DEBUG, "conf_session_management", "Terminate response auth tag (received):", resp.auth_tag, len(resp.auth_tag))
        if not hmac.compare_digest(bytes(tag2), bytes(resp.auth_tag)):
            _clear_session(cfg)
            return -3
        _clear_session(cfg)
        return 0
    # Timed out waiting for terminate response — session is dead on device side
    log_info("conf_session_management", "Terminate timed out (no response from PID %d) — treating as closed", target_pid)
    _clear_session(cfg)
    return -6


def configurator_factory_reset(cfg: Configurator, target_pid: int, legacy: bool = False) -> int:
    """Manufacturer Reset (SPsec302 §2.3.4): write magic 0x1D04E5E1 to reg 0x7F
    in an Integrator session. legacy=True zero-writes keys via Provisioning session instead."""
    if legacy:
        log_info("configurator", "Starting legacy factory reset (zero-write keys) for PID %d", target_pid)
        ret = configurator_start_session(cfg, target_pid, SPSEC_KEY_SELECTOR_PROVISIONING_KEY, SESSION_TIMEOUT_S)
        if ret < 0:
            log_error("configurator", "Failed to start provisioning session for legacy factory reset: %d", ret)
            return ret
        try:
            zero_key = bytes(KEY_LEN)
            zero_salt = bytes(SALT_LEN)
            zero_key_id = bytes(4)
            
            for reg, data, dlen in [
                (SPSEC_REG_PROVISIONING_KEY, zero_key, KEY_LEN),
                (SPSEC_REG_INTEGRATOR_KEY, zero_key, KEY_LEN),
                (SPSEC_REG_SEED_KEY, zero_key, KEY_LEN),
                (SPSEC_REG_PROVISIONING_KEY_SALT, zero_salt, SALT_LEN),
                (SPSEC_REG_INTEGRATOR_KEY_SALT, zero_salt, SALT_LEN),
                (SPSEC_REG_SEED_KEY_SALT, zero_salt, SALT_LEN),
                (SPSEC_REG_PROVISIONING_KEY_ID, zero_key_id, 4),
                (SPSEC_REG_INTEGRATOR_KEY_ID, zero_key_id, 4),
                (SPSEC_REG_SEED_KEY_ID, zero_key_id, 4),
            ]:
                res = configurator_write_register(cfg, target_pid, reg, data, dlen)
                if res < 0:
                    log_error("configurator", "Failed legacy reset write to reg 0x%02X: %d", reg, res)
                    return res
            log_info("configurator", "Legacy factory reset completed successfully for PID %d", target_pid)
            return 0
        finally:
            configurator_terminate_session(cfg, target_pid)

    log_info("configurator", "Starting spec Manufacturer Reset (0x7F magic write) for PID %d", target_pid)
    
    # Establish session using Integrator Key (Key Selector 14) per SPsec302 §2.3.4
    ret = configurator_start_session(cfg, target_pid, SPSEC_KEY_SELECTOR_INTEGRATOR_KEY, SESSION_TIMEOUT_S)
    if ret < 0:
        log_error("configurator", "Failed to start Integrator session for manufacturer reset: %d", ret)
        return ret
    
    try:
        # Write magic 0x1D04E5E1 to reg 0x7F; needs an Integrator-Key session
        # (see spsec_participant/register_write_segment.c:344-375).
        ret = configurator_write_register(
            cfg, target_pid, SPSEC_REG_MANUFACTURER_RESET, SPSEC_MANUFACTURER_RESET_MAGIC, 4
        )
        if ret < 0:
            log_error("configurator", "Failed to write Manufacturer Reset magic to register 0x7F: %d", ret)
            return ret
        
        log_info("configurator", "Manufacturer Reset (0x7F) completed successfully for PID %d", target_pid)
        return 0
    finally:
        configurator_terminate_session(cfg, target_pid)


def configurator_bootstrap_device(
    cfg: Configurator,
    target_pid: int,
    integrator_key: bytes,
    integrator_salt: bytes,
    integrator_key_id: int,
    seed_key: bytes,
    seed_salt: bytes,
    seed_key_id: int,
) -> int:
    """Provision a fresh device: open a provisioning-key session, write the
    integrator and seed keys/salts/IDs, then verify by reading status back."""


    if len(integrator_key) != KEY_LEN or len(seed_key) != KEY_LEN:
        log_error("configurator", "Invalid key length")
        return -1
    if len(integrator_salt) < SALT_LEN or len(seed_salt) < SALT_LEN:
        log_error("configurator", "Invalid salt length")
        return -1
    if len(integrator_salt) > SALT_LEN:
        log_warning(
            "configurator",
            "Integrator salt is %d bytes, truncating to %d bytes",
            len(integrator_salt), SALT_LEN,
        )
        integrator_salt = integrator_salt[:SALT_LEN]
    if len(seed_salt) > SALT_LEN:
        log_warning(
            "configurator",
            "Seed salt is %d bytes, truncating to %d bytes",
            len(seed_salt), SALT_LEN,
        )
        seed_salt = seed_salt[:SALT_LEN]
    
    log_info("configurator", "Starting bootstrap for PID %d", target_pid)
    
    # Step 1: Start session using provisioning key
    ret = configurator_start_session(cfg, target_pid, SPSEC_KEY_SELECTORS[1], SESSION_TIMEOUT_S)  # provisioning
    if ret < 0:
        log_error("configurator", "Failed to start provisioning session: %d", ret)
        return ret
    
    try:
        # Step 2: Provision integrator key (first invalidate Key ID with 0xFFFFFFFF)
        log_info("configurator", "Provisioning integrator key...")
        invalid_key_id_bytes = b"\xFF\xFF\xFF\xFF"
        ret = configurator_write_register(cfg, target_pid, SPSEC_REG_INTEGRATOR_KEY_ID, invalid_key_id_bytes, 4)
        if ret < 0:
            log_error("configurator", "Failed to invalidate integrator key ID: %d", ret)
            return ret

        ret = configurator_write_register(cfg, target_pid, SPSEC_REG_INTEGRATOR_KEY, integrator_key, KEY_LEN)
        if ret < 0:
            log_error("configurator", "Failed to write integrator key: %d", ret)
            return ret

        # Step 3: Provision integrator salt
        ret = configurator_write_register(cfg, target_pid, SPSEC_REG_INTEGRATOR_KEY_SALT, integrator_salt, SALT_LEN)
        if ret < 0:
            log_error("configurator", "Failed to write integrator salt: %d", ret)
            return ret

        # Step 4: Provision integrator key ID
        integrator_key_id_bytes = integrator_key_id.to_bytes(4, "little")
        ret = configurator_write_register(cfg, target_pid, SPSEC_REG_INTEGRATOR_KEY_ID, integrator_key_id_bytes, 4)
        if ret < 0:
            log_error("configurator", "Failed to write integrator key ID: %d", ret)
            return ret

        # Step 5: Terminate Provisioning session and start Integrator session to write Seed key
        log_info("configurator", "Terminating Provisioning session to establish Integrator session for Seed key")
        configurator_terminate_session(cfg, target_pid)
        ret = configurator_start_session(cfg, target_pid, SPSEC_KEY_SELECTOR_INTEGRATOR_KEY, SESSION_TIMEOUT_S)
        if ret < 0:
            log_error("configurator", "Failed to start Integrator session for Seed key: %d", ret)
            return ret

        # Step 6: Provision seed key (first invalidate Key ID with 0xFFFFFFFF)
        log_info("configurator", "Provisioning seed key...")
        ret = configurator_write_register(cfg, target_pid, SPSEC_REG_SEED_KEY_ID, invalid_key_id_bytes, 4)
        if ret < 0:
            log_error("configurator", "Failed to invalidate seed key ID: %d", ret)
            return ret

        ret = configurator_write_register(cfg, target_pid, SPSEC_REG_SEED_KEY, seed_key, KEY_LEN)
        if ret < 0:
            log_error("configurator", "Failed to write seed key: %d", ret)
            return ret
        
        # Step 7: Provision seed salt
        ret = configurator_write_register(cfg, target_pid, SPSEC_REG_SEED_KEY_SALT, seed_salt, SALT_LEN)
        if ret < 0:
            log_error("configurator", "Failed to write seed salt: %d", ret)
            return ret
        
        # Step 8: Provision seed key ID
        seed_key_id_bytes = seed_key_id.to_bytes(4, "little")
        ret = configurator_write_register(cfg, target_pid, SPSEC_REG_SEED_KEY_ID, seed_key_id_bytes, 4)
        if ret < 0:
            log_error("configurator", "Failed to write seed key ID: %d", ret)
            return ret
        
        # Step 8: Verify by reading status
        log_info("configurator", "Verifying bootstrap...")
        status_buf = bytearray(1)
        ret = configurator_read_register(cfg, target_pid, SPSEC_REG_STATUS, status_buf, 1)
        if ret < 0:
            log_error("configurator", "Failed to read status for verification: %d", ret)
            return ret
        
        log_info("configurator", "Bootstrap completed successfully for PID %d (status: 0x%02X)", target_pid, status_buf[0])
        return 0
    finally:
        configurator_terminate_session(cfg, target_pid)


def configurator_establish_keys_sequential(
    cfg: Configurator,
    target_pid: int,
    initial_key_selector: int,
    provisioning_key: Optional[bytes] = None,
    provisioning_salt: Optional[bytes] = None,
    provisioning_key_id: Optional[int] = None,
    integrator_key: Optional[bytes] = None,
    integrator_salt: Optional[bytes] = None,
    integrator_key_id: Optional[int] = None,
    seed_key: Optional[bytes] = None,
    seed_salt: Optional[bytes] = None,
    seed_key_id: Optional[int] = None,
) -> int:
    """Write keys one at a time up the ladder from initial_key_selector
    (Zero->Prov->Integrator->Seed); provisioning_* args only needed from Zero."""

    
    # Key sequence mapping: {initial_key: [keys_to_write]}
    KEY_SEQUENCE = {
        SPSEC_KEY_SELECTOR_ZERO_KEY: [SPSEC_KEY_SELECTOR_INTEGRATOR_KEY, SPSEC_KEY_SELECTOR_SEED_KEY],  # Zero → Integrator → Seed (when no Prov Key)
        SPSEC_KEY_SELECTOR_PROVISIONING_KEY: [SPSEC_KEY_SELECTOR_INTEGRATOR_KEY, SPSEC_KEY_SELECTOR_SEED_KEY],     # Provisioning → Integrator → Seed
        SPSEC_KEY_SELECTOR_INTEGRATOR_KEY: [SPSEC_KEY_SELECTOR_SEED_KEY],         # Integrator → Seed
        # No Seed entry: the Seed key cannot open a configuration session
        # (SPsec201 §2.4, REQ-PART-025), so it is never a valid starting rung.
    }
    
    # Key selector to register mapping
    KEY_REG_MAP = {
        SPSEC_KEY_SELECTOR_PROVISIONING_KEY: (SPSEC_REG_PROVISIONING_KEY, SPSEC_REG_PROVISIONING_KEY_SALT, SPSEC_REG_PROVISIONING_KEY_ID),
        SPSEC_KEY_SELECTOR_INTEGRATOR_KEY: (SPSEC_REG_INTEGRATOR_KEY, SPSEC_REG_INTEGRATOR_KEY_SALT, SPSEC_REG_INTEGRATOR_KEY_ID),
        SPSEC_KEY_SELECTOR_SEED_KEY: (SPSEC_REG_SEED_KEY, SPSEC_REG_SEED_KEY_SALT, SPSEC_REG_SEED_KEY_ID),
    }
    
    # Key selector to name mapping
    KEY_NAME_MAP = {
        SPSEC_KEY_SELECTOR_ZERO_KEY: "Zero",
        SPSEC_KEY_SELECTOR_PROVISIONING_KEY: "Provisioning",
        SPSEC_KEY_SELECTOR_INTEGRATOR_KEY: "Integrator",
        SPSEC_KEY_SELECTOR_SEED_KEY: "Seed",
    }
    
    # Validate initial key selector
    if initial_key_selector not in KEY_SEQUENCE:
        log_error("configurator", "Invalid initial key selector: %d", initial_key_selector)
        return -1
    
    keys_to_write = KEY_SEQUENCE[initial_key_selector]
    if not keys_to_write:
        log_info("configurator", "No keys to write (starting from Seed key)")
        return 0
    
    log_info("configurator", "Starting sequential key establishment for PID %d with initial key: %s (%d)",
             target_pid, KEY_NAME_MAP.get(initial_key_selector, "Unknown"), initial_key_selector)
    
    # Validate required keys
    if SPSEC_KEY_SELECTOR_PROVISIONING_KEY in keys_to_write:
        if not provisioning_key or not provisioning_salt or provisioning_key_id is None:
            log_error("configurator", "Provisioning key data required but not provided")
            return -2
        if len(provisioning_key) != KEY_LEN or len(provisioning_salt) < SALT_LEN:
            log_error("configurator", "Invalid provisioning key/salt length")
            return -2
        if len(provisioning_salt) > SALT_LEN:
            provisioning_salt = provisioning_salt[:SALT_LEN]
    
    if SPSEC_KEY_SELECTOR_INTEGRATOR_KEY in keys_to_write or SPSEC_KEY_SELECTOR_SEED_KEY in keys_to_write:
        if not integrator_key or not integrator_salt or integrator_key_id is None:
            log_error("configurator", "Integrator key data required but not provided")
            return -2
        if len(integrator_key) != KEY_LEN or len(integrator_salt) < SALT_LEN:
            log_error("configurator", "Invalid integrator key/salt length")
            return -2
        if len(integrator_salt) > SALT_LEN:
            integrator_salt = integrator_salt[:SALT_LEN]
    
    if SPSEC_KEY_SELECTOR_SEED_KEY in keys_to_write:
        if not seed_key or not seed_salt or seed_key_id is None:
            log_error("configurator", "Seed key data required but not provided")
            return -2
        if len(seed_key) != KEY_LEN or len(seed_salt) < SALT_LEN:
            log_error("configurator", "Invalid seed key/salt length")
            return -2
        if len(seed_salt) > SALT_LEN:
            seed_salt = seed_salt[:SALT_LEN]
    
    # Start with initial session
    current_key_selector = initial_key_selector
    log_info("configurator", "Starting initial session with key selector %d (%s)",
             current_key_selector, KEY_NAME_MAP.get(current_key_selector, "Unknown"))
    
    ret = configurator_start_session(cfg, target_pid, current_key_selector, SESSION_TIMEOUT_S)
    if ret < 0:
        log_error("configurator", "Failed to start initial session with key %d: %d", current_key_selector, ret)
        return ret
    
    try:
        # Write each key in sequence
        for key_selector in keys_to_write:
            key_name = KEY_NAME_MAP.get(key_selector, f"Key {key_selector}")
            reg_key, reg_salt, reg_key_id = KEY_REG_MAP[key_selector]
            
            # Get key data based on selector
            if key_selector == SPSEC_KEY_SELECTOR_PROVISIONING_KEY:
                key_data = provisioning_key
                salt_data = provisioning_salt
                key_id_value = provisioning_key_id
            elif key_selector == SPSEC_KEY_SELECTOR_INTEGRATOR_KEY:
                key_data = integrator_key
                salt_data = integrator_salt
                key_id_value = integrator_key_id
            elif key_selector == SPSEC_KEY_SELECTOR_SEED_KEY:
                key_data = seed_key
                salt_data = seed_salt
                key_id_value = seed_key_id
            else:
                log_error("configurator", "Unknown key selector: %d", key_selector)
                return -3
            
            log_info("configurator", "Writing %s key (selector %d)...", key_name, key_selector)

            # Invalidate key ID first per SPsec302 §2.3.1 (write 0xFFFFFFFF)
            invalid_key_id_bytes = b"\xFF\xFF\xFF\xFF"
            ret = configurator_write_register(cfg, target_pid, reg_key_id, invalid_key_id_bytes, 4)
            if ret < 0:
                log_error("configurator", "Failed to invalidate %s key ID: %d", key_name, ret)
                return ret

            # Write key
            ret = configurator_write_register(cfg, target_pid, reg_key, key_data, KEY_LEN)
            if ret < 0:
                log_error("configurator", "Failed to write %s key: %d", key_name, ret)
                return ret
            
            # Write salt
            ret = configurator_write_register(cfg, target_pid, reg_salt, salt_data, SALT_LEN)
            if ret < 0:
                log_error("configurator", "Failed to write %s salt: %d", key_name, ret)
                return ret
            
            # Write key ID
            key_id_bytes = key_id_value.to_bytes(4, "little")
            ret = configurator_write_register(cfg, target_pid, reg_key_id, key_id_bytes, 4)
            if ret < 0:
                log_error("configurator", "Failed to write %s key ID: %d", key_name, ret)
                return ret
            
            log_info("configurator", "Successfully wrote %s key, salt, and key ID", key_name)
            
            # If this is not the last key, terminate session and start new one with this key
            if key_selector != keys_to_write[-1]:
                log_info("configurator", "Terminating session to establish new session with %s key", key_name)
                configurator_terminate_session(cfg, target_pid)
                
                # Start new session using the newly written key
                current_key_selector = key_selector
                log_info("configurator", "Starting new session with %s key (selector %d)",
                         key_name, current_key_selector)
                ret = configurator_start_session(cfg, target_pid, current_key_selector, SESSION_TIMEOUT_S)
                if ret < 0:
                    log_error("configurator", "Failed to start session with %s key: %d", key_name, ret)
                    return ret
        
        # Verify by reading status
        log_info("configurator", "Verifying key establishment...")
        status_buf = bytearray(1)
        ret = configurator_read_register(cfg, target_pid, SPSEC_REG_STATUS, status_buf, 1)
        if ret < 0:
            log_error("configurator", "Failed to read status for verification: %d", ret)
            return ret
        
        log_info("configurator", "Sequential key establishment completed successfully for PID %d (status: 0x%02X)",
                 target_pid, status_buf[0])
        return 0
        
    finally:
        configurator_terminate_session(cfg, target_pid)


