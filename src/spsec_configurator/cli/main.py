# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

from __future__ import annotations

import argparse
import sys

from ..core.logging_util import configure_logging, log_info, log_error
from ..core.spsec_definitions import (
    SESSION_TIMEOUT_S,
    SESSION_KEY_SELECTORS,
    SPSEC_REG_SECURE_HEARTBEAT_MONITOR,
    SPSEC_REG_STATUS,
    SPSEC_REG_LAST_SECURITY_EVENT,
    SPSEC_REG_CORE_VERSION_INFO,
    SPSEC_REG_MAPPING_VERSION_INFO,
    SPSEC_KEY_SELECTOR_ZERO_KEY,
    SPSEC_KEY_SELECTOR_PROVISIONING_KEY,
    SPSEC_KEY_SELECTOR_INTEGRATOR_KEY,
)
from ..core.crypto import CryptoAlgorithm
from ..core.configurator import (
    configurator_init,
    configurator_destroy,
    configurator_start_session,
    configurator_read_register,
    configurator_write_register,
    configurator_write_key,
    configurator_write_salt,
    configurator_write_key_id,
    configurator_terminate_session,
    configurator_establish_keys_sequential,
)


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser()
    p.add_argument("-i", "--interface", default="vcan0")
    p.add_argument("-p", "--pid", type=int, required=True)
    # Key selector index: 0=Zero, 1=Provisioning, 2=Integrator
    p.add_argument("-s", "--key", type=int, default=0,
                   choices=range(len(SESSION_KEY_SELECTORS)),
                   help="Session key: 0=Zero, 1=Provisioning, 2=Integrator "
                        "(default: 0). The Seed key cannot open a session.")
    p.add_argument("-k", "--keys_file", default="keys.txt")
    p.add_argument("-l", "--log-level", default="DEBUG")
    p.add_argument("-d", "--tx-delay-us", type=int, default=0)
    p.add_argument("-S", "--start-session", action="store_true")
    p.add_argument("-M", "--hb-monitor")
    p.add_argument("-R", "--read-info", action="store_true")
    algo_group = p.add_mutually_exclusive_group()
    algo_group.add_argument("--ascon", action="store_const", const=CryptoAlgorithm.CRYPTO_ALGO_ASCON128, dest="algorithm", help="Use ASCON-128 algorithm")
    algo_group.add_argument("--chacha", action="store_const", const=CryptoAlgorithm.CRYPTO_ALGO_CHACHA20_POLY1305, dest="algorithm", help="Use ChaCha20-Poly1305 algorithm")
    args = p.parse_args(argv)

    configure_logging(args.log_level)

    cfg = configurator_init(args.interface, args.keys_file, algorithm=getattr(args, 'algorithm', None))
    cfg.tx_delay_us = max(0, int(args.tx_delay_us))

    try:
        if args.read_info:
            ks_value = SESSION_KEY_SELECTORS[args.key]
            ret = configurator_start_session(cfg, args.pid, ks_value, SESSION_TIMEOUT_S)
            if ret < 0:
                log_error("cli", "Failed to start session: %d", ret)
                return -1
            # 50h
            buf = bytearray(1)
            ret = configurator_read_register(cfg, args.pid, SPSEC_REG_STATUS, buf, 1)
            if ret == 0:
                state = buf[0] & 0x0F
                alert = 1 if (buf[0] & 0x80) else 0
                log_info("cli", "SPsec Status (50h): state=0x%02X, alert=%d", state, alert)
            # 51h
            buf2 = bytearray(2)
            ret = configurator_read_register(cfg, args.pid, SPSEC_REG_LAST_SECURITY_EVENT, buf2, 2)
            if ret == 0:
                evt = buf2[0] | (buf2[1] << 8)
                log_info("cli", "Last Security Event (51h): 0x%04X", evt)
            # 58h
            core = bytearray(16)
            ret = configurator_read_register(cfg, args.pid, SPSEC_REG_CORE_VERSION_INFO, core, 16)
            if ret == 0:
                s = bytes(core).split(b"\x00", 1)[0].decode(errors="ignore")
                log_info("cli", "Core Version (58h): %s", s)
            # 59h
            m = bytearray(16)
            ret = configurator_read_register(cfg, args.pid, SPSEC_REG_MAPPING_VERSION_INFO, m, 16)
            if ret == 0:
                s2 = bytes(m).split(b"\x00", 1)[0].decode(errors="ignore")
                log_info("cli", "Mapping Version (59h): %s", s2)

            configurator_terminate_session(cfg, args.pid)
            return 0

        if args.start_session or args.hb_monitor:
            ks_value = SESSION_KEY_SELECTORS[args.key]
            ret = configurator_start_session(cfg, args.pid, ks_value, SESSION_TIMEOUT_S)
            if ret < 0:
                log_error("cli", "Failed to start session: %d", ret)
                return -1
            if args.hb_monitor:
                parts = [x.strip() for x in args.hb_monitor.split(",") if x.strip()]
                if len(parts) > 4:
                    parts = parts[:4]
                hb_bytes = bytearray(4)
                for i, s in enumerate(parts):
                    hb_bytes[i] = int(s, 0) & 0xFF
                ret = configurator_write_register(cfg, args.pid, SPSEC_REG_SECURE_HEARTBEAT_MONITOR, hb_bytes, 4)
                if ret < 0:
                    log_error("cli", "Failed to write HB monitor: %d", ret)
                    return -1
            configurator_terminate_session(cfg, args.pid)
            return 0

        # Sequential key establishment
        ret = configurator_establish_keys_sequential(
            cfg, args.pid, SESSION_KEY_SELECTORS[args.key],
            provisioning_key=cfg.comm_keys.spsec_keys[1].key if cfg.comm_keys.spsec_keys[1] else None,
            provisioning_salt=cfg.comm_keys.spsec_salt[1].salt if cfg.comm_keys.spsec_salt[1] else None,
            provisioning_key_id=cfg.comm_keys.spsec_keys[1].key_id if cfg.comm_keys.spsec_keys[1] else None,
            integrator_key=cfg.comm_keys.spsec_keys[2].key if cfg.comm_keys.spsec_keys[2] else None,
            integrator_salt=cfg.comm_keys.spsec_salt[2].salt if cfg.comm_keys.spsec_salt[2] else None,
            integrator_key_id=cfg.comm_keys.spsec_keys[2].key_id if cfg.comm_keys.spsec_keys[2] else None,
            seed_key=cfg.comm_keys.spsec_keys[3].key if cfg.comm_keys.spsec_keys[3] else None,
            seed_salt=cfg.comm_keys.spsec_salt[3].salt if cfg.comm_keys.spsec_salt[3] else None,
            seed_key_id=cfg.comm_keys.spsec_keys[3].key_id if cfg.comm_keys.spsec_keys[3] else None,
        )
        return ret
    finally:
        log_info("cli", "Configurator finished")
        configurator_destroy(cfg)


if __name__ == "__main__":
    raise SystemExit(main())


