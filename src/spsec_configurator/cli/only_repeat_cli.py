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
import csv
import os
import sys
import time
from datetime import datetime, timezone
import threading
import re
from typing import Optional

try:
    import serial  # type: ignore
except Exception:  # noqa: BLE001
    serial = None  # Loaded lazily; error if user enables serial and module missing

from ..core.logging_util import configure_logging, log_info, log_error
from ..core.spsec_definitions import SESSION_TIMEOUT_S, SPSEC_KEY_SELECTORS
from ..core.configurator import (
    configurator_init,
    configurator_destroy,
    configurator_start_session,
    configurator_write_key,
    configurator_write_salt,
    configurator_write_key_id,
    configurator_terminate_session,
)


def _ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_one_provision_cycle(cfg, pid: int) -> int:
    # Mirrors the legacy demo block in cli.py lines ~97-104
    for i in range(0, 3):
        ret = configurator_start_session(cfg, pid, SPSEC_KEY_SELECTORS[i], SESSION_TIMEOUT_S)
        if ret < 0:
            return ret
        try:
            ret = configurator_write_key(cfg, pid, i + 1)
            if ret < 0:
                return ret
            ret = configurator_write_salt(cfg, pid, i + 1)
            if ret < 0:
                return ret
            ret = configurator_write_key_id(cfg, pid, i + 1)
            if ret < 0:
                return ret
        finally:
            configurator_terminate_session(cfg, pid)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(description="Repeat provisioning block and record timing stats")
    p.add_argument("-i", "--interface", default="vcan0")
    p.add_argument("-p", "--pid", type=int, required=True)
    p.add_argument("-k", "--keys_file", default="keys.txt")
    p.add_argument("-l", "--log-level", default="DEBUG")
    p.add_argument("-d", "--tx-delay-us", type=int, default=0)
    p.add_argument("-n", "--repeats", type=int, required=True)
    p.add_argument(
        "-o",
        "--out",
        default="repeat_stats.csv",
        help="CSV file to write per-iteration stats",
    )
    p.add_argument(
        "--append",
        action="store_true",
        help="Append to output CSV instead of overwriting",
    )
    p.add_argument(
        "--repeat-delay-ms",
        type=int,
        default=0,
        help="Delay between repeats in milliseconds",
    )
    # Serial logging options
    p.add_argument(
        "--serial-port",
        help="Serial port (e.g., /dev/ttyUSB0) to read participant logs. If unset, serial reading is disabled.",
    )
    p.add_argument(
        "--serial-baud",
        type=int,
        default=115200,
        help="Serial baud rate (default: 115200)",
    )
    p.add_argument(
        "--serial-tick-hz",
        type=float,
        default=1_000_000.0,
        help="Hardware tick frequency in Hz for projecting ticks to real UTC time (default: 1e6)",
    )
    p.add_argument(
        "--serial-out",
        default="serial_logs.csv",
        help="CSV file to write projected serial logs (UTC aligned)",
    )
    args = p.parse_args(argv)

    configure_logging(args.log_level)

    _ensure_parent_dir(args.out)
    if args.serial_port:
        _ensure_parent_dir(args.serial_out)

    write_header = True
    if args.append and os.path.exists(args.out):
        write_header = False

    cfg = configurator_init(args.interface, args.keys_file)
    cfg.tx_delay_us = max(0, int(args.tx_delay_us))

    durations_ms: list[float] = []
    successes = 0
    failures = 0

    # --- Serial logging thread setup ---
    stop_event = threading.Event()
    serial_thread: Optional[threading.Thread] = None
    if args.serial_port:
        if serial is None:
            log_error("repeat", "pyserial is required but not installed. pip install pyserial")
            return 2

        def _serial_reader(port: str, baud: int, tick_hz: float, out_path: str, stop: threading.Event) -> None:
            # Pattern: 0x<hex> - LEVEL - component - message
            tick_re = re.compile(r"^0x([0-9a-fA-F]+)\s+-\s+([A-Z]+)\s+-\s+([^\-]+)\s+-\s+(.*)$")
            anchor_tick: Optional[int] = None
            anchor_real_ns: Optional[int] = None
            last_tick: Optional[int] = None
            wrap_offset: int = 0
            try:
                with serial.Serial(port=port, baudrate=baud, timeout=0.2) as ser, open(out_path, "a" if args.append else "w", newline="") as sf:
                    writer = csv.writer(sf)
                    # Write header if not appending or file empty
                    if not args.append or os.stat(out_path).st_size == 0:
                        writer.writerow(["iso_utc", "tick_hex", "tick", "delta_ms", "level", "component", "message"])
                        sf.flush()

                    # Internal helper to project tick to UTC iso string
                    def project_tick(now_ns: int, tick_val: int) -> tuple[str, float]:
                        nonlocal anchor_tick, anchor_real_ns
                        if anchor_tick is None or anchor_real_ns is None:
                            anchor_tick = tick_val
                            anchor_real_ns = now_ns
                            iso = datetime.fromtimestamp(anchor_real_ns / 1_000_000_000.0, tz=timezone.utc).isoformat()
                            return iso, 0.0
                        dt_ticks = tick_val - anchor_tick
                        dt_sec = dt_ticks / tick_hz
                        ts_ns = anchor_real_ns + int(dt_sec * 1_000_000_000)
                        iso = datetime.fromtimestamp(ts_ns / 1_000_000_000.0, tz=timezone.utc).isoformat()
                        return iso, dt_sec * 1000.0

                    buf = bytearray()
                    while not stop.is_set():
                        try:
                            data = ser.readline()  # type: ignore[attr-defined]
                        except Exception:
                            # Attempt to continue; small backoff
                            time.sleep(0.05)
                            continue
                        if not data:
                            continue
                        now_ns = time.time_ns()
                        try:
                            line = data.decode(errors="replace").strip()
                        except Exception:
                            line = str(bytes(data))
                        m = tick_re.match(line)
                        if not m:
                            # Write raw line with no parsed fields
                            writer.writerow([_iso_now(), "", "", "", "", "", line])
                            sf.flush()
                            continue
                        tick_raw = m.group(1)
                        level = m.group(2)
                        component = m.group(3).strip()
                        message = m.group(4)
                        try:
                            tick_val = int(tick_raw, 16)
                        except Exception:
                            writer.writerow([_iso_now(), f"0x{tick_raw}", "", "", level, component, message])
                            sf.flush()
                            continue

                        # Handle potential wrap (unlikely for 64-bit within a session)
                        if last_tick is not None and tick_val < last_tick:
                            # If huge backward jump, assume wrap at 2^64
                            if last_tick - tick_val > (tick_hz * 10):  # heuristic
                                wrap_offset += 1 << 64
                        logical_tick = tick_val + wrap_offset
                        last_tick = tick_val

                        iso, delta_ms = project_tick(now_ns, logical_tick)
                        writer.writerow([iso, f"0x{tick_val:016x}", logical_tick, f"{delta_ms:.3f}", level, component, message])
                        sf.flush()
            except Exception as ex:  # noqa: BLE001
                log_error("repeat", "Serial reader error: %s", ex)

        serial_thread = threading.Thread(
            target=_serial_reader,
            args=(args.serial_port, int(args.serial_baud), float(args.serial_tick_hz), args.serial_out, stop_event),
            name="serial-log-reader",
            daemon=True,
        )
        serial_thread.start()

    try:
        with open(args.out, "a" if args.append else "w", newline="") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow([
                    "iteration",
                    "start_iso_utc",
                    "end_iso_utc",
                    "duration_ms",
                    "status",
                    "ret_code",
                ])

            for iteration in range(1, args.repeats + 1):
                start_iso = _iso_now()
                t0 = time.perf_counter_ns()
                ret_code = 0
                status = "ok"
                try:
                    ret_code = _run_one_provision_cycle(cfg, args.pid)
                    if ret_code < 0:
                        status = "fail"
                except Exception as ex:  # noqa: BLE001
                    log_error("repeat", "Exception during cycle %d: %s", iteration, ex)
                    status = "exception"
                    ret_code = -9999
                t1 = time.perf_counter_ns()
                end_iso = _iso_now()
                duration_ms = (t1 - t0) / 1_000_000.0
                writer.writerow([iteration, start_iso, end_iso, f"{duration_ms:.3f}", status, ret_code])
                if status == "ok":
                    successes += 1
                    durations_ms.append(duration_ms)
                else:
                    failures += 1

                # Optional delay between repeats (not after the last iteration)
                if iteration < args.repeats and args.repeat_delay_ms > 0:
                    time.sleep(max(0, args.repeat_delay_ms) / 1000.0)

            # Summary row(s)
            total = successes + failures
            avg_ms = (sum(durations_ms) / len(durations_ms)) if durations_ms else 0.0
            min_ms = min(durations_ms) if durations_ms else 0.0
            max_ms = max(durations_ms) if durations_ms else 0.0
            writer.writerow([])
            writer.writerow(["summary", "", "", "", "", ""])
            writer.writerow(["total_iterations", total, "", "", "", ""]) 
            writer.writerow(["successes", successes, "", "", "", ""]) 
            writer.writerow(["failures", failures, "", "", "", ""]) 
            writer.writerow(["avg_duration_ms", f"{avg_ms:.3f}", "", "", "", ""]) 
            writer.writerow(["min_duration_ms", f"{min_ms:.3f}", "", "", "", ""]) 
            writer.writerow(["max_duration_ms", f"{max_ms:.3f}", "", "", "", ""]) 

        log_info(
            "repeat",
            "Completed %d iterations: %d ok, %d failed. Avg %.3f ms (min %.3f, max %.3f). CSV: %s",
            successes + failures,
            successes,
            failures,
            (sum(durations_ms) / len(durations_ms)) if durations_ms else 0.0,
            min(durations_ms) if durations_ms else 0.0,
            max(durations_ms) if durations_ms else 0.0,
            os.path.abspath(args.out),
        )
        return 0 if failures == 0 else 1
    finally:
        if stop_event is not None:
            stop_event.set()
        if serial_thread is not None:
            try:
                serial_thread.join(timeout=2.0)
            except Exception:
                pass
        configurator_destroy(cfg)


if __name__ == "__main__":
    raise SystemExit(main())


