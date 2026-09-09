# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

import sys
import time


LOG_LEVEL_DEBUG = 10
LOG_LEVEL_INFO = 20
LOG_LEVEL_WARNING = 30
LOG_LEVEL_ERROR = 40
LOG_LEVEL_CRITICAL = 50


current_log_level = LOG_LEVEL_INFO


def configure_logging(level: str) -> None:
    global current_log_level
    mapping = {
        "DEBUG": LOG_LEVEL_DEBUG,
        "INFO": LOG_LEVEL_INFO,
        "WARNING": LOG_LEVEL_WARNING,
        "ERROR": LOG_LEVEL_ERROR,
        "CRITICAL": LOG_LEVEL_CRITICAL,
    }
    current_log_level = mapping.get(level.upper(), LOG_LEVEL_INFO)


def _ts_prefix(level_name: str, name: str) -> str:
    # Format like: 13:10:20.919034 - INFO - component -
    t = time.time()
    lt = time.localtime(t)
    frac = int((t - int(t)) * 1_000_000)
    ts = time.strftime("%H:%M:%S", lt) + f".{frac:06d}"
    return f"{ts} - {level_name} - {name} - "


def _log(level: int, name: str, msg: str, *args) -> None:
    if level < current_log_level:
        return
    level_name = {
        LOG_LEVEL_DEBUG: "DEBUG",
        LOG_LEVEL_INFO: "INFO",
        LOG_LEVEL_WARNING: "WARNING",
        LOG_LEVEL_ERROR: "ERROR",
        LOG_LEVEL_CRITICAL: "CRITICAL",
    }.get(level, "INFO")
    prefix = _ts_prefix(level_name, name)
    try:
        # Convert Path objects and other types to strings for safe formatting
        if args:
            safe_args = tuple(str(arg) if not isinstance(arg, (int, float, str)) else arg for arg in args)
            text = msg % safe_args
        else:
            text = msg
    except Exception:
        text = f"{msg} | args={args}"
    sys.stdout.write(prefix + text + "\n")
    sys.stdout.flush()


def log_debug(name: str, msg: str, *args) -> None:
    _log(LOG_LEVEL_DEBUG, name, msg, *args)


def log_info(name: str, msg: str, *args) -> None:
    _log(LOG_LEVEL_INFO, name, msg, *args)


def log_warning(name: str, msg: str, *args) -> None:
    _log(LOG_LEVEL_WARNING, name, msg, *args)


def log_error(name: str, msg: str, *args) -> None:
    _log(LOG_LEVEL_ERROR, name, msg, *args)


def log_critical(name: str, msg: str, *args) -> None:
    _log(LOG_LEVEL_CRITICAL, name, msg, *args)


def log_array(level: int, name: str, label: str, data, length: int = None) -> None:
    if level < current_log_level:
        return
    if data is None:
        log_debug(name, "%s: <None>", label)
        return
    if isinstance(data, (bytes, bytearray)):
        b = data
    else:
        b = bytes(data)
    if length is not None:
        b = b[:length]
    hexs = " ".join(f"{x:02X}" for x in b)
    _log(level, name, "%s: [%s]", label, hexs)


