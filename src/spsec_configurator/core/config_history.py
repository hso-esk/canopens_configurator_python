# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Versioned history/rollback for groups_config.json (§14.3): every mutation
is archived first (0600, `<config>.history/`) so a bad rollout is a file copy away."""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .logging_util import log_info, log_error, log_warning

DEFAULT_KEEP = 20
_STAMP_FORMAT = "%Y%m%dT%H%M%S%f"


def history_dir(config_file: str | Path) -> Path:
    """Directory holding the snapshots for `config_file`."""
    path = Path(config_file)
    return path.with_name(path.name + ".history")


def snapshot(config_file: str | Path, keep: int = DEFAULT_KEEP) -> Optional[Path]:
    """Archive `config_file`, pruning to `keep`. Never raises - a lost
    snapshot must not block the caller from saving."""
    src = Path(config_file)
    if not src.is_file():
        return None  # nothing written yet

    try:
        hdir = history_dir(src)
        hdir.mkdir(parents=True, exist_ok=True)
        os.chmod(hdir, 0o700)

        stamp = datetime.now(timezone.utc).strftime(_STAMP_FORMAT)
        dest = hdir / f"{stamp}.json"
        shutil.copy2(src, dest)
        os.chmod(dest, 0o600)

        _prune(hdir, keep)
        return dest
    except Exception as exc:
        log_warning("config_history", "Could not snapshot %s: %s", str(src), exc)
        return None


def _prune(hdir: Path, keep: int) -> None:
    if keep <= 0:
        return
    versions = sorted(hdir.glob("*.json"))
    for stale in versions[:-keep]:
        try:
            stale.unlink()
        except OSError:
            pass


def list_versions(config_file: str | Path) -> List[Tuple[str, Path]]:
    """Snapshots for `config_file`, newest first, as (version_id, path)."""
    hdir = history_dir(config_file)
    if not hdir.is_dir():
        return []
    return [(p.stem, p) for p in sorted(hdir.glob("*.json"), reverse=True)]


def _resolve(config_file: str | Path, version: str) -> Optional[Path]:
    for vid, path in list_versions(config_file):
        if vid == version:
            return path
    return None


def summarize(path: str | Path) -> Dict[str, object]:
    """Group/device summary of a config file, for `history` and `diff` output."""
    try:
        with open(path) as fh:
            data = json.load(fh)
    except Exception as exc:
        return {"error": str(exc), "groups": {}, "devices": []}

    groups = {
        int(g["group_id"]): {
            "name": g.get("name", ""),
            "members": sorted(g.get("member_pids", []) or []),
            "has_keys": bool(g.get("group_keys")),
        }
        for g in data.get("groups", [])
    }
    devices = sorted(int(d["participant_id"]) for d in data.get("devices", []))
    return {"groups": groups, "devices": devices}


def diff_versions(config_file: str | Path, version: str) -> Optional[List[str]]:
    """Human-readable differences between a snapshot and the live config."""
    old_path = _resolve(config_file, version)
    if old_path is None:
        return None

    old, new = summarize(old_path), summarize(config_file)
    if "error" in old or "error" in new:
        return None
    lines: List[str] = []

    old_groups, new_groups = old["groups"], new["groups"]
    for gid in sorted(set(old_groups) | set(new_groups)):
        if gid not in new_groups:
            lines.append(f"- group {gid} ({old_groups[gid]['name']}) removed since {version}")
        elif gid not in old_groups:
            lines.append(f"+ group {gid} ({new_groups[gid]['name']}) added since {version}")
        else:
            o, n = old_groups[gid], new_groups[gid]
            if o["name"] != n["name"]:
                lines.append(f"~ group {gid} renamed {o['name']} -> {n['name']}")
            gone = set(o["members"]) - set(n["members"])
            added = set(n["members"]) - set(o["members"])
            if gone:
                lines.append(f"~ group {gid} lost members {sorted(gone)}")
            if added:
                lines.append(f"~ group {gid} gained members {sorted(added)}")
            if o["has_keys"] != n["has_keys"]:
                lines.append(f"~ group {gid} keys {'set' if n['has_keys'] else 'cleared'}")

    gone_dev = set(old["devices"]) - set(new["devices"])
    added_dev = set(new["devices"]) - set(old["devices"])
    if gone_dev:
        lines.append(f"- devices removed: {sorted(gone_dev)}")
    if added_dev:
        lines.append(f"+ devices added: {sorted(added_dev)}")

    return lines


def restore(config_file: str | Path, version: str, keep: int = DEFAULT_KEEP) -> bool:
    """Roll `config_file` back to `version` (current contents are
    snapshotted first, so a rollback is itself reversible)."""
    src = _resolve(config_file, version)
    if src is None:
        log_error("config_history", "No such config version: %s", version)
        return False

    try:
        snapshot(config_file, keep)
        dest = Path(config_file)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        shutil.copy2(src, tmp)
        os.chmod(tmp, 0o600)
        tmp.replace(dest)  # atomic, same as group_manager._save_config
        log_info("config_history", "Restored %s from version %s", str(dest), version)
        return True
    except Exception as exc:
        log_error("config_history", "Failed to restore version %s: %s", version, exc)
        return False
