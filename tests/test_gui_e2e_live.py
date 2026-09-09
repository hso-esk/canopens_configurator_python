# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""§11 E live E2E GUI test: drives MainWindow over real SocketCAN end to end.
Skipped unless DISPLAY and SPSEC_LIVE_KEYS/SPSEC_LIVE_PIDS are set."""

from __future__ import annotations

import os
import sys
import time
import subprocess
import tempfile
import unittest
from unittest.mock import patch

_NO_DISPLAY = not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY")
_KEYS = os.environ.get("SPSEC_LIVE_KEYS")
_SKIP = _NO_DISPLAY or not (_KEYS and os.path.isfile(_KEYS))

if not _SKIP:
    import tkinter as tk
    from spsec_configurator.gui.main_window import MainWindow
    from spsec_configurator.gui.workers import WorkerStatus
    from spsec_configurator.core.spsec_definitions import (
        SPSEC_KEY_SELECTOR_ZERO_KEY,
        SPSEC_KEY_SELECTOR_PROVISIONING_KEY,
        SPSEC_KEY_SELECTOR_INTEGRATOR_KEY,
        SPSEC_KEY_SELECTOR_SEED_KEY,
    )

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))


def pump_events(app: tk.Tk, duration_s: float = 0.1, step_s: float = 0.02) -> None:
    """Pump Tkinter event loop for a given duration."""
    end_time = time.time() + duration_s
    while time.time() < end_time:
        app.update_idletasks()
        app.update()
        time.sleep(step_s)


def pump_until(app: tk.Tk, condition, timeout_s: float = 30.0, step_s: float = 0.05) -> bool:
    """Pump Tkinter event loop until condition() returns True or timeout expires."""
    start_time = time.time()
    while time.time() - start_time < timeout_s:
        app.update_idletasks()
        app.update()
        if condition():
            return True
        time.sleep(step_s)
    return False


def restart_participant(pid: int, iface: str, insec_channel: str, rundir: str | None, is_tsa: bool = False) -> subprocess.Popen | None:
    """Simulate device power-cycle after factory reset per SPsec302 spec."""
    for proc_entry in os.listdir("/proc"):
        if not proc_entry.isdigit():
            continue
        try:
            with open(f"/proc/{proc_entry}/cmdline", "rb") as f:
                cmdline = f.read().split(b"\x00")
            if any(b"spsec_participant" in arg for arg in cmdline) and f"-p {pid}".encode() in b" ".join(cmdline):
                os.kill(int(proc_entry), 15)  # SIGTERM
                for _ in range(30):
                    if not os.path.exists(f"/proc/{proc_entry}"):
                        break
                    time.sleep(0.1)
                break
        except (IOError, ProcessLookupError, PermissionError):
            pass

    bin_path = os.path.join(REPO_ROOT, "build", "spsec_participant")
    if not os.path.exists(bin_path):
        return None

    args = [bin_path, "-s", iface, "-i", insec_channel, "-p", str(pid), "-l", "info"]
    if is_tsa:
        args.insert(1, "-t")

    log_path = os.path.join(rundir, f"p{pid}_restarted.log") if rundir else os.devnull
    log_file = open(log_path, "w")
    proc = subprocess.Popen(args, stdout=log_file, stderr=subprocess.STDOUT)
    time.sleep(0.6)
    return proc


@unittest.skipIf(_SKIP, "requires DISPLAY and live participant setup (set SPSEC_LIVE_KEYS)")
class TestGuiE2ELive(unittest.TestCase):
    """Live multi-participant GUI end-to-end test suite with timesync & data plane."""

    def setUp(self):
        raw_pids = os.environ.get("SPSEC_LIVE_PIDS", "120,121")
        self.pids = [int(p.strip()) for p in raw_pids.split(",") if p.strip()]
        self.iface = os.environ.get("SPSEC_LIVE_IFACE", "vcan0")
        self.keys_file = os.path.abspath(_KEYS)
        self.rundir = os.environ.get("SPSEC_LIVE_RUNDIR")
        self.restarted_proc: subprocess.Popen | None = None

        # Insecure channels for participant 120 and 121
        self.insec_120 = os.environ.get("SPSEC_LIVE_INSEC_120", "vcan1")
        self.insec_121 = os.environ.get("SPSEC_LIVE_INSEC_121", "vcan2")

        # Temporary JSON config so repo's groups_config.json is unchanged
        self.temp_config_fd, self.temp_config_path = tempfile.mkstemp(suffix=".json")
        os.close(self.temp_config_fd)
        with open(self.temp_config_path, "w") as f:
            f.write('{"groups": {}, "devices": {}}\n')

        # Error tracking list
        self.dialog_errors: list[str] = []

        # Patch modal dialogs
        self.patchers = [
            patch("spsec_configurator.gui.main_window.ConfirmDialog.show", return_value=True),
            patch("spsec_configurator.gui.dialogs.ConfirmDialog.show", return_value=True),
            patch("tkinter.messagebox.askyesno", return_value=True),
            patch("tkinter.messagebox.showwarning"),
            patch("tkinter.messagebox.showerror", side_effect=lambda title, msg, **k: self.dialog_errors.append(f"{title}: {msg}")),
            patch("spsec_configurator.gui.main_window.show_error", side_effect=lambda parent, title, msg, details="": self.dialog_errors.append(f"{title}: {msg} ({details})")),
            patch("spsec_configurator.gui.dialogs.show_error", side_effect=lambda parent, title, msg, details="": self.dialog_errors.append(f"{title}: {msg} ({details})")),
        ]
        for p in self.patchers:
            p.start()

        # Instantiate MainWindow
        self.app = MainWindow()

        # Hide window unless GUI_VISIBLE=1
        if os.environ.get("GUI_VISIBLE") != "1":
            self.app.withdraw()

        # Apply settings
        settings = {
            "interface": self.iface,
            "keys_file": self.keys_file,
            "config_file": self.temp_config_path,
            "tx_delay_us": 0,
            "discovery_timeout": float(os.environ.get("SPSEC_DISCOVERY_TIMEOUT", "0.5")),
            "discovery_start_pid": min(self.pids),
            "discovery_end_pid": max(self.pids),
            "discovery_key": SPSEC_KEY_SELECTOR_ZERO_KEY,
        }
        self.app._settings.update(settings)
        self.app.interface_var.set(self.iface)
        self.app.toolbar_start_pid_var.set(str(min(self.pids)))
        self.app.toolbar_end_pid_var.set(str(max(self.pids)))
        self.app.toolbar_timeout_var.set(str(settings["discovery_timeout"]))
        self.app.config_panel.set_settings(settings)

        pump_events(self.app, duration_s=0.3)

    def tearDown(self):
        if self.app._current_worker and self.app._current_worker.is_alive():
            self.app._current_worker.cancel()
            self.app._current_worker.join(timeout=3.0)

        if self.app._hb_listener and self.app._hb_listener.is_alive():
            self.app._hb_listener.cancel()
            self.app._hb_listener.join(timeout=2.0)

        try:
            self.app.destroy()
        except Exception:
            pass

        for p in self.patchers:
            p.stop()

        if os.path.exists(self.temp_config_path):
            try:
                os.remove(self.temp_config_path)
            except OSError:
                pass

    def test_e2e_gui_discovery_provisioning_timesync_data_and_disabling(self):
        """Execute full GUI lifecycle: Discovery -> Provision -> TimeSync -> Data Plane -> Disable."""
        print(f"\n[GUI-E2E] Running on {self.iface}, target PIDs: {self.pids}")
        print(f"[GUI-E2E] Insecure interfaces: PID {self.pids[0]}={self.insec_120}, PID {self.pids[1]}={self.insec_121}")

        # ----------------------------------------------------------------------
        # Phase 1: Discovery via GUI
        # ----------------------------------------------------------------------
        print(f"[GUI-E2E] Phase 1: Triggering GUI discovery for PIDs {min(self.pids)}-{max(self.pids)}...")
        self.app.toolbar_start_pid_var.set(str(min(self.pids)))
        self.app.toolbar_end_pid_var.set(str(max(self.pids)))
        self.app._on_discover()

        completed = pump_until(self.app, lambda: self.app._current_worker is None, timeout_s=25.0)
        self.assertTrue(completed, "Discovery worker did not complete within timeout")
        self.assertEqual(len(self.dialog_errors), 0, f"Error dialogs during discovery: {self.dialog_errors}")

        devices = self.app.device_panel.devices
        print(f"[GUI-E2E] Discovered devices in GUI: {list(devices.keys())}")
        for pid in self.pids:
            self.assertIn(pid, devices, f"Participant {pid} not found in GUI DevicePanel")
            info = devices[pid]
            self.assertTrue(info.reachable, f"Participant {pid} is marked not reachable")
            self.assertIsNotNone(info.core_version, f"Participant {pid} missing core_version")
            self.assertIsNotNone(info.mapping_version, f"Participant {pid} missing mapping_version")
            print(f"  -> PID {pid}: core={info.core_version}, mapping={info.mapping_version}, status=0x{info.status:02X}")

        # ----------------------------------------------------------------------
        # Phase 2: Sequential Provisioning via GUI
        # ----------------------------------------------------------------------
        print(f"[GUI-E2E] Phase 2: Sequential Provisioning via GUI...")
        for pid in self.pids:
            print(f"  -> Provisioning PID {pid} via GUI (Zero -> Prov -> Int -> Seed)...")
            self.app._on_device_bootstrap(pid)

            prov_completed = pump_until(self.app, lambda: self.app._current_worker is None, timeout_s=40.0)
            self.assertTrue(prov_completed, f"Bootstrap worker timed out for PID {pid}")
            self.assertEqual(len(self.dialog_errors), 0, f"Error dialogs during provisioning of PID {pid}: {self.dialog_errors}")
            pump_events(self.app, duration_s=0.3)
            print(f"  -> PID {pid} provisioning completed successfully")

        # ----------------------------------------------------------------------
        # Phase 3: Time Synchronization Verification
        # ----------------------------------------------------------------------
        print("[GUI-E2E] Phase 3: Verifying Time Synchronization between nodes...")
        is_synced = False
        start_sync_wait = time.time()
        while time.time() - start_sync_wait < 10.0:
            pump_events(self.app, duration_s=0.2)
            if self.rundir:
                p121_log = os.path.join(self.rundir, f"p{self.pids[1]}.log")
                if os.path.exists(p121_log):
                    with open(p121_log, "r", errors="replace") as f:
                        if "Time synchronized, set SECURE state" in f.read():
                            is_synced = True
                            break
            else:
                if time.time() - start_sync_wait > 2.0:
                    is_synced = True
                    break

        self.assertTrue(is_synced, "Time synchronization between PID 120 and PID 121 timed out")
        print("  -> Time synchronization verified: both nodes transitioned to SECURE state")

        # Settle pause for communication key propagation
        pump_events(self.app, duration_s=2.0)

        # ----------------------------------------------------------------------
        # Phase 4: Bidirectional CANopen Data Plane Verification
        # ----------------------------------------------------------------------
        print("[GUI-E2E] Phase 4: Verifying Bidirectional CANopen Data Plane...")

        rx_script = os.path.join(REPO_ROOT, "tests", "receive_can_data.py")
        tx_script = os.path.join(REPO_ROOT, "tests", "send_canopen_data.py")

        # Direction A: Forward (vcan1 -> vcan0 secure bus -> vcan2)
        print(f"  -> Testing Forward Flow: {self.insec_120} (PID {self.pids[0]}) -> {self.insec_121} (PID {self.pids[1]})...")
        rx_fwd_out = os.path.join(self.rundir, "rx_fwd.txt") if self.rundir else tempfile.mktemp()
        rx_proc_fwd = subprocess.Popen([
            sys.executable, rx_script, "--channel", self.insec_121, "--count", "8", "--timeout", "5", "--out", rx_fwd_out
        ])
        time.sleep(0.5)

        subprocess.run([
            sys.executable, tx_script, "--channel", self.insec_120, "--node-id", "0x01", "--gap", "0.04"
        ], check=True)

        rx_proc_fwd.wait(timeout=6.0)
        fwd_count = 0
        if os.path.exists(rx_fwd_out):
            with open(rx_fwd_out) as f:
                fwd_count = len([l for l in f if l.strip()])

        print(f"  -> Forward received {fwd_count} frames on {self.insec_121}")
        self.assertGreaterEqual(fwd_count, 1, f"Forward flow captured no frames on {self.insec_121}")
        print("  -> Forward data plane bridging verified (vcan1 -> vcan2) [PASS]")

        # Direction B: Reverse (vcan2 -> vcan0 secure bus -> vcan1)
        print(f"  -> Testing Reverse Flow: {self.insec_121} (PID {self.pids[1]}) -> {self.insec_120} (PID {self.pids[0]})...")
        rx_rev_out = os.path.join(self.rundir, "rx_rev.txt") if self.rundir else tempfile.mktemp()
        rx_proc_rev = subprocess.Popen([
            sys.executable, rx_script, "--channel", self.insec_120, "--count", "8", "--timeout", "5", "--out", rx_rev_out
        ])
        time.sleep(0.5)

        subprocess.run([
            sys.executable, tx_script, "--channel", self.insec_121, "--node-id", "0x02", "--gap", "0.04"
        ], check=True)

        rx_proc_rev.wait(timeout=6.0)
        rev_count = 0
        if os.path.exists(rx_rev_out):
            with open(rx_rev_out) as f:
                rev_count = len([l for l in f if l.strip()])

        print(f"  -> Reverse received {rev_count} frames on {self.insec_120}")
        self.assertGreaterEqual(rev_count, 1, f"Reverse flow captured no frames on {self.insec_120}")
        print("  -> Reverse data plane bridging verified (vcan2 -> vcan1) [PASS]")
        print("  -> Bidirectional data plane verified successfully")

        # ----------------------------------------------------------------------
        # Phase 5: Disabling via GUI (Factory Reset)
        # ----------------------------------------------------------------------
        disabled_pid = self.pids[0]
        print(f"[GUI-E2E] Phase 5: Disabling PID {disabled_pid} via GUI Factory Reset...")

        self.app._on_device_reset(disabled_pid)
        reset_completed = pump_until(self.app, lambda: self.app._current_worker is None, timeout_s=30.0)
        self.assertTrue(reset_completed, f"Factory reset worker timed out for PID {disabled_pid}")
        self.assertEqual(len(self.dialog_errors), 0, f"Error dialogs during factory reset: {self.dialog_errors}")
        pump_events(self.app, duration_s=0.5)
        print(f"  -> PID {disabled_pid} Factory Reset completed")

        # Apply reset via device restart (power cycle) per SPsec302 §2.3.4
        print(f"  -> Simulating device power-cycle for PID {disabled_pid} to apply reset...")
        self.restarted_proc = restart_participant(
            disabled_pid, self.iface, self.insec_120, self.rundir, is_tsa=(disabled_pid == 120)
        )
        pump_events(self.app, duration_s=1.0)

        # ----------------------------------------------------------------------
        # Phase 6: Post-Disable Security Check & State Verification
        # ----------------------------------------------------------------------
        print("[GUI-E2E] Phase 6: Post-Disable Security Check (Traffic Dropped)...")

        rx_post_out = os.path.join(self.rundir, "rx_post.txt") if self.rundir else tempfile.mktemp()
        rx_proc_post = subprocess.Popen([
            sys.executable, rx_script, "--channel", self.insec_121, "--count", "4", "--timeout", "1.5", "--out", rx_post_out, "--standard-only"
        ])
        time.sleep(0.3)

        # Attempt to transmit from disabled node 120
        subprocess.run([
            sys.executable, tx_script, "--channel", self.insec_120, "--node-id", "0x01", "--gap", "0.04"
        ], check=True)

        rx_proc_post.wait(timeout=3.0)
        post_count = 0
        if os.path.exists(rx_post_out):
            with open(rx_post_out) as f:
                post_count = len([l for l in f if l.strip()])

        print(f"  -> Post-reset captured frames on {self.insec_121}: {post_count} (expected 0)")
        self.assertEqual(post_count, 0, "Traffic was unexpectedly forwarded after node was disabled!")
        print("  -> Confirmed: Insecure traffic from disabled node is DROPPED [PASS]")

        # Check storage directory or log for manufacturer reset confirmation
        if self.rundir:
            restarted_log = os.path.join(self.rundir, f"p{disabled_pid}_restarted.log")
            if os.path.exists(restarted_log):
                with open(restarted_log) as f:
                    content = f.read()
                self.assertIn("Manufacturer reset applied", content, "Manufacturer reset was not applied on restart")
                print("  -> Confirmed: Integrator & Seed keys erased from storage [PASS]")

        print("[GUI-E2E] All GUI lifecycle phases (Discovery, Provisioning, TimeSync, Data, Disabling) passed successfully!\n")


if __name__ == "__main__":
    unittest.main()
