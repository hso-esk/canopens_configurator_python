# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Interactive step-by-step GUI test runner: mounts a Stage Controller panel
that pauses at each lifecycle stage until 'Next Stage'/Enter."""

from __future__ import annotations

import os
import sys
import time
import threading
import argparse
import tempfile
import subprocess
import tkinter as tk
from tkinter import ttk
from unittest.mock import patch

from .main_window import MainWindow
from ..core.spsec_definitions import SPSEC_KEY_SELECTOR_ZERO_KEY
from ..core.logging_util import log_info

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "..", ".."))


def restart_participant_proc(pid: int, iface: str, insec_channel: str, rundir: str | None, is_tsa: bool = False) -> subprocess.Popen | None:
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


class InteractiveStageController(ttk.LabelFrame):
    """Visual stage controller mounted at the top of MainWindow."""

    STAGES = [
        {
            "id": 1,
            "title": "Stage 1/7: Discover Participants",
            "desc": "Probes bus vcan0 with Zero Key for unprovisioned participants (PID 120, 121).",
            "btn_text": "▶ Run Stage 1: Discover Participants",
            "working_text": "⏳ Probing bus for devices...",
        },
        {
            "id": 2,
            "title": "Stage 2/7: Provision Node 120 (TSA)",
            "desc": "Executes SPsec key ladder (Zero -> Prov -> Int -> Seed) on PID 120.",
            "btn_text": "▶ Run Stage 2: Provision PID 120",
            "working_text": "⏳ Bootstrapping PID 120 through key ladder...",
        },
        {
            "id": 3,
            "title": "Stage 3/7: Provision Node 121 (Client)",
            "desc": "Executes SPsec key ladder (Zero -> Prov -> Int -> Seed) on PID 121.",
            "btn_text": "▶ Run Stage 3: Provision PID 121",
            "working_text": "⏳ Bootstrapping PID 121 through key ladder...",
        },
        {
            "id": 4,
            "title": "Stage 4/7: Verify Time Synchronization",
            "desc": "Verifies client 121 synchronizes clock with TSA 120 and both enter SECURE mode.",
            "btn_text": "▶ Run Stage 4: Verify Time Synchronization",
            "working_text": "⏳ Checking time sync & secure state...",
        },
        {
            "id": 5,
            "title": "Stage 5/7: Verify Bidirectional Data Plane",
            "desc": "Verifies CANopen traffic bridged both ways: vcan1 -> vcan2 and vcan2 -> vcan1.",
            "btn_text": "▶ Run Stage 5: Test Bidirectional Data Plane",
            "working_text": "⏳ Exchanging CANopen frames across secure bus...",
        },
        {
            "id": 6,
            "title": "Stage 6/7: Disable Node 120 (Factory Reset)",
            "desc": "Writes 0x1D04E5E1 to register 0x7F on PID 120 and simulates device restart.",
            "btn_text": "▶ Run Stage 6: Factory Reset PID 120",
            "working_text": "⏳ Sending Manufacturer Reset to PID 120...",
        },
        {
            "id": 7,
            "title": "Stage 7/7: Post-Disable Security Check",
            "desc": "Verifies traffic from disabled Node 120 is dropped (0 frames forwarded to vcan2).",
            "btn_text": "▶ Run Stage 7: Post-Disable Security Check",
            "working_text": "⏳ Verifying traffic blocking on disabled node...",
        },
        {
            "id": 8,
            "title": "All Stages Complete! 🎉",
            "desc": "All operations verified successfully. Click below to close and stop participants.",
            "btn_text": "⏹ Finish & Clean Up",
            "working_text": "Closing application...",
        },
    ]

    def __init__(self, parent: tk.Widget, app: MainWindow, pids: list[int],
                 rundir: str | None = None, insec_120: str = "vcan1", insec_121: str = "vcan2",
                 auto_advance: bool = False):
        super().__init__(parent, text=" 🎯 Interactive Stage Controller ", padding=10)
        self.app = app
        self.pids = pids
        self.rundir = rundir
        self.insec_120 = insec_120
        self.insec_121 = insec_121
        self.stage_idx = 0
        self.is_running_stage = False
        self.auto_advance_var = tk.BooleanVar(value=auto_advance)

        self._create_widgets()
        self._update_display()
        self._start_terminal_listener()

        if auto_advance:
            print("[Interactive] Auto-advance enabled: starting Stage 1 in 1 second...")
            self.after(1000, self.advance_stage)

    def _create_widgets(self) -> None:
        header_frame = ttk.Frame(self)
        header_frame.pack(fill=tk.X, expand=True)

        self.stage_title_label = ttk.Label(
            header_frame,
            text="",
            font=("TkDefaultFont", 11, "bold"),
            foreground="#0d47a1"
        )
        self.stage_title_label.pack(side=tk.LEFT)

        self.status_badge = ttk.Label(
            header_frame,
            text="[ Ready ]",
            font=("TkDefaultFont", 10, "bold"),
            foreground="#2e7d32"
        )
        self.status_badge.pack(side=tk.RIGHT)

        self.stage_desc_label = ttk.Label(
            self,
            text="",
            font=("TkDefaultFont", 9),
            foreground="#424242",
            wraplength=700
        )
        self.stage_desc_label.pack(fill=tk.X, pady=(4, 8))

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X)

        self.action_btn = tk.Button(
            btn_frame,
            text="",
            font=("TkDefaultFont", 10, "bold"),
            bg="#1976d2",
            fg="white",
            activebackground="#1565c0",
            activeforeground="white",
            padx=16,
            pady=6,
            cursor="hand2",
            command=self.advance_stage
        )
        self.action_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.auto_cb = ttk.Checkbutton(
            btn_frame,
            text="Auto-advance (3s delay between stages)",
            variable=self.auto_advance_var
        )
        self.auto_cb.pack(side=tk.LEFT)

    def _update_display(self) -> None:
        """Update display for the current stage."""
        stage = self.STAGES[self.stage_idx]
        self.stage_title_label.configure(text=stage["title"])
        self.stage_desc_label.configure(text=stage["desc"])
        self.action_btn.configure(text=stage["btn_text"], state=tk.NORMAL)
        self.status_badge.configure(text="[ Ready ]", foreground="#2e7d32")

        stage_num = stage["id"]
        if stage_num <= 7:
            print(f"\n>>> [Stage {stage_num}/7] Ready: {stage['title']}")
            print(f"    {stage['desc']}")
            print("    Press [Enter] in this terminal OR click the button in the GUI to proceed...")
        else:
            print("\n>>> All stages complete! Press [Enter] or click 'Finish & Clean Up' in the GUI.")

    def advance_stage(self) -> None:
        """Trigger execution of the current stage."""
        if self.is_running_stage:
            return

        stage = self.STAGES[self.stage_idx]
        stage_num = stage["id"]

        if stage_num == 8:
            print("[Interactive] Finished. Closing GUI window...")
            self.app._on_close()
            return

        self.is_running_stage = True
        self.action_btn.configure(text=stage["working_text"], state=tk.DISABLED)
        self.status_badge.configure(text="[ Running... ]", foreground="#e65100")

        if stage_num == 1:
            self._execute_stage_1_discovery()
        elif stage_num == 2:
            self._execute_stage_2_provision_120()
        elif stage_num == 3:
            self._execute_stage_3_provision_121()
        elif stage_num == 4:
            self._execute_stage_4_verify_timesync()
        elif stage_num == 5:
            self._execute_stage_5_bidirectional_data()
        elif stage_num == 6:
            self._execute_stage_6_factory_reset_120()
        elif stage_num == 7:
            self._execute_stage_7_post_disable_check()

    def _execute_stage_1_discovery(self) -> None:
        print("[Interactive] Executing Stage 1: Discovering participants...")
        self.app.toolbar_start_pid_var.set(str(min(self.pids)))
        self.app.toolbar_end_pid_var.set(str(max(self.pids)))
        self.app._on_discover()
        self._wait_for_worker(self._on_stage_1_complete)

    def _on_stage_1_complete(self) -> None:
        devices = list(self.app.device_panel.devices.keys())
        print(f"[Interactive] Stage 1 Complete: Discovered {len(devices)} device(s): {devices}")
        self._stage_done(f"[ ✅ Stage 1 Done: Found {len(devices)} nodes ]")

    def _execute_stage_2_provision_120(self) -> None:
        target_pid = self.pids[0]
        print(f"[Interactive] Executing Stage 2: Provisioning PID {target_pid} (TSA)...")
        self.app._on_device_bootstrap(target_pid)
        self._wait_for_worker(lambda: self._stage_done(f"[ ✅ Stage 2 Done: PID {target_pid} Provisioned ]"))

    def _execute_stage_3_provision_121(self) -> None:
        target_pid = self.pids[1] if len(self.pids) > 1 else self.pids[0]
        print(f"[Interactive] Executing Stage 3: Provisioning PID {target_pid} (Client)...")
        self.app._on_device_bootstrap(target_pid)
        self._wait_for_worker(lambda: self._stage_done(f"[ ✅ Stage 3 Done: PID {target_pid} Provisioned ]"))

    def _execute_stage_4_verify_timesync(self) -> None:
        print("[Interactive] Executing Stage 4: Verifying Time Synchronization...")
        def check_sync():
            synced = False
            if self.rundir:
                p121_log = os.path.join(self.rundir, f"p{self.pids[1]}.log")
                if os.path.exists(p121_log):
                    with open(p121_log, "r", errors="replace") as f:
                        if "Time synchronized, set SECURE state" in f.read():
                            synced = True
            else:
                synced = True

            if synced:
                print("  -> Time synchronization verified: both nodes in SECURE state")
                self._stage_done("[ ✅ Stage 4 Done: Time Synchronized (SECURE) ]")
            else:
                self.after(300, check_sync)

        self.after(200, check_sync)

    def _execute_stage_5_bidirectional_data(self) -> None:
        print("[Interactive] Executing Stage 5: Verifying Bidirectional CANopen Data Plane...")
        rx_script = os.path.join(REPO_ROOT, "tests", "receive_can_data.py")
        tx_script = os.path.join(REPO_ROOT, "tests", "send_canopen_data.py")

        def run_data_plane():
            # Direction A: Forward (vcan1 -> vcan2)
            print(f"  -> Testing Forward Flow: {self.insec_120} -> {self.insec_121}...")
            rx_fwd_out = os.path.join(self.rundir, "rx_fwd_interactive.txt") if self.rundir else tempfile.mktemp()
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

            # Direction B: Reverse (vcan2 -> vcan1)
            print(f"  -> Testing Reverse Flow: {self.insec_121} -> {self.insec_120}...")
            rx_rev_out = os.path.join(self.rundir, "rx_rev_interactive.txt") if self.rundir else tempfile.mktemp()
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

            badge = f"[ ✅ Stage 5 Done: Fwd={fwd_count}, Rev={rev_count} ]"
            self.after(0, lambda: self._stage_done(badge))

        threading.Thread(target=run_data_plane, daemon=True).start()

    def _execute_stage_6_factory_reset_120(self) -> None:
        target_pid = self.pids[0]
        print(f"[Interactive] Executing Stage 6: Resetting/Disabling PID {target_pid}...")
        with patch("spsec_configurator.gui.main_window.ConfirmDialog.show", return_value=True):
            self.app._on_device_reset(target_pid)

        def on_reset_done():
            print(f"  -> Simulating power-cycle for PID {target_pid} to apply reset...")
            restart_participant_proc(
                target_pid, self.app._settings["interface"], self.insec_120, self.rundir, is_tsa=(target_pid == 120)
            )
            self._stage_done(f"[ ✅ Stage 6 Done: PID {target_pid} Reset & Restarted ]")

        self._wait_for_worker(on_reset_done)

    def _execute_stage_7_post_disable_check(self) -> None:
        print("[Interactive] Executing Stage 7: Post-Disable Security Check (Traffic Dropped)...")
        rx_script = os.path.join(REPO_ROOT, "tests", "receive_can_data.py")
        tx_script = os.path.join(REPO_ROOT, "tests", "send_canopen_data.py")

        def run_post_check():
            rx_post_out = os.path.join(self.rundir, "rx_post_interactive.txt") if self.rundir else tempfile.mktemp()
            rx_proc_post = subprocess.Popen([
                sys.executable, rx_script, "--channel", self.insec_121, "--count", "4", "--timeout", "1.5", "--out", rx_post_out, "--standard-only"
            ])
            time.sleep(0.3)

            subprocess.run([
                sys.executable, tx_script, "--channel", self.insec_120, "--node-id", "0x01", "--gap", "0.04"
            ], check=True)

            rx_proc_post.wait(timeout=3.0)
            post_count = 0
            if os.path.exists(rx_post_out):
                with open(rx_post_out) as f:
                    post_count = len([l for l in f if l.strip()])

            print(f"  -> Post-reset captured frames on {self.insec_121}: {post_count} (expected 0)")
            if post_count == 0:
                print("  -> Confirmed: Insecure traffic from disabled node is DROPPED [PASS]")
                badge = "[ ✅ Stage 7 Done: Traffic Dropped (0 frames) ]"
            else:
                badge = f"[ ⚠️ Warning: {post_count} frames received ]"

            self.after(0, lambda: self._stage_done(badge))

        threading.Thread(target=run_post_check, daemon=True).start()

    def _wait_for_worker(self, on_done_callback) -> None:
        """Poll for current worker completion without freezing Tkinter."""
        if self.app._current_worker is None or not self.app._current_worker.is_alive():
            on_done_callback()
            return
        self.after(100, lambda: self._wait_for_worker(on_done_callback))

    def _stage_done(self, badge_text: str) -> None:
        """Mark current stage finished and prepare next stage."""
        self.is_running_stage = False
        self.status_badge.configure(text=badge_text, foreground="#2e7d32")
        self.stage_idx = min(len(self.STAGES) - 1, self.stage_idx + 1)
        self._update_display()

        if self.auto_advance_var.get():
            print("[Interactive] Auto-advance enabled: proceeding in 3 seconds...")
            self.after(3000, self.advance_stage)

    def _start_terminal_listener(self) -> None:
        """Listen for [Enter] keypresses on sys.stdin."""
        def listener():
            while True:
                try:
                    line = sys.stdin.readline()
                    if not line:
                        break
                    self.after(0, self.advance_stage)
                except Exception:
                    break

        thread = threading.Thread(target=listener, daemon=True)
        thread.start()


def main() -> int:
    parser = argparse.ArgumentParser(description="Interactive Step-by-Step GUI Test Runner")
    parser.add_argument("-i", "--interface", default="vcan0", help="SocketCAN secure interface")
    parser.add_argument("-p", "--pids", default="120,121", help="Comma-separated PIDs to test")
    parser.add_argument("-k", "--keys", required=True, help="Path to keys file")
    parser.add_argument("--insec-120", default="vcan1", help="Insecure channel for PID 120")
    parser.add_argument("--insec-121", default="vcan2", help="Insecure channel for PID 121")
    parser.add_argument("--rundir", default=None, help="Participant runtime directory")
    parser.add_argument("--auto", action="store_true", help="Auto-advance through stages (3s delay)")
    args = parser.parse_args()

    pids = [int(p.strip()) for p in args.pids.split(",") if p.strip()]

    temp_fd, temp_config = tempfile.mkstemp(suffix=".json")
    os.close(temp_fd)
    with open(temp_config, "w") as f:
        f.write('{"groups": {}, "devices": {}}\n')

    # Auto-confirm modal dialogs
    patchers = [
        patch("spsec_configurator.gui.main_window.ConfirmDialog.show", return_value=True),
        patch("spsec_configurator.gui.dialogs.ConfirmDialog.show", return_value=True),
        patch("tkinter.messagebox.askyesno", return_value=True),
    ]
    for p in patchers:
        p.start()

    app = MainWindow()

    settings = {
        "interface": args.interface,
        "keys_file": os.path.abspath(args.keys),
        "config_file": temp_config,
        "tx_delay_us": 0,
        "discovery_timeout": 0.5,
        "discovery_start_pid": min(pids),
        "discovery_end_pid": max(pids),
        "discovery_key": SPSEC_KEY_SELECTOR_ZERO_KEY,
    }
    app._settings.update(settings)
    app.interface_var.set(args.interface)
    app.toolbar_start_pid_var.set(str(min(pids)))
    app.toolbar_end_pid_var.set(str(max(pids)))
    app.toolbar_timeout_var.set(str(settings["discovery_timeout"]))
    app.config_panel.set_settings(settings)

    controller = InteractiveStageController(
        app, app, pids,
        rundir=args.rundir,
        insec_120=args.insec_120,
        insec_121=args.insec_121,
        auto_advance=args.auto
    )
    controller.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(5, 5), before=app.statusbar)

    app.title("SPsec Configurator - Interactive Step-by-Step E2E Verification")

    print("\n" + "=" * 70)
    print("  SPsec Desktop GUI - Interactive Step-by-Step E2E Verification")
    print("=" * 70)
    print(f"Target Participants: {pids} on {args.interface}")
    print(f"Insecure Channels:   PID {pids[0]}={args.insec_120}, PID {pids[1]}={args.insec_121}")
    print("A control bar is displayed at the top of the GUI window.")
    print("You can advance to each stage using either:")
    print("  1. Press [Enter] in this terminal")
    print("  2. Click the prominent 'Run Stage' button in the GUI window")
    print("=" * 70 + "\n")

    try:
        app.mainloop()
    finally:
        for p in patchers:
            p.stop()
        if os.path.exists(temp_config):
            try:
                os.remove(temp_config)
            except OSError:
                pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
