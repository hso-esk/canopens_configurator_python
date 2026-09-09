# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Device ops panel: bootstrap, factory reset, key distribution, batch ops."""

from __future__ import annotations

import tkinter as tk
from ..core.keys import generate_key_id
from tkinter import ttk, messagebox
from typing import Optional, Callable, List
import secrets


class OperationsPanel(ttk.Frame):
    """Device ops: bootstrap wizard, factory reset, key distribution, batch ops."""
    
    def __init__(
        self,
        parent: tk.Widget,
        on_bootstrap: Optional[Callable[[int, dict], None]] = None,
        on_factory_reset: Optional[Callable[[int], None]] = None,
        on_distribute_keys: Optional[Callable[[int], None]] = None,
        on_batch_bootstrap: Optional[Callable[[List[int], dict], None]] = None,
        on_rekey_seed: Optional[Callable[[int, dict], None]] = None,
        on_provision_discovered: Optional[Callable[[List[int], dict], None]] = None,
    ):
        super().__init__(parent)
        
        self.on_bootstrap = on_bootstrap
        self.on_factory_reset = on_factory_reset
        self.on_distribute_keys = on_distribute_keys
        self.on_batch_bootstrap = on_batch_bootstrap
        self.on_rekey_seed = on_rekey_seed
        self.on_provision_discovered = on_provision_discovered
        
        self._create_widgets()
    
    def _create_widgets(self) -> None:
        """Create panel widgets"""
        # Notebook for operation tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bootstrap tab
        bootstrap_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(bootstrap_frame, text="Bootstrap")
        self._create_bootstrap_tab(bootstrap_frame)
        
        # Factory Reset tab
        reset_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(reset_frame, text="Factory Reset")
        self._create_reset_tab(reset_frame)
        
        # Batch Operations tab
        batch_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(batch_frame, text="Batch Operations")
        self._create_batch_tab(batch_frame)
    
    def _create_bootstrap_tab(self, parent: ttk.Frame) -> None:
        """Create bootstrap tab content"""
        # Description
        desc = ttk.Label(
            parent,
            text="Bootstrap a device by provisioning cryptographic keys.\n"
                 "This establishes secure communication with the device.",
            wraplength=500,
        )
        desc.pack(anchor=tk.W, pady=(0, 15))
        
        # Device selection
        device_frame = ttk.LabelFrame(parent, text="Target Device", padding=10)
        device_frame.pack(fill=tk.X, pady=(0, 10))
        
        pid_frame = ttk.Frame(device_frame)
        pid_frame.pack(fill=tk.X)
        
        ttk.Label(pid_frame, text="Participant ID:").pack(side=tk.LEFT)
        self.bootstrap_pid_entry = ttk.Entry(pid_frame, width=10)
        self.bootstrap_pid_entry.pack(side=tk.LEFT, padx=(5, 0))
        
        # Initial Session Key Selection
        initial_key_frame = ttk.LabelFrame(parent, text="Initial Session Key", padding=10)
        initial_key_frame.pack(fill=tk.X, pady=(0, 10))
        
        key_selector_row = ttk.Frame(initial_key_frame)
        key_selector_row.pack(fill=tk.X)
        
        ttk.Label(key_selector_row, text="Key to use for first session:").pack(side=tk.LEFT)
        
        self.initial_key_selector_var = tk.StringVar(value="Zero (1)")
        self.initial_key_selector_combo = ttk.Combobox(
            key_selector_row,
            textvariable=self.initial_key_selector_var,
            values=["Zero (1)", "Provisioning (15)", "Integrator (14)"],
            state="readonly",
            width=20,
        )
        self.initial_key_selector_combo.pack(side=tk.LEFT, padx=(5, 0))
        
        key_help = ttk.Label(
            initial_key_frame,
            text="Each subsequent key will be written in a new session using the previously written key",
            font=("", 8),
            foreground="gray",
        )
        key_help.pack(anchor=tk.W, pady=(5, 0))
        
        # Keys section
        keys_frame = ttk.LabelFrame(parent, text="Keys Configuration", padding=10)
        keys_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Key source selection
        source_frame = ttk.Frame(keys_frame)
        source_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.key_source_var = tk.StringVar(value="file")
        
        ttk.Radiobutton(
            source_frame,
            text="Use keys from file",
            variable=self.key_source_var,
            value="file",
            command=self._on_key_source_change,
        ).pack(anchor=tk.W)
        
        ttk.Radiobutton(
            source_frame,
            text="Enter keys manually",
            variable=self.key_source_var,
            value="manual",
            command=self._on_key_source_change,
        ).pack(anchor=tk.W)
        
        ttk.Radiobutton(
            source_frame,
            text="Generate random keys",
            variable=self.key_source_var,
            value="generate",
            command=self._on_key_source_change,
        ).pack(anchor=tk.W)
        
        # Manual key entry (hidden by default)
        self.manual_keys_frame = ttk.Frame(keys_frame)
        
        self.key_entries = {}
        # Provisioning keys (only needed if starting from Zero)
        self._create_key_entry_fields(self.manual_keys_frame, "Provisioning", "provisioning")
        self._create_key_entry_fields(self.manual_keys_frame, "Integrator", "integrator")
        self._create_key_entry_fields(self.manual_keys_frame, "Seed", "seed")
        
        # Generate button for manual mode
        gen_btn = ttk.Button(
            self.manual_keys_frame,
            text="Generate Random Keys",
            command=self._generate_random_keys,
        )
        gen_btn.pack(anchor=tk.W, pady=(10, 0))
        
        # Action buttons
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X)
        
        self.bootstrap_btn = ttk.Button(
            action_frame,
            text="Bootstrap Device",
            command=self._on_bootstrap_click,
        )
        self.bootstrap_btn.pack(side=tk.RIGHT)

        # Rotating the Seed key on an already-provisioned device is a separate
        # operation from bootstrapping: bootstrap also writes the write-once
        # Integrator key and so fails with KEY_ALREADY_SET on a live device.
        self.rekey_seed_btn = ttk.Button(
            action_frame,
            text="Rekey Seed Key",
            command=self._on_rekey_seed_click,
        )
        self.rekey_seed_btn.pack(side=tk.RIGHT, padx=(0, 5))
    
    def _create_key_entry_fields(
        self,
        parent: ttk.Frame,
        label: str,
        prefix: str,
    ) -> None:
        """Create key entry fields"""
        frame = ttk.LabelFrame(parent, text=f"{label} Keys", padding=5)
        frame.pack(fill=tk.X, pady=(0, 5))
        
        # Key
        key_row = ttk.Frame(frame)
        key_row.pack(fill=tk.X, pady=2)
        ttk.Label(key_row, text="Key (hex):", width=12).pack(side=tk.LEFT)
        key_entry = ttk.Entry(key_row, width=70, font=("TkFixedFont", 9))
        key_entry.pack(side=tk.LEFT, padx=(5, 0))
        self.key_entries[f"{prefix}_key"] = key_entry
        
        # Salt
        salt_row = ttk.Frame(frame)
        salt_row.pack(fill=tk.X, pady=2)
        ttk.Label(salt_row, text="Salt (hex):", width=12).pack(side=tk.LEFT)
        salt_entry = ttk.Entry(salt_row, width=40, font=("TkFixedFont", 9))
        salt_entry.pack(side=tk.LEFT, padx=(5, 0))
        self.key_entries[f"{prefix}_salt"] = salt_entry
        
        # Key ID
        id_row = ttk.Frame(frame)
        id_row.pack(fill=tk.X, pady=2)
        ttk.Label(id_row, text="Key ID:", width=12).pack(side=tk.LEFT)
        id_entry = ttk.Entry(id_row, width=15)
        id_entry.pack(side=tk.LEFT, padx=(5, 0))
        self.key_entries[f"{prefix}_key_id"] = id_entry
    
    def _on_key_source_change(self) -> None:
        """Handle key source radio button change"""
        source = self.key_source_var.get()
        if source == "manual" or source == "generate":
            self.manual_keys_frame.pack(fill=tk.X, pady=(10, 0))
            if source == "generate":
                self._generate_random_keys()
        else:
            self.manual_keys_frame.pack_forget()
    
    def _generate_random_keys(self) -> None:
        """Generate random keys and fill entries"""
        for name, entry in self.key_entries.items():
            entry.delete(0, tk.END)
            if name.endswith("_key"):
                entry.insert(0, secrets.token_hex(32))
            elif name.endswith("_salt"):
                entry.insert(0, secrets.token_hex(16))
            elif name.endswith("_key_id"):
                entry.insert(0, str(generate_key_id()))
    
    def _on_bootstrap_click(self) -> None:
        """Handle bootstrap button click"""
        try:
            pid = int(self.bootstrap_pid_entry.get().strip())
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid Participant ID")
            return
        
        # Get initial key selector
        initial_key_text = self.initial_key_selector_var.get()
        if "1)" in initial_key_text or "Zero" in initial_key_text:
            initial_key_selector = 1
        elif "15" in initial_key_text or "Provisioning" in initial_key_text:
            initial_key_selector = 15
        elif "14" in initial_key_text or "Integrator" in initial_key_text:
            initial_key_selector = 14
        else:
            initial_key_selector = 1  # Default
        
        source = self.key_source_var.get()
        
        if source == "file":
            # Use keys from configuration file
            keys = None
        else:
            # Get keys from entries
            try:
                keys = self._get_keys_from_entries()
            except ValueError as e:
                messagebox.showerror("Invalid Keys", str(e))
                return
        
        # Add initial key selector to keys dict
        if keys is not None:
            keys["initial_key_selector"] = initial_key_selector
        else:
            keys = {"initial_key_selector": initial_key_selector}
        
        if self.on_bootstrap:
            self.on_bootstrap(pid, keys)

    def _on_rekey_seed_click(self) -> None:
        """Install a new Seed key via the Integrator key ladder rung
        (SPsec302 §2.3.1 permits it; the Seed register is re-writable)."""
        try:
            pid = int(self.bootstrap_pid_entry.get().strip())
        except (ValueError, AttributeError):
            messagebox.showerror("Invalid PID", "Enter a valid participant ID")
            return

        source = self.key_source_var.get()
        if source == "file":
            keys = {}
        else:
            try:
                keys = self._get_keys_from_entries()
            except ValueError as e:
                messagebox.showerror("Invalid Keys", str(e))
                return

        if self.on_rekey_seed:
            self.on_rekey_seed(pid, keys)
    
    def _get_keys_from_entries(self) -> dict:
        """Get and validate keys from entry fields"""
        result = {}
        
        # Determine which keys are needed based on initial key selector
        initial_key_text = self.initial_key_selector_var.get()
        if "1)" in initial_key_text or "Zero" in initial_key_text:
            prefixes = ["provisioning", "integrator", "seed"]
        elif "15" in initial_key_text or "Provisioning" in initial_key_text:
            prefixes = ["integrator", "seed"]
        elif "14" in initial_key_text or "Integrator" in initial_key_text:
            prefixes = ["seed"]
        else:
            # Unreachable while the combo is limited to the three session keys;
            # kept as a safe default matching an Integrator start.
            prefixes = ["seed"]
        
        for prefix in prefixes:
            key_hex = self.key_entries[f"{prefix}_key"].get().strip()
            salt_hex = self.key_entries[f"{prefix}_salt"].get().strip()
            key_id_str = self.key_entries[f"{prefix}_key_id"].get().strip()
            
            if len(key_hex) != 64:
                raise ValueError(f"{prefix.title()} key must be 64 hex characters (32 bytes)")
            if len(salt_hex) != 32:
                raise ValueError(f"{prefix.title()} salt must be 32 hex characters (16 bytes)")
            
            try:
                result[f"{prefix}_key"] = bytes.fromhex(key_hex)
                result[f"{prefix}_salt"] = bytes.fromhex(salt_hex)
                result[f"{prefix}_key_id"] = int(key_id_str)
            except ValueError as e:
                raise ValueError(f"Invalid {prefix} key data: {e}")
        
        return result
    
    def _create_reset_tab(self, parent: ttk.Frame) -> None:
        """Create factory reset tab content"""
        # Warning
        warning_frame = ttk.Frame(parent)
        warning_frame.pack(fill=tk.X, pady=(0, 15))
        
        warning_label = ttk.Label(
            warning_frame,
            text="⚠ WARNING",
            font=("TkDefaultFont", 12, "bold"),
            foreground="red",
        )
        warning_label.pack(anchor=tk.W)
        
        warning_text = ttk.Label(
            warning_frame,
            text="Factory reset will delete ALL cryptographic keys from the device.\n"
                 "The device will need to be re-bootstrapped to use secure communication.",
            wraplength=500,
            foreground="red",
        )
        warning_text.pack(anchor=tk.W)
        
        # Device selection
        device_frame = ttk.LabelFrame(parent, text="Target Device", padding=10)
        device_frame.pack(fill=tk.X, pady=(0, 10))
        
        pid_frame = ttk.Frame(device_frame)
        pid_frame.pack(fill=tk.X)
        
        ttk.Label(pid_frame, text="Participant ID:").pack(side=tk.LEFT)
        self.reset_pid_entry = ttk.Entry(pid_frame, width=10)
        self.reset_pid_entry.pack(side=tk.LEFT, padx=(5, 0))
        
        # Confirmation
        confirm_frame = ttk.LabelFrame(parent, text="Confirmation", padding=10)
        confirm_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.reset_confirm_var = tk.BooleanVar(value=False)
        confirm_check = ttk.Checkbutton(
            confirm_frame,
            text="I understand this will delete all keys and cannot be undone",
            variable=self.reset_confirm_var,
            command=self._on_reset_confirm_change,
        )
        confirm_check.pack(anchor=tk.W)
        
        # Action buttons
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X)
        
        self.reset_btn = ttk.Button(
            action_frame,
            text="Factory Reset",
            command=self._on_reset_click,
            state=tk.DISABLED,
        )
        self.reset_btn.pack(side=tk.RIGHT)
    
    def _on_reset_confirm_change(self) -> None:
        """Handle reset confirmation checkbox"""
        if self.reset_confirm_var.get():
            self.reset_btn.configure(state=tk.NORMAL)
        else:
            self.reset_btn.configure(state=tk.DISABLED)
    
    def _on_reset_click(self) -> None:
        """Handle reset button click"""
        try:
            pid = int(self.reset_pid_entry.get().strip())
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid Participant ID")
            return
        
        # Double confirm
        if not messagebox.askyesno(
            "Confirm Factory Reset",
            f"Are you sure you want to factory reset device PID {pid}?\n\n"
            "This will delete ALL cryptographic keys.",
        ):
            return
        
        if self.on_factory_reset:
            self.on_factory_reset(pid)
        
        # Reset the form
        self.reset_confirm_var.set(False)
        self._on_reset_confirm_change()
    
    def _create_batch_tab(self, parent: ttk.Frame) -> None:
        """Create batch operations tab content"""
        # Description
        desc = ttk.Label(
            parent,
            text="Perform operations on multiple devices at once.",
            wraplength=500,
        )
        desc.pack(anchor=tk.W, pady=(0, 15))
        
        # Device selection
        device_frame = ttk.LabelFrame(parent, text="Target Devices", padding=10)
        device_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # PID entry
        pid_row = ttk.Frame(device_frame)
        pid_row.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(
            pid_row,
            text="PIDs (comma-separated or range like 1-10):",
        ).pack(anchor=tk.W)
        
        self.batch_pids_entry = ttk.Entry(device_frame, width=50)
        self.batch_pids_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Help text
        help_label = ttk.Label(
            device_frame,
            text="Examples: 1,2,3,4 or 1-10 or 1,2,5-8,10",
            foreground="gray",
        )
        help_label.pack(anchor=tk.W)
        
        # Operation selection
        op_frame = ttk.LabelFrame(parent, text="Operation", padding=10)
        op_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.batch_op_var = tk.StringVar(value="bootstrap")
        
        ttk.Radiobutton(
            op_frame,
            text="Bootstrap devices",
            variable=self.batch_op_var,
            value="bootstrap",
        ).pack(anchor=tk.W)
        
        ttk.Radiobutton(
            op_frame,
            text="Factory reset devices",
            variable=self.batch_op_var,
            value="reset",
        ).pack(anchor=tk.W)

        # Ladder only unprovisioned devices in range (skip already-provisioned
        # ones instead of failing on them).
        ttk.Radiobutton(
            op_frame,
            text="Provision discovered (scan range, skip already-provisioned)",
            variable=self.batch_op_var,
            value="provision_discovered",
        ).pack(anchor=tk.W)
        
        # Key source for bootstrap
        self.batch_key_source_var = tk.StringVar(value="file")
        
        key_source_frame = ttk.Frame(op_frame)
        key_source_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(key_source_frame, text="Key source:").pack(side=tk.LEFT)
        ttk.Radiobutton(
            key_source_frame,
            text="From file",
            variable=self.batch_key_source_var,
            value="file",
        ).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Radiobutton(
            key_source_frame,
            text="Generate random",
            variable=self.batch_key_source_var,
            value="generate",
        ).pack(side=tk.LEFT, padx=(10, 0))
        
        # Action buttons
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X)
        
        self.batch_btn = ttk.Button(
            action_frame,
            text="Execute Batch Operation",
            command=self._on_batch_click,
        )
        self.batch_btn.pack(side=tk.RIGHT)
    
    def _parse_pid_list(self, text: str) -> List[int]:
        """Parse PID list from text (e.g., '1,2,3' or '1-10')"""
        pids = []
        parts = text.replace(" ", "").split(",")
        
        for part in parts:
            if not part:
                continue
            
            if "-" in part:
                # Range
                try:
                    start, end = part.split("-", 1)
                    start_pid = int(start)
                    end_pid = int(end)
                    pids.extend(range(start_pid, end_pid + 1))
                except ValueError:
                    raise ValueError(f"Invalid range: {part}")
            else:
                # Single PID
                try:
                    pids.append(int(part))
                except ValueError:
                    raise ValueError(f"Invalid PID: {part}")
        
        return sorted(set(pids))
    
    def _on_batch_click(self) -> None:
        """Handle batch operation button click"""
        try:
            pids = self._parse_pid_list(self.batch_pids_entry.get().strip())
        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e))
            return
        
        if not pids:
            messagebox.showerror("Invalid Input", "Please enter at least one PID")
            return
        
        operation = self.batch_op_var.get()
        
        if operation == "bootstrap":
            key_source = self.batch_key_source_var.get()
            if key_source == "generate":
                keys = {
                    "provisioning_key": secrets.token_bytes(32),
                    "provisioning_salt": secrets.token_bytes(16),
                    "provisioning_key_id": generate_key_id(),
                    "integrator_key": secrets.token_bytes(32),
                    "integrator_salt": secrets.token_bytes(16),
                    "integrator_key_id": generate_key_id(),
                    "seed_key": secrets.token_bytes(32),
                    "seed_salt": secrets.token_bytes(16),
                    "seed_key_id": generate_key_id(),
                }
            else:
                keys = None
            
            if self.on_batch_bootstrap:
                self.on_batch_bootstrap(pids, keys)

        elif operation == "provision_discovered":
            source = self.batch_key_source_var.get()
            if source == "file":
                keys = {}
            else:
                try:
                    keys = self._get_keys_from_entries()
                except ValueError as e:
                    messagebox.showerror("Invalid Keys", str(e))
                    return
            if self.on_provision_discovered:
                self.on_provision_discovered(pids, keys)
        
        elif operation == "reset":
            # Confirm
            if not messagebox.askyesno(
                "Confirm Batch Reset",
                f"Are you sure you want to factory reset {len(pids)} device(s)?\n\n"
                f"PIDs: {', '.join(map(str, pids[:10]))}{'...' if len(pids) > 10 else ''}\n\n"
                "This will delete ALL cryptographic keys from these devices.",
            ):
                return
            
            # Reset each device
            for pid in pids:
                if self.on_factory_reset:
                    self.on_factory_reset(pid)
    
    def set_target_pid(self, pid: int) -> None:
        """Set target PID in bootstrap and reset tabs"""
        self.bootstrap_pid_entry.delete(0, tk.END)
        self.bootstrap_pid_entry.insert(0, str(pid))
        
        self.reset_pid_entry.delete(0, tk.END)
        self.reset_pid_entry.insert(0, str(pid))
    
    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable operations"""
        state = tk.NORMAL if enabled else tk.DISABLED
        
        self.bootstrap_btn.configure(state=state)
        self.batch_btn.configure(state=state)
        
        # Reset button depends on confirmation checkbox
        if enabled and self.reset_confirm_var.get():
            self.reset_btn.configure(state=tk.NORMAL)
        else:
            self.reset_btn.configure(state=tk.DISABLED)

