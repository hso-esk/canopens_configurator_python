# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Settings panel: CAN interface, secure keys, config import/export."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from typing import Optional, Callable, List
from pathlib import Path


class PasswordDialog(tk.Toplevel):
    """Dialog for password entry"""
    
    def __init__(self, parent, title="Enter Password", confirm=False):
        super().__init__(parent)
        self.title(title)
        self.result = None
        self.confirm = confirm
        
        self.transient(parent)
        self.grab_set()
        
        # Center on parent
        self.geometry("350x180" if confirm else "350x130")
        self.resizable(False, False)
        
        self._create_widgets()
        
        # Center
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - 350) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - 150) // 2
        self.geometry(f"+{x}+{y}")
        
        self.password_entry.focus_set()
        self.bind("<Return>", lambda e: self._on_ok())
        self.bind("<Escape>", lambda e: self._on_cancel())
    
    def _create_widgets(self):
        main = ttk.Frame(self, padding=20)
        main.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main, text="Password:").pack(anchor=tk.W)
        self.password_entry = ttk.Entry(main, show="*", width=40)
        self.password_entry.pack(fill=tk.X, pady=(5, 10))
        
        if self.confirm:
            ttk.Label(main, text="Confirm Password:").pack(anchor=tk.W)
            self.confirm_entry = ttk.Entry(main, show="*", width=40)
            self.confirm_entry.pack(fill=tk.X, pady=(5, 10))
        
        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(btn_frame, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(btn_frame, text="OK", command=self._on_ok).pack(side=tk.RIGHT)
    
    def _on_ok(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password is required", parent=self)
            return
        
        if self.confirm:
            confirm = self.confirm_entry.get()
            if password != confirm:
                messagebox.showerror("Error", "Passwords don't match", parent=self)
                return
            if len(password) < 8:
                messagebox.showerror("Error", "Password must be at least 8 characters", parent=self)
                return
        
        self.result = password
        self.destroy()
    
    def _on_cancel(self):
        self.result = None
        self.destroy()
    
    def show(self):
        self.wait_window()
        return self.result


class ConfigPanel(ttk.Frame):
    """Application settings: CAN interfaces, key management, config import/export."""
    
    def __init__(
        self,
        parent: tk.Widget,
        on_settings_change: Optional[Callable[[dict], None]] = None,
        on_export: Optional[Callable[[str], None]] = None,
        on_import: Optional[Callable[[str, bool], None]] = None,
        on_keys_loaded: Optional[Callable[[], None]] = None,
    ):
        super().__init__(parent)
        
        self.on_settings_change = on_settings_change
        self.on_export = on_export
        self.on_import = on_import
        self.on_keys_loaded = on_keys_loaded
        
        self._settings = {
            "interface": "vcan0",
            "keys_file": "keys.txt",
            "keys_encrypted": False,
            "config_file": "groups_config.json",
            "tx_delay_us": 0,
            "discovery_timeout": 1.0,
            "discovery_start_pid": 1,
            "discovery_end_pid": 127,
            "discovery_key": 1,  # 1=Zero, 15=Provisioning, 14=Integrator (Seed cannot open a session)
            "establish_keys_after_discovery": False,
            "establish_initial_key": 15,  # Default to Provisioning
        }
        
        self._key_store = None
        self._create_widgets()
    
    def _create_widgets(self) -> None:
        """Create panel widgets"""
        # Notebook for settings sections
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Connection settings tab
        conn_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(conn_frame, text="Connection")
        self._create_connection_tab(conn_frame)
        
        # Keys Management tab (NEW)
        keys_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(keys_frame, text="Keys")
        self._create_keys_tab(keys_frame)
        
        # Files settings tab
        files_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(files_frame, text="Files")
        self._create_files_tab(files_frame)
        
        # Discovery settings tab
        discovery_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(discovery_frame, text="Discovery")
        self._create_discovery_tab(discovery_frame)
        
        # Import/Export tab
        io_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(io_frame, text="Import/Export")
        self._create_io_tab(io_frame)
    
    def _create_connection_tab(self, parent: ttk.Frame) -> None:
        """Create connection settings tab"""
        # CAN Interface
        interface_frame = ttk.LabelFrame(parent, text="CAN Interface", padding=10)
        interface_frame.pack(fill=tk.X, pady=(0, 10))
        
        interface_row = ttk.Frame(interface_frame)
        interface_row.pack(fill=tk.X)
        
        ttk.Label(interface_row, text="Interface:").pack(side=tk.LEFT)
        
        self.interface_var = tk.StringVar(value=self._settings["interface"])
        self.interface_combo = ttk.Combobox(
            interface_row,
            textvariable=self.interface_var,
            values=["vcan0", "can0", "can1", "slcan0"],
            width=15,
        )
        self.interface_combo.pack(side=tk.LEFT, padx=(5, 0))
        
        refresh_btn = ttk.Button(
            interface_row,
            text="↻",
            width=3,
            command=self._refresh_interfaces,
        )
        refresh_btn.pack(side=tk.LEFT, padx=(5, 0))
        
        # Interface status
        status_row = ttk.Frame(interface_frame)
        status_row.pack(fill=tk.X, pady=(10, 0))
        
        self.interface_status_label = ttk.Label(
            status_row,
            text="Status: Not connected",
            foreground="gray",
        )
        self.interface_status_label.pack(side=tk.LEFT)
        
        # TX Delay
        delay_frame = ttk.LabelFrame(parent, text="Timing", padding=10)
        delay_frame.pack(fill=tk.X, pady=(0, 10))
        
        delay_row = ttk.Frame(delay_frame)
        delay_row.pack(fill=tk.X)
        
        ttk.Label(delay_row, text="TX Delay (µs):").pack(side=tk.LEFT)
        
        self.tx_delay_var = tk.StringVar(value=str(self._settings["tx_delay_us"]))
        self.tx_delay_entry = ttk.Entry(
            delay_row,
            textvariable=self.tx_delay_var,
            width=10,
        )
        self.tx_delay_entry.pack(side=tk.LEFT, padx=(5, 0))
        
        ttk.Label(
            delay_row,
            text="(0 = no delay)",
            foreground="gray",
        ).pack(side=tk.LEFT, padx=(5, 0))
        
        # Apply button
        apply_frame = ttk.Frame(parent)
        apply_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            apply_frame,
            text="Apply Settings",
            command=self._on_apply_click,
        ).pack(side=tk.RIGHT)
    
    def _create_keys_tab(self, parent: ttk.Frame) -> None:
        """Create keys management tab"""
        # Key Store Type
        type_frame = ttk.LabelFrame(parent, text="Key Storage Type", padding=10)
        type_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.key_type_var = tk.StringVar(value="plain")
        
        ttk.Radiobutton(
            type_frame,
            text="Plain text file (keys.txt) - Not recommended for production",
            variable=self.key_type_var,
            value="plain",
            command=self._on_key_type_change,
        ).pack(anchor=tk.W)
        
        ttk.Radiobutton(
            type_frame,
            text="Encrypted key store (keys.enc) - Password protected, AES-256",
            variable=self.key_type_var,
            value="encrypted",
            command=self._on_key_type_change,
        ).pack(anchor=tk.W)
        
        # Key Store Status
        status_frame = ttk.LabelFrame(parent, text="Key Store Status", padding=10)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.key_status_label = ttk.Label(
            status_frame,
            text="No key store loaded",
            foreground="gray",
        )
        self.key_status_label.pack(anchor=tk.W)
        
        self.key_count_label = ttk.Label(
            status_frame,
            text="",
            foreground="gray",
        )
        self.key_count_label.pack(anchor=tk.W, pady=(5, 0))
        
        # Key Store Actions
        action_frame = ttk.LabelFrame(parent, text="Key Store Actions", padding=10)
        action_frame.pack(fill=tk.X, pady=(0, 10))
        
        btn_row1 = ttk.Frame(action_frame)
        btn_row1.pack(fill=tk.X, pady=(0, 5))
        
        self.load_keys_btn = ttk.Button(
            btn_row1,
            text="Load Key Store",
            command=self._load_key_store,
        )
        self.load_keys_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.create_keys_btn = ttk.Button(
            btn_row1,
            text="Create New Store",
            command=self._create_key_store,
        )
        self.create_keys_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.import_keys_btn = ttk.Button(
            btn_row1,
            text="Import from Plain Text",
            command=self._import_plain_keys,
        )
        self.import_keys_btn.pack(side=tk.LEFT)
        
        btn_row2 = ttk.Frame(action_frame)
        btn_row2.pack(fill=tk.X)
        
        self.view_keys_btn = ttk.Button(
            btn_row2,
            text="View Keys",
            command=self._view_keys,
            state=tk.DISABLED,
        )
        self.view_keys_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.export_keys_btn = ttk.Button(
            btn_row2,
            text="Export to Plain Text",
            command=self._export_plain_keys,
            state=tk.DISABLED,
        )
        self.export_keys_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.change_pass_btn = ttk.Button(
            btn_row2,
            text="Change Password",
            command=self._change_password,
            state=tk.DISABLED,
        )
        self.change_pass_btn.pack(side=tk.LEFT)
        
        # Key File Path
        path_frame = ttk.LabelFrame(parent, text="Key File Path", padding=10)
        path_frame.pack(fill=tk.X)
        
        path_row = ttk.Frame(path_frame)
        path_row.pack(fill=tk.X)
        
        self.keys_file_var = tk.StringVar(value=self._settings["keys_file"])
        self.keys_file_entry = ttk.Entry(
            path_row,
            textvariable=self.keys_file_var,
            width=50,
        )
        self.keys_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Button(
            path_row,
            text="Browse...",
            command=self._browse_keys_file,
        ).pack(side=tk.LEFT, padx=(5, 0))
    
    def _create_files_tab(self, parent: ttk.Frame) -> None:
        """Create files settings tab"""
        # Config file
        config_frame = ttk.LabelFrame(parent, text="Configuration File", padding=10)
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        config_row = ttk.Frame(config_frame)
        config_row.pack(fill=tk.X)
        
        self.config_file_var = tk.StringVar(value=self._settings["config_file"])
        self.config_file_entry = ttk.Entry(
            config_row,
            textvariable=self.config_file_var,
            width=50,
        )
        self.config_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Button(
            config_row,
            text="Browse...",
            command=self._browse_config_file,
        ).pack(side=tk.LEFT, padx=(5, 0))
        
        config_help = ttk.Label(
            config_frame,
            text="Stores group definitions and device registry (JSON format)",
            foreground="gray",
        )
        config_help.pack(anchor=tk.W, pady=(5, 0))
        
        # Apply button
        apply_frame = ttk.Frame(parent)
        apply_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            apply_frame,
            text="Apply Settings",
            command=self._on_apply_click,
        ).pack(side=tk.RIGHT)
    
    def _create_discovery_tab(self, parent: ttk.Frame) -> None:
        """Create discovery settings tab"""
        # PID Range
        range_frame = ttk.LabelFrame(parent, text="PID Range", padding=10)
        range_frame.pack(fill=tk.X, pady=(0, 10))
        
        range_row = ttk.Frame(range_frame)
        range_row.pack(fill=tk.X)
        
        ttk.Label(range_row, text="Start PID:").pack(side=tk.LEFT)
        
        self.start_pid_var = tk.StringVar(value=str(self._settings["discovery_start_pid"]))
        self.start_pid_entry = ttk.Entry(
            range_row,
            textvariable=self.start_pid_var,
            width=6,
        )
        self.start_pid_entry.pack(side=tk.LEFT, padx=(5, 15))
        
        ttk.Label(range_row, text="End PID:").pack(side=tk.LEFT)
        
        self.end_pid_var = tk.StringVar(value=str(self._settings["discovery_end_pid"]))
        self.end_pid_entry = ttk.Entry(
            range_row,
            textvariable=self.end_pid_var,
            width=6,
        )
        self.end_pid_entry.pack(side=tk.LEFT, padx=(5, 0))
        
        range_help = ttk.Label(
            range_frame,
            text="Valid PID range: 1-127",
            foreground="gray",
        )
        range_help.pack(anchor=tk.W, pady=(5, 0))
        
        # Timeout
        timeout_frame = ttk.LabelFrame(parent, text="Timeout", padding=10)
        timeout_frame.pack(fill=tk.X, pady=(0, 10))
        
        timeout_row = ttk.Frame(timeout_frame)
        timeout_row.pack(fill=tk.X)
        
        ttk.Label(timeout_row, text="Timeout per device (seconds):").pack(side=tk.LEFT)
        
        self.timeout_var = tk.StringVar(value=str(self._settings["discovery_timeout"]))
        self.timeout_entry = ttk.Entry(
            timeout_row,
            textvariable=self.timeout_var,
            width=6,
        )
        self.timeout_entry.pack(side=tk.LEFT, padx=(5, 0))
        
        # Discovery Key Selection
        key_frame = ttk.LabelFrame(parent, text="Discovery Key", padding=5)
        key_frame.pack(fill=tk.X, pady=(0, 10))
        
        key_row = ttk.Frame(key_frame)
        key_row.pack(fill=tk.X)
        
        ttk.Label(key_row, text="Key to use for discovery:").pack(side=tk.LEFT)
        
        self.discovery_key_var = tk.StringVar(value="Zero (1)")
        self.discovery_key_combo = ttk.Combobox(
            key_row,
            textvariable=self.discovery_key_var,
            values=["Zero (1)", "Provisioning (15)", "Integrator (14)"],
            state="readonly",
            width=18,
        )
        self.discovery_key_combo.pack(side=tk.LEFT, padx=(5, 0))
        
        key_help = ttk.Label(
            key_frame,
            text="Select which key to use when scanning for devices",
            font=("", 8),
            foreground="gray",
        )
        key_help.pack(anchor=tk.W, pady=(5, 0))
        
        # Key Establishment After Discovery
        establish_frame = ttk.LabelFrame(parent, text="Key Establishment", padding=10)
        establish_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.establish_keys_var = tk.BooleanVar(value=False)
        establish_check = ttk.Checkbutton(
            establish_frame,
            text="Establish keys after discovery",
            variable=self.establish_keys_var,
        )
        establish_check.pack(anchor=tk.W)
        
        establish_help = ttk.Label(
            establish_frame,
            text="If enabled, keys will be written to discovered devices using sequential key establishment",
            font=("", 8),
            foreground="gray",
        )
        establish_help.pack(anchor=tk.W, pady=(5, 0))
        
        # Initial key selector for establishment
        establish_key_row = ttk.Frame(establish_frame)
        establish_key_row.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(establish_key_row, text="Initial session key:").pack(side=tk.LEFT)
        
        self.establish_initial_key_var = tk.StringVar(value="Zero (1)")
        self.establish_initial_key_combo = ttk.Combobox(
            establish_key_row,
            textvariable=self.establish_initial_key_var,
            values=["Zero (1)", "Provisioning (15)", "Integrator (14)"],
            state="readonly",
            width=18,
        )
        self.establish_initial_key_combo.pack(side=tk.LEFT, padx=(5, 0))
        
        establish_key_help = ttk.Label(
            establish_frame,
            text="Each subsequent key will be written in a new session using the previously written key",
            font=("", 8),
            foreground="gray",
        )
        establish_key_help.pack(anchor=tk.W, pady=(5, 0))
        
        # Apply button
        apply_frame = ttk.Frame(parent)
        apply_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            apply_frame,
            text="Apply Settings",
            command=self._on_apply_click,
        ).pack(side=tk.RIGHT)
    
    def _create_io_tab(self, parent: ttk.Frame) -> None:
        """Create import/export tab"""
        # Export section
        export_frame = ttk.LabelFrame(parent, text="Export Configuration", padding=10)
        export_frame.pack(fill=tk.X, pady=(0, 10))
        
        export_desc = ttk.Label(
            export_frame,
            text="Export all groups and device registry to a file.",
            wraplength=400,
        )
        export_desc.pack(anchor=tk.W, pady=(0, 10))
        
        export_btn = ttk.Button(
            export_frame,
            text="Export Configuration...",
            command=self._on_export_click,
        )
        export_btn.pack(anchor=tk.W)
        
        # Import section
        import_frame = ttk.LabelFrame(parent, text="Import Configuration", padding=10)
        import_frame.pack(fill=tk.X, pady=(0, 10))
        
        import_desc = ttk.Label(
            import_frame,
            text="Import groups and device registry from a file.",
            wraplength=400,
        )
        import_desc.pack(anchor=tk.W, pady=(0, 10))
        
        self.merge_var = tk.BooleanVar(value=False)
        merge_check = ttk.Checkbutton(
            import_frame,
            text="Merge with existing configuration (don't replace)",
            variable=self.merge_var,
        )
        merge_check.pack(anchor=tk.W, pady=(0, 10))
        
        import_btn = ttk.Button(
            import_frame,
            text="Import Configuration...",
            command=self._on_import_click,
        )
        import_btn.pack(anchor=tk.W)
        
        # Warning
        warning_label = ttk.Label(
            parent,
            text="⚠ Importing without merge will replace all existing groups and devices.",
            foreground="orange",
        )
        warning_label.pack(anchor=tk.W, pady=(10, 0))
    
    # Key Management Methods
    
    def _on_key_type_change(self) -> None:
        """Handle key type change"""
        key_type = self.key_type_var.get()
        current_path = self.keys_file_var.get()
        
        if key_type == "encrypted":
            if current_path.endswith(".txt"):
                self.keys_file_var.set(current_path.replace(".txt", ".enc"))
            elif not current_path.endswith(".enc"):
                self.keys_file_var.set(current_path + ".enc")
            self._settings["keys_encrypted"] = True
        else:
            if current_path.endswith(".enc"):
                self.keys_file_var.set(current_path.replace(".enc", ".txt"))
            self._settings["keys_encrypted"] = False
    
    def _load_key_store(self) -> None:
        """Load a key store"""
        from ..core.logging_util import log_info, log_error, log_debug
        
        path = self.keys_file_var.get()
        log_info("config_panel", "Loading key store from: %s", path)
        
        if not Path(path).exists():
            log_error("config_panel", "File not found: %s", path)
            messagebox.showerror("Error", f"File not found: {path}", parent=self)
            return
        
        if path.endswith(".enc"):
            log_info("config_panel", "Detected encrypted key store")
            # Encrypted store - need password
            dialog = PasswordDialog(self, "Enter Key Store Password")
            password = dialog.show()
            if not password:
                log_debug("config_panel", "Password dialog cancelled")
                return
            
            try:
                from ..core.secure_keys import SecureKeyStore
                log_debug("config_panel", "Creating SecureKeyStore object")
                self._key_store = SecureKeyStore(path)
                log_debug("config_panel", "Attempting to load and decrypt store")
                if self._key_store.load(password):
                    keys = self._key_store.list_keys()
                    log_info("config_panel", "Key store loaded successfully. Keys: %s", ", ".join(keys))
                    self._update_key_status()
                    self.key_type_var.set("encrypted")
                    self._settings["keys_encrypted"] = True
                    messagebox.showinfo("Success", "Key store loaded successfully", parent=self)
                    if self.on_keys_loaded:
                        self.on_keys_loaded()
                else:
                    log_error("config_panel", "Failed to load key store (decryption failed)")
                    messagebox.showerror("Error", "Failed to load key store (wrong password?)", parent=self)
                    self._key_store = None
            except Exception as e:
                log_error("config_panel", "Exception loading key store: %s", str(e))
                import traceback
                log_debug("config_panel", "Traceback: %s", traceback.format_exc())
                messagebox.showerror("Error", f"Failed to load key store: {e}", parent=self)
                self._key_store = None
        else:
            log_info("config_panel", "Detected plain text key file")
            # Plain text - just verify it exists and has keys
            try:
                from ..core.keys import load_kv_hex_file
                log_debug("config_panel", "Loading provisioning_key from plain text file")
                test_key = load_kv_hex_file(path, "provisioning_key")
                if test_key:
                    log_info("config_panel", "Plain text keys loaded. provisioning_key: %d bytes", len(test_key))
                    self.key_type_var.set("plain")
                    self._settings["keys_encrypted"] = False
                    self._key_store = None  # Plain text doesn't use store object
                    self._update_key_status_plain(path)
                    messagebox.showinfo("Success", "Keys file loaded successfully", parent=self)
                    if self.on_keys_loaded:
                        self.on_keys_loaded()
                else:
                    log_error("config_panel", "No valid keys found in plain text file")
                    messagebox.showerror("Error", "No valid keys found in file", parent=self)
            except Exception as e:
                log_error("config_panel", "Exception loading plain text keys: %s", str(e))
                messagebox.showerror("Error", f"Failed to load keys: {e}", parent=self)
    
    def _create_key_store(self) -> None:
        """Create a new encrypted key store"""
        path = filedialog.asksaveasfilename(
            title="Create New Key Store",
            defaultextension=".enc",
            filetypes=[("Encrypted key store", "*.enc"), ("All files", "*.*")],
        )
        if not path:
            return
        
        dialog = PasswordDialog(self, "Create Password", confirm=True)
        password = dialog.show()
        if not password:
            return
        
        generate = messagebox.askyesno(
            "Generate Keys",
            "Generate new random keys for the store?",
            parent=self,
        )
        
        try:
            from ..core.secure_keys import SecureKeyStore
            import secrets
            
            self._key_store = SecureKeyStore(path)
            self._key_store.create(password)
            
            if generate:
                self._key_store.set_key("provisioning_key", secrets.token_bytes(32),
                                       description="Device provisioning key", key_type="provisioning")
                self._key_store.set_key("provisioning_salt", secrets.token_bytes(16),
                                       description="Device provisioning salt", key_type="provisioning")
                self._key_store.set_key("integrator_key", secrets.token_bytes(32),
                                       description="Integrator key", key_type="integrator")
                self._key_store.set_key("integrator_salt", secrets.token_bytes(16),
                                       description="Integrator salt", key_type="integrator")
                self._key_store.set_key("seed_key", secrets.token_bytes(32),
                                       description="Seed key", key_type="seed")
                self._key_store.set_key("seed_salt", secrets.token_bytes(16),
                                       description="Seed salt", key_type="seed")
            
            self._key_store.save()
            self.keys_file_var.set(path)
            self.key_type_var.set("encrypted")
            self._settings["keys_encrypted"] = True
            self._update_key_status()
            
            msg = f"Created encrypted key store: {path}"
            if generate:
                msg += f"\nGenerated {len(self._key_store.list_keys())} keys"
            messagebox.showinfo("Success", msg, parent=self)
            
            if self.on_keys_loaded:
                self.on_keys_loaded()
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create key store: {e}", parent=self)
    
    def _import_plain_keys(self) -> None:
        """Import keys from plain text file to encrypted store"""
        source = filedialog.askopenfilename(
            title="Select Plain Text Keys File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not source:
            return
        
        dest = filedialog.asksaveasfilename(
            title="Save Encrypted Key Store",
            defaultextension=".enc",
            filetypes=[("Encrypted key store", "*.enc"), ("All files", "*.*")],
        )
        if not dest:
            return
        
        dialog = PasswordDialog(self, "Create Password for Encrypted Store", confirm=True)
        password = dialog.show()
        if not password:
            return
        
        try:
            from ..core.secure_keys import SecureKeyStore
            
            self._key_store = SecureKeyStore(dest)
            if self._key_store.import_from_plain_text(source, password):
                self.keys_file_var.set(dest)
                self.key_type_var.set("encrypted")
                self._settings["keys_encrypted"] = True
                self._update_key_status()
                
                messagebox.showinfo(
                    "Success",
                    f"Imported {len(self._key_store.list_keys())} keys from {source}",
                    parent=self,
                )
                
                if self.on_keys_loaded:
                    self.on_keys_loaded()
            else:
                messagebox.showerror("Error", "Failed to import keys", parent=self)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import keys: {e}", parent=self)
    
    def _view_keys(self) -> None:
        """View keys in the store"""
        if not self._key_store:
            messagebox.showinfo("Info", "No encrypted key store loaded", parent=self)
            return
        
        keys = self._key_store.list_keys()
        if not keys:
            messagebox.showinfo("Info", "No keys in store", parent=self)
            return
        
        # Create view dialog
        dialog = tk.Toplevel(self)
        dialog.title("Key Store Contents")
        dialog.geometry("500x400")
        dialog.transient(self)
        
        main = ttk.Frame(dialog, padding=10)
        main.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main, text=f"Profile: {self._key_store.active_profile}",
                  font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W)
        ttk.Label(main, text=f"Keys: {len(keys)}").pack(anchor=tk.W, pady=(0, 10))
        
        # Key list
        tree = ttk.Treeview(main, columns=("type", "size"), show="headings")
        tree.heading("type", text="Type")
        tree.heading("size", text="Size")
        tree.column("type", width=100)
        tree.column("size", width=80)
        
        for key_name in sorted(keys):
            info = self._key_store.get_key_info(key_name)
            if info:
                tree.insert("", tk.END, text=key_name, 
                           values=(info.get("key_type", "raw"), f"{info.get('size', 0)} bytes"))
        
        scrollbar = ttk.Scrollbar(main, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)
    
    def _export_plain_keys(self) -> None:
        """Export keys to plain text"""
        if not self._key_store:
            messagebox.showinfo("Info", "No encrypted key store loaded", parent=self)
            return
        
        if not messagebox.askyesno(
            "Warning",
            "Exporting to plain text will create an UNENCRYPTED file!\n\n"
            "The exported file will contain your keys in readable format.\n\n"
            "Continue?",
            parent=self,
        ):
            return
        
        dest = filedialog.asksaveasfilename(
            title="Export to Plain Text",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not dest:
            return
        
        try:
            if self._key_store.export_to_plain_text(dest):
                messagebox.showwarning(
                    "Exported",
                    f"Keys exported to PLAIN TEXT file:\n{dest}\n\n"
                    "⚠ This file is NOT encrypted!",
                    parent=self,
                )
            else:
                messagebox.showerror("Error", "Failed to export keys", parent=self)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export keys: {e}", parent=self)
    
    def _change_password(self) -> None:
        """Change key store password"""
        if not self._key_store:
            messagebox.showinfo("Info", "No encrypted key store loaded", parent=self)
            return
        
        old_dialog = PasswordDialog(self, "Enter Current Password")
        old_password = old_dialog.show()
        if not old_password:
            return
        
        new_dialog = PasswordDialog(self, "Enter New Password", confirm=True)
        new_password = new_dialog.show()
        if not new_password:
            return
        
        try:
            if self._key_store.change_password(old_password, new_password):
                messagebox.showinfo("Success", "Password changed successfully", parent=self)
            else:
                messagebox.showerror("Error", "Failed to change password (wrong current password?)", parent=self)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change password: {e}", parent=self)
    
    def _update_key_status(self) -> None:
        """Update key status display for encrypted store"""
        if self._key_store:
            self.key_status_label.configure(
                text=f"✓ Encrypted store loaded: {self._key_store.path.name}",
                foreground="green",
            )
            keys = self._key_store.list_keys()
            self.key_count_label.configure(
                text=f"Keys: {len(keys)} ({', '.join(keys[:3])}{'...' if len(keys) > 3 else ''})",
                foreground="black",
            )
            self.view_keys_btn.configure(state=tk.NORMAL)
            self.export_keys_btn.configure(state=tk.NORMAL)
            self.change_pass_btn.configure(state=tk.NORMAL)
        else:
            self.key_status_label.configure(
                text="No key store loaded",
                foreground="gray",
            )
            self.key_count_label.configure(text="")
            self.view_keys_btn.configure(state=tk.DISABLED)
            self.export_keys_btn.configure(state=tk.DISABLED)
            self.change_pass_btn.configure(state=tk.DISABLED)
    
    def _update_key_status_plain(self, path: str) -> None:
        """Update key status display for plain text file"""
        self.key_status_label.configure(
            text=f"⚠ Plain text file: {Path(path).name}",
            foreground="orange",
        )
        self.key_count_label.configure(
            text="Warning: Keys are NOT encrypted",
            foreground="orange",
        )
        self.view_keys_btn.configure(state=tk.DISABLED)
        self.export_keys_btn.configure(state=tk.DISABLED)
        self.change_pass_btn.configure(state=tk.DISABLED)
    
    def _refresh_interfaces(self) -> None:
        """Refresh available CAN interfaces"""
        interfaces = self._get_can_interfaces()
        self.interface_combo["values"] = interfaces
        
        if interfaces:
            messagebox.showinfo(
                "Interfaces Found",
                f"Found {len(interfaces)} interface(s):\n" + "\n".join(interfaces)
            )
        else:
            messagebox.showwarning(
                "No Interfaces",
                "No CAN interfaces found.\n\n"
                "Make sure a CAN interface is configured and up."
            )
    
    def _get_can_interfaces(self) -> List[str]:
        """Get list of available CAN interfaces"""
        interfaces = []
        
        try:
            # Try to get interfaces from /sys/class/net
            net_path = Path("/sys/class/net")
            if net_path.exists():
                for iface in net_path.iterdir():
                    name = iface.name
                    if name.startswith(("can", "vcan", "slcan")):
                        interfaces.append(name)
        except Exception:
            pass
        
        # Always include common defaults
        defaults = ["vcan0", "can0", "can1", "slcan0"]
        for default in defaults:
            if default not in interfaces:
                interfaces.append(default)
        
        return sorted(interfaces)
    
    def _browse_keys_file(self) -> None:
        """Browse for keys file"""
        key_type = self.key_type_var.get()
        if key_type == "encrypted":
            filetypes = [("Encrypted key store", "*.enc"), ("All files", "*.*")]
        else:
            filetypes = [("Text files", "*.txt"), ("Encrypted key store", "*.enc"), ("All files", "*.*")]
        
        filename = filedialog.askopenfilename(
            title="Select Keys File",
            filetypes=filetypes,
        )
        if filename:
            self.keys_file_var.set(filename)
            if filename.endswith(".enc"):
                self.key_type_var.set("encrypted")
            else:
                self.key_type_var.set("plain")
    
    def _browse_config_file(self) -> None:
        """Browse for config file"""
        filename = filedialog.askopenfilename(
            title="Select Configuration File",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if filename:
            self.config_file_var.set(filename)
    
    def _on_apply_click(self) -> None:
        """Handle apply button click"""
        try:
            settings = self._get_settings()
            self._settings.update(settings)
            
            if self.on_settings_change:
                self.on_settings_change(settings)
            
            messagebox.showinfo("Settings Applied", "Settings have been applied successfully.")
        except ValueError as e:
            messagebox.showerror("Invalid Settings", str(e))
    
    def _get_settings(self) -> dict:
        """Get current settings from UI"""
        try:
            tx_delay = int(self.tx_delay_var.get().strip())
        except ValueError:
            raise ValueError("TX Delay must be a number")
        
        try:
            start_pid = int(self.start_pid_var.get().strip())
            end_pid = int(self.end_pid_var.get().strip())
            if not (1 <= start_pid <= 127) or not (1 <= end_pid <= 127):
                raise ValueError()
            if start_pid > end_pid:
                raise ValueError()
        except ValueError:
            raise ValueError("PID range must be valid numbers between 1 and 127")
        
        try:
            timeout = float(self.timeout_var.get().strip())
            if timeout <= 0:
                raise ValueError()
        except ValueError:
            raise ValueError("Timeout must be a positive number")
        
        return {
            "interface": self.interface_var.get().strip(),
            "keys_file": self.keys_file_var.get().strip(),
            "keys_encrypted": self.key_type_var.get() == "encrypted",
            "config_file": self.config_file_var.get().strip(),
            "tx_delay_us": tx_delay,
            "discovery_timeout": timeout,
            "discovery_start_pid": start_pid,
            "discovery_end_pid": end_pid,
            "discovery_key": self._get_discovery_key_value(),
            "establish_keys_after_discovery": self.establish_keys_var.get(),
            "establish_initial_key": self._get_establish_initial_key_value(),
        }
    
    def _get_establish_initial_key_value(self) -> int:
        """Get the establishment initial key selector value from combo box"""
        key_text = self.establish_initial_key_var.get()
        if "1)" in key_text or "Zero" in key_text:
            return 1
        elif "15" in key_text or "Provisioning" in key_text:
            return 15
        elif "14" in key_text or "Integrator" in key_text:
            return 14
        return 15  # Default to provisioning
    
    def _get_discovery_key_value(self) -> int:
        """Get the discovery key selector value from combo box"""
        key_text = self.discovery_key_var.get()
        if "1)" in key_text or "Zero" in key_text:
            return 1
        elif "15" in key_text or "Provisioning" in key_text:
            return 15
        elif "14" in key_text or "Integrator" in key_text:
            return 14
        return 1  # Default to Zero
    
    def _on_export_click(self) -> None:
        """Handle export button click"""
        filename = filedialog.asksaveasfilename(
            title="Export Configuration",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if filename and self.on_export:
            self.on_export(filename)
    
    def _on_import_click(self) -> None:
        """Handle import button click"""
        filename = filedialog.askopenfilename(
            title="Import Configuration",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if filename and self.on_import:
            merge = self.merge_var.get()
            self.on_import(filename, merge)
    
    def get_settings(self) -> dict:
        """Get current settings"""
        return self._settings.copy()
    
    def set_settings(self, settings: dict) -> None:
        """Set settings from dictionary"""
        self._settings.update(settings)
        
        # Update UI
        self.interface_var.set(settings.get("interface", "vcan0"))
        self.keys_file_var.set(settings.get("keys_file", "keys.txt"))
        self.config_file_var.set(settings.get("config_file", "groups_config.json"))
        self.tx_delay_var.set(str(settings.get("tx_delay_us", 0)))
        self.timeout_var.set(str(settings.get("discovery_timeout", 1.0)))
        self.start_pid_var.set(str(settings.get("discovery_start_pid", 1)))
        self.end_pid_var.set(str(settings.get("discovery_end_pid", 127)))
        
        # Set discovery key combo box
        discovery_key = settings.get("discovery_key", 1)
        key_map = {1: "Zero (1)", 15: "Provisioning (15)", 14: "Integrator (14)"}
        self.discovery_key_var.set(key_map.get(discovery_key, "Zero (1)"))
        
        # Set key establishment options
        self.establish_keys_var.set(settings.get("establish_keys_after_discovery", False))
        establish_initial_key = settings.get("establish_initial_key", 1)
        self.establish_initial_key_var.set(key_map.get(establish_initial_key, "Zero (1)"))
        
        if settings.get("keys_encrypted", False):
            self.key_type_var.set("encrypted")
        else:
            self.key_type_var.set("plain")
    
    def set_interface_status(self, connected: bool, message: str = "") -> None:
        """Set interface connection status"""
        if connected:
            self.interface_status_label.configure(
                text=f"Status: Connected {message}".strip(),
                foreground="green",
            )
        else:
            self.interface_status_label.configure(
                text=f"Status: Not connected {message}".strip(),
                foreground="red",
            )
    
    def get_key_store(self):
        """Get the loaded key store (for other panels to use)"""
        return self._key_store
    
    def get_key(self, name: str) -> "bytes | None":
        """Get a key by name (from store or plain text)"""
        if self._key_store:
            return self._key_store.get_key(name)
        else:
            # Fall back to plain text
            from ..core.keys import load_kv_hex_file
            return load_kv_hex_file(self.keys_file_var.get(), name)
