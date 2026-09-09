# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Main window: menu/toolbar/panel layout, coordinates panels + app state."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Optional, Dict, Any, List
import queue
import secrets
from datetime import datetime, timezone

from .device_panel import DevicePanel, DeviceDisplayInfo
from .group_panel import GroupPanel, GroupDisplayInfo
from .operations_panel import OperationsPanel
from .config_panel import ConfigPanel
from ..core.keys import generate_key_id
from .dialogs import (
    ConfirmDialog,
    CreateGroupDialog,
    GroupSelectDialog,
    show_error,
    show_info,
)
from .workers import (
    WorkerResult,
    WorkerStatus,
    DiscoveryWorker,
    BootstrapWorker,
    SequentialKeyEstablishmentWorker,
    FactoryResetWorker,
    KeyDistributionWorker,
    BatchBootstrapWorker,
    ProvisionDiscoveredWorker,
)
from ..core.spsec_definitions import SPSEC_KEY_SELECTOR_INTEGRATOR_KEY


class MainWindow(tk.Tk):
    """Top-level window: menu/toolbar, device tree, tabbed group/ops/settings
    panels, and a status bar."""
    
    def __init__(self):
        super().__init__()
        
        self.title("SPsec Configurator")
        self.geometry("1200x800")
        self.minsize(800, 600)
        
        # Application state
        self._settings = {
            "interface": "vcan0",
            "keys_file": "keys.txt",
            "keys_encrypted": False,
            "config_file": "groups_config.json",
            "tx_delay_us": 0,
            "discovery_timeout": 1.0,
            "discovery_start_pid": 1,
            "discovery_end_pid": 127,
            "discovery_key": 1,  # 1=Zero, 15=Provisioning, 14=Integrator, 13=Seed
        }
        
        self._group_manager = None
        self._key_store = None  # Secure key store (if loaded)
        self._temp_keys_file = None  # Temp plain text export for workers
        self._current_worker: Optional[Any] = None
        self._hb_listener: Optional[Any] = None
        self._update_queue: queue.Queue = queue.Queue()
        
        # Create UI
        self._create_menu()
        self._create_toolbar()
        self._create_main_layout()
        self._create_statusbar()
        
        # Configure styles
        self._configure_styles()
        
        # Load initial data
        self.after(100, self._initial_load)
        
        # Start periodic UI updates
        self._schedule_updates()
        
        # Handle window close
        self.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _configure_styles(self) -> None:
        """Configure ttk styles"""
        style = ttk.Style()
        
        # Try to use a modern theme
        available_themes = style.theme_names()
        for theme in ["clam", "alt", "default"]:
            if theme in available_themes:
                style.theme_use(theme)
                break
    
    def _create_menu(self) -> None:
        """Create menu bar"""
        self.menubar = tk.Menu(self)
        self.config(menu=self.menubar)
        
        # File menu
        file_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="File", menu=file_menu)
        
        file_menu.add_command(label="Export Configuration...", command=self._on_export)
        file_menu.add_command(label="Import Configuration...", command=self._on_import)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        
        # Tools menu
        tools_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Tools", menu=tools_menu)
        
        tools_menu.add_command(label="Discover Devices", command=self._on_discover)
        tools_menu.add_separator()
        tools_menu.add_command(label="Create Group...", command=self._on_create_group)
        tools_menu.add_separator()
        tools_menu.add_command(label="Key Management...", command=self._on_key_management)
        tools_menu.add_separator()
        tools_menu.add_command(label="Refresh", command=self._on_refresh)
        
        # Help menu
        help_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Help", menu=help_menu)
        
        help_menu.add_command(label="About", command=self._on_about)
    
    def _create_toolbar(self) -> None:
        """Create toolbar"""
        self.toolbar = ttk.Frame(self)
        self.toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        # Connection indicator
        self.conn_indicator = ttk.Label(
            self.toolbar,
            text="●",
            foreground="gray",
            font=("TkDefaultFont", 14),
        )
        self.conn_indicator.pack(side=tk.LEFT, padx=(0, 5))
        
        # Interface selector
        ttk.Label(self.toolbar, text="Interface:").pack(side=tk.LEFT)
        
        self.interface_var = tk.StringVar(value=self._settings["interface"])
        self.interface_combo = ttk.Combobox(
            self.toolbar,
            textvariable=self.interface_var,
            values=["vcan0", "can0", "can1", "slcan0"],
            width=10,
            state="readonly",
        )
        self.interface_combo.pack(side=tk.LEFT, padx=(5, 15))
        self.interface_combo.bind("<<ComboboxSelected>>", self._on_interface_change)
        
        # Discovery options
        ttk.Label(self.toolbar, text="Range:").pack(side=tk.LEFT, padx=(10, 2))
        self.toolbar_start_pid_var = tk.StringVar(value=str(self._settings["discovery_start_pid"]))
        ttk.Entry(self.toolbar, textvariable=self.toolbar_start_pid_var, width=4).pack(side=tk.LEFT)
        
        ttk.Label(self.toolbar, text="-").pack(side=tk.LEFT)
        
        self.toolbar_end_pid_var = tk.StringVar(value=str(self._settings["discovery_end_pid"]))
        ttk.Entry(self.toolbar, textvariable=self.toolbar_end_pid_var, width=4).pack(side=tk.LEFT)

        ttk.Label(self.toolbar, text="Timeout (s):").pack(side=tk.LEFT, padx=(10, 2))
        self.toolbar_timeout_var = tk.StringVar(value=str(self._settings["discovery_timeout"]))
        ttk.Entry(self.toolbar, textvariable=self.toolbar_timeout_var, width=4).pack(side=tk.LEFT, padx=(0, 10))

        # Action buttons
        ttk.Button(
            self.toolbar,
            text="🔍 Discover",
            command=self._on_discover,
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            self.toolbar,
            text="↻ Refresh",
            command=self._on_refresh,
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(self.toolbar, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=10
        )
        
        ttk.Button(
            self.toolbar,
            text="+ Group",
            command=self._on_create_group,
        ).pack(side=tk.LEFT, padx=2)
    
    def _create_main_layout(self) -> None:
        """Create main panel layout"""
        # Main paned window
        self.main_paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        self.main_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel: Devices
        left_frame = ttk.Frame(self.main_paned)
        self.main_paned.add(left_frame, weight=1)
        
        self.device_panel = DevicePanel(
            left_frame,
            on_device_select=self._on_device_select,
            on_device_bootstrap=self._on_device_bootstrap,
            on_device_reset=self._on_device_reset,
            on_device_add_to_group=self._on_device_add_to_group,
            on_refresh=self._on_refresh,
        )
        self.device_panel.pack(fill=tk.BOTH, expand=True)
        
        # Right panel: Notebook with tabs
        right_frame = ttk.Frame(self.main_paned)
        self.main_paned.add(right_frame, weight=2)
        
        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Groups tab
        groups_frame = ttk.Frame(self.notebook)
        self.notebook.add(groups_frame, text="Groups")
        
        self.group_panel = GroupPanel(
            groups_frame,
            on_group_select=self._on_group_select,
            on_group_create=self._on_create_group,
            on_group_delete=self._on_delete_group,
            on_group_distribute_keys=self._on_distribute_keys,
            on_group_verify_keys=self._on_verify_keys,
            on_member_add=self._on_add_member,
            on_member_remove=self._on_remove_member,
            on_refresh=self._on_refresh,
        )
        self.group_panel.pack(fill=tk.BOTH, expand=True)
        
        # Operations tab
        operations_frame = ttk.Frame(self.notebook)
        self.notebook.add(operations_frame, text="Operations")
        
        self.operations_panel = OperationsPanel(
            operations_frame,
            on_bootstrap=self._on_bootstrap_with_keys,
            on_factory_reset=self._on_device_reset,
            on_distribute_keys=self._on_distribute_keys,
            on_batch_bootstrap=self._on_batch_bootstrap,
            on_rekey_seed=self._on_rekey_seed,
            on_provision_discovered=self._on_provision_discovered,
        )
        self.operations_panel.pack(fill=tk.BOTH, expand=True)
        
        # Settings tab
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")
        
        self.config_panel = ConfigPanel(
            settings_frame,
            on_settings_change=self._on_settings_change,
            on_export=self._export_config,
            on_import=self._import_config,
            on_keys_loaded=self._on_keys_loaded,
        )
        self.config_panel.pack(fill=tk.BOTH, expand=True)
    
    def _create_statusbar(self) -> None:
        """Create status bar"""
        self.statusbar = ttk.Frame(self)
        self.statusbar.pack(fill=tk.X, side=tk.BOTTOM)
        
        # Status message
        self.status_label = ttk.Label(
            self.statusbar,
            text="Ready",
            anchor=tk.W,
        )
        self.status_label.pack(side=tk.LEFT, padx=5, pady=2)
        
        # Progress indicator (hidden by default)
        self.progress_bar = ttk.Progressbar(
            self.statusbar,
            mode="determinate",
            length=150,
        )
        
        # Device/group counts
        self.counts_label = ttk.Label(
            self.statusbar,
            text="Devices: 0 | Groups: 0",
            anchor=tk.E,
        )
        self.counts_label.pack(side=tk.RIGHT, padx=5, pady=2)
    
    def _schedule_updates(self) -> None:
        """Schedule periodic UI updates"""
        self._process_update_queue()
        self.after(100, self._schedule_updates)
    
    def _process_update_queue(self) -> None:
        """Process pending UI updates from worker threads"""
        try:
            while True:
                update = self._update_queue.get_nowait()
                update_type = update.get("type")
                
                if update_type == "progress":
                    self._update_progress(update.get("progress", 0), update.get("message", ""))
                elif update_type == "device_found":
                    self._add_discovered_device(update.get("pid"), update.get("info"))
                elif update_type == "complete":
                    self._on_worker_complete(update.get("result"))
                elif update_type == "batch_bootstrap_complete":
                    self._on_batch_bootstrap_complete(update.get("result"))
                elif update_type == "error":
                    self._on_worker_error(update.get("message", "Unknown error"))
                elif update_type == "heartbeat":
                    self._on_heartbeat_received(update.get("pid"), update.get("status"), update.get("timestamp"))
        except queue.Empty:
            pass
    
    def _initial_load(self) -> None:
        """Load initial data"""
        self._load_group_manager()
        self._refresh_groups()
        self._update_counts()
        self._set_status("Ready")
        self._start_heartbeat_listener()
    
    def _load_group_manager(self) -> None:
        """Load or create group manager"""
        from ..core.group_manager import GroupManager
        
        try:
            self._group_manager = GroupManager(self._settings["config_file"])
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"Error loading configuration: {error_details}")
            show_error(self, "Load Error", f"Failed to load configuration: {e}", error_details)
            # Create empty group manager as fallback
            try:
                self._group_manager = GroupManager(":memory:")  # Use temp name
            except Exception:
                # Last resort - create manager without loading config
                self._group_manager = GroupManager.__new__(GroupManager)
                self._group_manager.config_file = None
                self._group_manager.groups = {}
                self._group_manager.devices = {}
    
    def _refresh_groups(self) -> None:
        """Refresh group list from manager"""
        if not self._group_manager:
            return
        
        groups = []
        for group in self._group_manager.list_groups():
            groups.append(GroupDisplayInfo(
                group_id=group.group_id,
                name=group.name,
                description=group.description,
                member_pids=list(group.member_pids),
                has_keys=group.group_keys is not None,
                created_at=group.created_at,
                updated_at=group.updated_at,
            ))
        
        self.group_panel.set_groups(groups)
    
    def _refresh_devices(self) -> None:
        """Refresh device list from manager"""
        if not self._group_manager:
            return
        
        devices = []
        for device in self._group_manager.list_devices():
            devices.append(DeviceDisplayInfo(
                participant_id=device.participant_id,
                device_type=device.device_type,
                firmware_version=device.firmware_version,
                core_version=device.core_version,
                mapping_version=device.mapping_version,
                device_identification=device.device_identification,
                mcu_serial_number=device.mcu_serial_number,
                provisioning_key_id=device.provisioning_key_id,
                integrator_key_id=device.integrator_key_id,
                seed_key_id=device.seed_key_id,
                status=device.status,
                last_security_event=device.last_security_event,
                groups=list(device.groups),
                last_seen=device.last_seen,
                last_heartbeat=device.last_heartbeat,
            ))
        
        self.device_panel.set_devices(devices)
    
    def _update_counts(self) -> None:
        """Update device/group counts in status bar"""
        device_count = len(self.device_panel.devices)
        group_count = len(self.group_panel.groups)
        self.counts_label.configure(
            text=f"Devices: {device_count} | Groups: {group_count}"
        )
    
    def _set_status(self, message: str) -> None:
        """Set status bar message"""
        self.status_label.configure(text=message)
    
    def _show_progress(self, show: bool = True) -> None:
        """Show or hide progress bar"""
        if show:
            self.progress_bar.pack(side=tk.LEFT, padx=5, pady=2)
        else:
            self.progress_bar.pack_forget()
            self.progress_bar["value"] = 0
    
    def _update_progress(self, progress: float, message: str = "") -> None:
        """Update progress bar"""
        self.progress_bar["value"] = progress * 100
        if message:
            self._set_status(message)
    
    # Key management helpers
    
    def _on_keys_loaded(self) -> None:
        """Handle keys loaded from config panel"""
        from ..core.logging_util import log_info, log_debug
        
        self._key_store = self.config_panel.get_key_store()
        if self._key_store:
            keys_list = self._key_store.list_keys()
            log_info("gui", "Secure key store loaded: %s (%d keys)", 
                    str(self._key_store.path), len(keys_list))
            log_debug("gui", "Available keys: %s", ", ".join(keys_list))
            self._set_status(f"Secure key store loaded ({len(keys_list)} keys)")
            # Export to temp file for worker compatibility
            self._export_keys_for_workers()
        else:
            log_info("gui", "Plain text keys file loaded: %s", self._settings["keys_file"])
            self._set_status("Keys file loaded")
    
    def _export_keys_for_workers(self) -> None:
        """Export encrypted keys to temp plain text file for worker compatibility"""
        from ..core.logging_util import log_info, log_error, log_debug
        
        if not self._key_store:
            log_debug("gui", "No key store to export")
            return
        
        # Create temp file in same directory as encrypted store
        store_dir = self._key_store.path.parent
        temp_path = store_dir / ".keys_temp.txt"
        
        log_info("gui", "Exporting keys to temp file: %s", str(temp_path))
        
        try:
            self._key_store.export_to_plain_text(str(temp_path))
            self._temp_keys_file = str(temp_path)
            log_info("gui", "Keys exported successfully to: %s", self._temp_keys_file)
        except Exception as e:
            log_error("gui", "Failed to export keys for workers: %s", str(e))
            self._temp_keys_file = None
    
    def _get_usable_keys_file(self) -> "str | None":
        """Get a usable keys file path (plain text) for workers"""
        from pathlib import Path
        from ..core.logging_util import log_info, log_debug, log_warning, log_error
        
        keys_file = self._settings["keys_file"]
        log_debug("gui", "Getting usable keys file. Settings keys_file: %s", keys_file)
        log_debug("gui", "Key store loaded: %s, Temp file: %s", 
                 self._key_store is not None, 
                 getattr(self, '_temp_keys_file', None))
        
        # If encrypted store is loaded, use temp export
        if self._key_store and self._temp_keys_file:
            if Path(self._temp_keys_file).exists():
                log_info("gui", "Using temp keys file: %s", self._temp_keys_file)
                return self._temp_keys_file
            else:
                log_warning("gui", "Temp keys file missing, re-exporting...")
                # Re-export
                self._export_keys_for_workers()
                if self._temp_keys_file and Path(self._temp_keys_file).exists():
                    log_info("gui", "Using re-exported temp keys file: %s", self._temp_keys_file)
                    return self._temp_keys_file
                else:
                    log_error("gui", "Failed to re-export keys")
        
        # Check if keys file exists
        if not Path(keys_file).exists():
            log_error("gui", "Keys file not found: %s", keys_file)
            messagebox.showerror(
                "Keys Not Found",
                f"Keys file not found: {keys_file}\n\n"
                "Please go to Settings > Keys and either:\n"
                "• Load an existing key store\n"
                "• Create a new encrypted key store\n"
                "• Import keys from a plain text file"
            )
            return None
        
        # Check if it's an encrypted file being used directly (error)
        if keys_file.endswith(".enc"):
            if not self._key_store:
                log_error("gui", "Encrypted store not loaded: %s", keys_file)
                messagebox.showerror(
                    "Encrypted Store Not Loaded",
                    "The keys file is encrypted but not loaded.\n\n"
                    "Please go to Settings > Keys and click 'Load Key Store' to unlock it."
                )
                return None
        
        log_info("gui", "Using plain text keys file: %s", keys_file)
        return keys_file
    
    def _load_keys_dict(self) -> "dict | None":
        """Load keys from key store or plain text file. Returns dict or None."""
        try:
            # Try to get key from config panel (supports both encrypted and plain)
            integrator_key = self.config_panel.get_key("integrator_key")
            integrator_salt = self.config_panel.get_key("integrator_salt")
            seed_key = self.config_panel.get_key("seed_key")
            seed_salt = self.config_panel.get_key("seed_salt")
            provisioning_key = self.config_panel.get_key("provisioning_key")
            provisioning_salt = self.config_panel.get_key("provisioning_salt")
            
            if not all([integrator_key, integrator_salt, seed_key, seed_salt]):
                # Fall back to direct file loading
                from spsec_configurator.core.keys import load_kv_hex_file
                keys_file = self._settings["keys_file"]
                integrator_key = load_kv_hex_file(keys_file, "integrator_key")
                integrator_salt = load_kv_hex_file(keys_file, "integrator_salt")
                seed_key = load_kv_hex_file(keys_file, "seed_key")
                seed_salt = load_kv_hex_file(keys_file, "seed_salt")
                
                if provisioning_key is None:
                    provisioning_key = load_kv_hex_file(keys_file, "provisioning_key")
                if provisioning_salt is None:
                    provisioning_salt = load_kv_hex_file(keys_file, "provisioning_salt")
            
            if not all([integrator_key, integrator_salt, seed_key, seed_salt]):
                return None
            
            return {
                "provisioning_key": provisioning_key,
                "provisioning_salt": provisioning_salt,
                "provisioning_key_id": generate_key_id(),
                "integrator_key": integrator_key,
                "integrator_salt": integrator_salt,
                "integrator_key_id": generate_key_id(),
                "seed_key": seed_key,
                "seed_salt": seed_salt,
                "seed_key_id": generate_key_id(),
            }
        except Exception as e:
            print(f"Error loading keys: {e}")
            return None
    
    # Event handlers
    
    def _on_interface_change(self, event: tk.Event) -> None:
        """Handle interface selection change"""
        self._settings["interface"] = self.interface_var.get()
        # Restart heartbeat listener on new interface
        if self._hb_listener:
            self._hb_listener.cancel()
            self._hb_listener = None
        self._start_heartbeat_listener()
    
    def _on_device_select(self, pid: int) -> None:
        """Handle device selection"""
        self.operations_panel.set_target_pid(pid)
    
    def _on_group_select(self, group_id: int) -> None:
        """Handle group selection"""
        pass
    
    def _on_discover(self) -> None:
        """Start device discovery"""
        if self._current_worker and self._current_worker.is_alive():
            messagebox.showwarning("Busy", "An operation is already in progress")
            return
        
        # Get keys file path (export encrypted store if needed)
        keys_file = self._get_usable_keys_file()
        if keys_file is None:
            return
        
        self._set_status("Discovering devices...")
        self._show_progress(True)
        self.device_panel.clear_devices()
        
        try:
            start_pid = int(self.toolbar_start_pid_var.get())
            end_pid = int(self.toolbar_end_pid_var.get())
            timeout = float(self.toolbar_timeout_var.get())
            self._settings["discovery_start_pid"] = start_pid
            self._settings["discovery_end_pid"] = end_pid
            self._settings["discovery_timeout"] = timeout
        except ValueError:
            # Fallback to settings if empty or invalid
            start_pid = self._settings["discovery_start_pid"]
            end_pid = self._settings["discovery_end_pid"]
            timeout = self._settings["discovery_timeout"]
            self.toolbar_start_pid_var.set(str(start_pid))
            self.toolbar_end_pid_var.set(str(end_pid))
            self.toolbar_timeout_var.set(str(timeout))
        
        def on_progress(progress: float, message: str):
            self._update_queue.put({
                "type": "progress",
                "progress": progress,
                "message": message,
            })
        
        def on_device_found(pid: int, info: dict):
            self._update_queue.put({
                "type": "device_found",
                "pid": pid,
                "info": info,
            })
        
        def on_complete(result: WorkerResult):
            self._update_queue.put({
                "type": "complete",
                "result": result,
            })
            
            # If key establishment is enabled, establish keys for discovered devices
            if self._settings.get("establish_keys_after_discovery", False):
                discovered_pids = list(self.device_panel.devices.keys())
                if discovered_pids:
                    self._establish_keys_for_devices(discovered_pids)
        
        def on_error(message: str):
            self._update_queue.put({
                "type": "error",
                "message": message,
            })
        
        self._current_worker = DiscoveryWorker(
            interface=self._settings["interface"],
            keys_file=keys_file,  # Use the usable (plain text) keys file
            pid_range=range(start_pid, end_pid + 1),
            timeout_per_device=timeout,
            key_selector=self._settings["discovery_key"],
            on_progress=on_progress,
            on_complete=on_complete,
            on_error=on_error,
            on_device_found=on_device_found,
        )
        self._current_worker.start()
    
    def _establish_keys_for_devices(self, pids: List[int]) -> None:
        """Establish keys for a list of devices after discovery"""
        if not pids:
            return
        
        # Load keys
        keys = self._load_keys_dict()
        if keys is None:
            show_error(self, "Key Establishment Failed", 
                      "Failed to load keys. Please load a key store or keys file in Settings.")
            return
        
        # Get initial key selector for establishment
        initial_key_selector = self._settings.get("establish_initial_key", 1)
        keys["initial_key_selector"] = initial_key_selector
        
        # Get usable keys file
        worker_keys_file = self._get_usable_keys_file()
        if worker_keys_file is None:
            return
        
        self._set_status(f"Establishing keys for {len(pids)} device(s)...")
        self._show_progress(True)
        
        def on_progress(progress: float, message: str):
            self._update_queue.put({
                "type": "progress",
                "progress": progress,
                "message": message,
            })
        
        def on_complete(result: WorkerResult):
            self._update_queue.put({
                "type": "complete",
                "result": result,
            })
        
        def on_error(message: str):
            self._update_queue.put({
                "type": "error",
                "message": message,
            })
        
        # Establish keys sequentially for each device
        # For simplicity, processing occurs one device at a time
        # A full implementation would use a batch worker
        total = len(pids)
        for i, pid in enumerate(pids):
            if self._current_worker and self._current_worker.is_alive():
                # Wait for previous operation
                self._current_worker.join()
            
            progress = (i + 1) / total
            self._update_progress(progress, f"Establishing keys for device {pid}...")
            
            # Extract provisioning keys if starting from Zero
            provisioning_key = keys.get("provisioning_key")
            provisioning_salt = keys.get("provisioning_salt")
            provisioning_key_id = keys.get("provisioning_key_id")
            
            self._current_worker = SequentialKeyEstablishmentWorker(
                interface=self._settings["interface"],
                keys_file=worker_keys_file,
                participant_id=pid,
                initial_key_selector=initial_key_selector,
                integrator_key=keys["integrator_key"],
                integrator_salt=keys["integrator_salt"],
                integrator_key_id=keys["integrator_key_id"],
                seed_key=keys["seed_key"],
                seed_salt=keys["seed_salt"],
                seed_key_id=keys["seed_key_id"],
                provisioning_key=provisioning_key,
                provisioning_salt=provisioning_salt,
                provisioning_key_id=provisioning_key_id,
                on_progress=on_progress,
                on_complete=on_complete,
                on_error=on_error,
            )
            self._current_worker.start()
            self._current_worker.join()  # Wait for completion
        
        self._show_progress(False)
        self._set_status(f"Key establishment completed for {len(pids)} device(s)")
    
    def _add_discovered_device(self, pid: int, info: dict) -> None:
        """Add a discovered device to the panel"""
        device = DeviceDisplayInfo(
            participant_id=pid,
            core_version=info.get("core_version"),
            mapping_version=info.get("mapping_version"),
            device_identification=info.get("device_identification"),
            mcu_serial_number=info.get("mcu_serial_number"),
            provisioning_key_id=info.get("provisioning_key_id"),
            integrator_key_id=info.get("integrator_key_id"),
            seed_key_id=info.get("seed_key_id"),
            status=info.get("status"),
            last_security_event=info.get("last_security_event"),
            reachable=True,
            last_seen=datetime.now(timezone.utc).strftime("%H:%M:%S"),
            last_heartbeat=info.get("last_heartbeat"),
        )
        self.device_panel.add_device(device)
        self._update_counts()
        
        # Register in group manager
        if self._group_manager:
            self._group_manager.register_device(
                pid,
                core_version=info.get("core_version"),
                mapping_version=info.get("mapping_version"),
                device_identification=info.get("device_identification"),
                mcu_serial_number=info.get("mcu_serial_number"),
                provisioning_key_id=info.get("provisioning_key_id"),
                integrator_key_id=info.get("integrator_key_id"),
                seed_key_id=info.get("seed_key_id"),
                status=info.get("status"),
                last_security_event=info.get("last_security_event"),
            )
    
    def _on_worker_complete(self, result: WorkerResult) -> None:
        """Handle worker completion"""
        self._show_progress(False)
        self._current_worker = None
        
        if result.status == WorkerStatus.COMPLETED:
            self._set_status("Operation completed successfully")
            self._refresh_groups()
            self._update_counts()
        elif result.status == WorkerStatus.CANCELLED:
            self._set_status("Operation cancelled")
        elif result.status == WorkerStatus.FAILED:
            self._set_status(f"Operation failed: {result.error}")
            show_error(self, "Operation Failed", result.error or "Unknown error")
    
    def _on_batch_bootstrap_complete(self, result: WorkerResult) -> None:
        """Handle batch bootstrap completion with real per-device counts"""
        self._show_progress(False)
        self._current_worker = None

        if result.status == WorkerStatus.COMPLETED:
            data = result.result
            self._refresh_groups()
            self._update_counts()
            if data["failed"] == 0:
                self._set_status(
                    f"Batch bootstrap complete: {data['successful']}/{data['total']} succeeded")
            else:
                self._set_status(
                    f"Batch bootstrap complete: {data['successful']}/{data['total']} succeeded, "
                    f"{data['failed']} failed (PIDs: {data['failed_pids']})")
                show_error(self, "Batch Bootstrap: Some Devices Failed",
                          f"{data['failed']} of {data['total']} device(s) failed to bootstrap:\n"
                          f"{data['failed_pids']}")
        elif result.status == WorkerStatus.CANCELLED:
            self._set_status("Batch bootstrap cancelled")
        else:
            self._set_status(f"Batch bootstrap failed: {result.error}")
            show_error(self, "Batch Bootstrap Failed", result.error or "Unknown error")

    def _on_worker_error(self, message: str) -> None:
        """Handle worker error"""
        self._show_progress(False)
        self._current_worker = None
        self._set_status(f"Error: {message}")
        show_error(self, "Error", message)
    
    def _on_refresh(self) -> None:
        """Refresh all data"""
        self._load_group_manager()
        self._refresh_groups()
        self._refresh_devices()
        self._update_counts()
        self._set_status("Refreshed")
    
    def _on_create_group(self) -> None:
        """Show create group dialog"""
        dialog = CreateGroupDialog(self)
        result = dialog.show()
        
        if result:
            try:
                group = self._group_manager.create_group(
                    result["group_id"],
                    result["name"],
                    result["description"],
                )
                
                if result["generate_keys"]:
                    from ..core.group_manager import GroupKeys
                    keys = GroupKeys(
                        integrator_key=secrets.token_bytes(32),
                        integrator_salt=secrets.token_bytes(16),
                        integrator_key_id=generate_key_id(),
                        seed_key=secrets.token_bytes(32),
                        seed_salt=secrets.token_bytes(16),
                        seed_key_id=generate_key_id(),
                    )
                    self._group_manager.set_group_keys(result["group_id"], keys)
                
                self._refresh_groups()
                self._update_counts()
                self._set_status(f"Created group {result['group_id']}: {result['name']}")
            except ValueError as e:
                show_error(self, "Create Group Failed", str(e))
    
    def _on_delete_group(self, group_id: int) -> None:
        """Delete a group"""
        group = self._group_manager.get_group(group_id)
        if not group:
            return
        
        dialog = ConfirmDialog(
            self,
            title="Delete Group",
            message=f"Delete group '{group.name}'?",
            detail=f"This will remove {len(group.member_pids)} member(s) from the group.",
            warning=True,
        )
        
        if dialog.show():
            self._group_manager.delete_group(group_id)
            self._refresh_groups()
            self._update_counts()
            self._set_status(f"Deleted group {group_id}")
    
    def _on_device_bootstrap(self, pid: int) -> None:
        """Bootstrap a device using keys from file"""
        self._on_bootstrap_with_keys(pid, None)
    
    def _on_rekey_seed(self, pid: int, keys: Optional[dict]) -> None:
        """Rotate the Seed key via the Integrator rung (bootstrap would fail
        with KEY_ALREADY_SET on the write-once Integrator key)."""
        keys = dict(keys or {})
        keys["initial_key_selector"] = SPSEC_KEY_SELECTOR_INTEGRATOR_KEY
        self._on_bootstrap_with_keys(pid, keys)

    def _on_provision_discovered(self, pids: List[int], keys: Optional[dict]) -> None:
        """Scan a PID range and provision only the devices that need it."""
        if self._current_worker and self._current_worker.is_alive():
            messagebox.showwarning("Busy", "An operation is already in progress")
            return

        if not pids:
            show_error(self, "Provision Discovered", "No PID range given")
            return

        if keys is None or "integrator_key" not in keys:
            loaded = self._load_keys_dict()
            if loaded is None:
                show_error(self, "Provision Discovered",
                           "Failed to load keys. Load a key store or keys file "
                           "in Settings.")
                return
            if keys:
                loaded.update(keys)
            keys = loaded

        worker_keys_file = self._get_usable_keys_file()
        if worker_keys_file is None:
            return

        self._set_status(f"Scanning PIDs {min(pids)}-{max(pids)}...")
        self._show_progress(True)

        def on_progress(progress: float, message: str):
            self._update_queue.put({"type": "progress", "progress": progress,
                                    "message": message})

        def on_complete(result: WorkerResult):
            self._update_queue.put({"type": "complete", "result": result})

        def on_error(message: str):
            self._update_queue.put({"type": "error", "message": message})

        self._current_worker = ProvisionDiscoveredWorker(
            interface=self._settings["interface"],
            keys_file=worker_keys_file,
            start_pid=min(pids),
            end_pid=max(pids),
            provisioning_key=keys.get("provisioning_key"),
            provisioning_salt=keys.get("provisioning_salt"),
            provisioning_key_id=keys.get("provisioning_key_id"),
            integrator_key=keys["integrator_key"],
            integrator_salt=keys["integrator_salt"],
            integrator_key_id=keys["integrator_key_id"],
            seed_key=keys["seed_key"],
            seed_salt=keys["seed_salt"],
            seed_key_id=keys["seed_key_id"],
            timeout=float(self._settings.get("discovery_timeout", 1.0)),
            on_progress=on_progress,
            on_complete=on_complete,
            on_error=on_error,
        )
        self._current_worker.start()

    def _on_bootstrap_with_keys(self, pid: int, keys: Optional[dict]) -> None:
        """Bootstrap a device with specific keys"""
        if self._current_worker and self._current_worker.is_alive():
            messagebox.showwarning("Busy", "An operation is already in progress")
            return
        
        if keys is None or "integrator_key" not in keys:
            # Load keys from key store or plain text
            loaded_keys = self._load_keys_dict()
            if loaded_keys is None:
                show_error(self, "Bootstrap Failed", 
                          "Failed to load keys. Please load a key store or keys file in Settings.")
                return
            if keys is not None:
                loaded_keys.update(keys)
            keys = loaded_keys
        
        self._set_status(f"Bootstrapping device {pid}...")
        self._show_progress(True)
        
        def on_progress(progress: float, message: str):
            self._update_queue.put({
                "type": "progress",
                "progress": progress,
                "message": message,
            })
        
        def on_complete(result: WorkerResult):
            self._update_queue.put({
                "type": "complete",
                "result": result,
            })
        
        def on_error(message: str):
            self._update_queue.put({
                "type": "error",
                "message": message,
            })
        
        # Get initial key selector (default to Provisioning if not specified)
        initial_key_selector = keys.get("initial_key_selector", 1)
        
        # Get usable keys file for worker
        worker_keys_file = self._get_usable_keys_file()
        if worker_keys_file is None:
            self._show_progress(False)
            return
        
        # Use SequentialKeyEstablishmentWorker if initial_key_selector is specified
        # (1=Zero, 15=Provisioning, 14=Integrator, 13=Seed)
        if initial_key_selector is not None:
            # Extract provisioning keys if starting from Zero
            provisioning_key = keys.get("provisioning_key")
            provisioning_salt = keys.get("provisioning_salt")
            provisioning_key_id = keys.get("provisioning_key_id")
            
            self._current_worker = SequentialKeyEstablishmentWorker(
                interface=self._settings["interface"],
                keys_file=worker_keys_file,
                participant_id=pid,
                initial_key_selector=initial_key_selector,
                integrator_key=keys["integrator_key"],
                integrator_salt=keys["integrator_salt"],
                integrator_key_id=keys["integrator_key_id"],
                seed_key=keys["seed_key"],
                seed_salt=keys["seed_salt"],
                seed_key_id=keys["seed_key_id"],
                provisioning_key=provisioning_key,
                provisioning_salt=provisioning_salt,
                provisioning_key_id=provisioning_key_id,
                on_progress=on_progress,
                on_complete=on_complete,
                on_error=on_error,
            )
        else:
            # Use old BootstrapWorker for backward compatibility
            self._current_worker = BootstrapWorker(
                interface=self._settings["interface"],
                keys_file=worker_keys_file,
                participant_id=pid,
                integrator_key=keys["integrator_key"],
                integrator_salt=keys["integrator_salt"],
                integrator_key_id=keys["integrator_key_id"],
                seed_key=keys["seed_key"],
                seed_salt=keys["seed_salt"],
                seed_key_id=keys["seed_key_id"],
                on_progress=on_progress,
                on_complete=on_complete,
                on_error=on_error,
            )
        self._current_worker.start()
    
    def _on_device_reset(self, pid: int) -> None:
        """Factory reset a device"""
        if self._current_worker and self._current_worker.is_alive():
            messagebox.showwarning("Busy", "An operation is already in progress")
            return
        
        dialog = ConfirmDialog(
            self,
            title="Factory Reset",
            message=f"Factory reset device PID {pid}?",
            detail="This will delete ALL cryptographic keys from the device.",
            warning=True,
        )
        
        if not dialog.show():
            return
        
        self._set_status(f"Resetting device {pid}...")
        self._show_progress(True)
        
        def on_progress(progress: float, message: str):
            self._update_queue.put({
                "type": "progress",
                "progress": progress,
                "message": message,
            })
        
        def on_complete(result: WorkerResult):
            self._update_queue.put({
                "type": "complete",
                "result": result,
            })
        
        def on_error(message: str):
            self._update_queue.put({
                "type": "error",
                "message": message,
            })
        
        # Get usable keys file for worker
        worker_keys_file = self._get_usable_keys_file()
        if worker_keys_file is None:
            self._show_progress(False)
            return
        
        self._current_worker = FactoryResetWorker(
            interface=self._settings["interface"],
            keys_file=worker_keys_file,
            participant_id=pid,
            on_progress=on_progress,
            on_complete=on_complete,
            on_error=on_error,
        )
        self._current_worker.start()
    
    def _on_device_add_to_group(self, pid: int) -> None:
        """Add device to a group"""
        groups = [(g.group_id, g.name, len(g.member_pids)) 
                  for g in self._group_manager.list_groups()]
        
        if not groups:
            messagebox.showinfo("No Groups", "Please create a group first.")
            return
        
        dialog = GroupSelectDialog(self, groups=groups)
        group_id = dialog.show()
        
        if group_id:
            self._group_manager.add_device_to_group(group_id, pid)
            self._refresh_groups()
            self._refresh_devices()
            self._set_status(f"Added device {pid} to group {group_id}")
    
    def _on_add_member(self, group_id: int) -> None:
        """Add a member to a group"""
        devices = [(d.participant_id, f"PID {d.participant_id}") 
                   for d in self._group_manager.list_devices()]
        
        if not devices:
            messagebox.showinfo("No Devices", "Please discover devices first.")
            return
        
        from .dialogs import DeviceSelectDialog
        dialog = DeviceSelectDialog(self, devices=devices, multi_select=True)
        pids = dialog.show()
        
        if pids:
            for pid in pids:
                self._group_manager.add_device_to_group(group_id, pid)
            self._refresh_groups()
            self._set_status(f"Added {len(pids)} device(s) to group {group_id}")
    
    def _on_remove_member(self, group_id: int, pid: int) -> None:
        """Remove a member from a group"""
        self._group_manager.remove_device_from_group(group_id, pid)
        self._refresh_groups()
        self._set_status(f"Removed device {pid} from group {group_id}")
    
    def _on_distribute_keys(self, group_id: int) -> None:
        """Distribute keys to group members"""
        if self._current_worker and self._current_worker.is_alive():
            messagebox.showwarning("Busy", "An operation is already in progress")
            return
        
        group = self._group_manager.get_group(group_id)
        if not group:
            return
        
        if not group.member_pids:
            messagebox.showinfo("No Members", "Group has no members to distribute keys to.")
            return
        
        if not group.group_keys:
            messagebox.showwarning("No Keys", "Group has no keys configured. Generate keys first.")
            return
        
        self._set_status(f"Distributing keys to group {group_id}...")
        self._show_progress(True)
        
        def on_progress(progress: float, message: str):
            self._update_queue.put({
                "type": "progress",
                "progress": progress,
                "message": message,
            })
        
        def on_complete(result: WorkerResult):
            self._update_queue.put({
                "type": "complete",
                "result": result,
            })
        
        def on_error(message: str):
            self._update_queue.put({
                "type": "error",
                "message": message,
            })
        
        # Get usable keys file for worker
        worker_keys_file = self._get_usable_keys_file()
        if worker_keys_file is None:
            self._show_progress(False)
            return
        
        self._current_worker = KeyDistributionWorker(
            interface=self._settings["interface"],
            keys_file=worker_keys_file,
            group_id=group_id,
            config_file=self._settings["config_file"],
            on_progress=on_progress,
            on_complete=on_complete,
            on_error=on_error,
        )
        self._current_worker.start()
    
    def _on_verify_keys(self, group_id: int) -> None:
        """Verify keys for group members"""
        messagebox.showinfo(
            "Verify Keys",
            "Key verification would check that all group members have the correct keys.\n\n"
            "This operation is not yet fully implemented in the GUI."
        )
    
    def _on_batch_bootstrap(self, pids: list, keys: Optional[dict]) -> None:
        """Batch bootstrap multiple devices"""
        if self._current_worker and self._current_worker.is_alive():
            messagebox.showwarning("Busy", "An operation is already in progress")
            return

        if keys is None or "integrator_key" not in keys:
            # Load keys from key store or plain text
            loaded_keys = self._load_keys_dict()
            if loaded_keys is None:
                show_error(self, "Batch Bootstrap Failed",
                          "Failed to load keys. Please load a key store or keys file in Settings.")
                return
            if keys is not None:
                loaded_keys.update(keys)
            keys = loaded_keys

        worker_keys_file = self._get_usable_keys_file()
        if worker_keys_file is None:
            return

        self._set_status(f"Batch bootstrapping {len(pids)} devices...")
        self._show_progress(True)

        def on_progress(progress: float, message: str):
            self._update_queue.put({
                "type": "progress",
                "progress": progress,
                "message": message,
            })

        def on_complete(result: WorkerResult):
            # Post result to UI update queue from worker thread
            self._update_queue.put({
                "type": "batch_bootstrap_complete",
                "result": result,
            })

        def on_error(message: str):
            self._update_queue.put({
                "type": "error",
                "message": message,
            })

        self._current_worker = BatchBootstrapWorker(
            interface=self._settings["interface"],
            keys_file=worker_keys_file,
            participant_ids=pids,
            integrator_key=keys["integrator_key"],
            integrator_salt=keys["integrator_salt"],
            integrator_key_id=keys["integrator_key_id"],
            seed_key=keys["seed_key"],
            seed_salt=keys["seed_salt"],
            seed_key_id=keys["seed_key_id"],
            on_progress=on_progress,
            on_complete=on_complete,
            on_error=on_error,
        )
        self._current_worker.start()
    
    def _on_settings_change(self, settings: dict) -> None:
        """Handle settings change"""
        self._settings.update(settings)
        self.interface_var.set(settings.get("interface", "vcan0"))
        
        # Reload group manager if config file changed
        if "config_file" in settings:
            self._load_group_manager()
            self._refresh_groups()
            self._refresh_devices()
    
    def _on_export(self) -> None:
        """Export configuration"""
        filename = filedialog.asksaveasfilename(
            title="Export Configuration",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if filename:
            self._export_config(filename)
    
    def _export_config(self, filename: str) -> None:
        """Export configuration to file"""
        try:
            from ..core.config_import_export import export_configuration
            if export_configuration(self._group_manager, filename):
                show_info(self, "Export Complete", f"Configuration exported to:\n{filename}")
            else:
                show_error(self, "Export Failed", "Failed to export configuration")
        except Exception as e:
            show_error(self, "Export Failed", str(e))
    
    def _on_import(self) -> None:
        """Import configuration"""
        filename = filedialog.askopenfilename(
            title="Import Configuration",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if filename:
            self._import_config(filename, False)
    
    def _import_config(self, filename: str, merge: bool) -> None:
        """Import configuration from file"""
        try:
            from ..core.config_import_export import import_configuration
            if import_configuration(self._group_manager, filename, merge=merge):
                self._refresh_groups()
                self._refresh_devices()
                self._update_counts()
                show_info(self, "Import Complete", f"Configuration imported from:\n{filename}")
            else:
                show_error(self, "Import Failed", "Failed to import configuration")
        except Exception as e:
            show_error(self, "Import Failed", str(e))
    
    def _on_key_management(self) -> None:
        """Open key management tab in settings"""
        self.notebook.select(2)  # Select Settings tab (index: 0=Groups, 1=Operations, 2=Settings)
        self.config_panel.notebook.select(1)  # Select Keys tab (index: 0=Connection, 1=Keys, ...)
    
    def _on_about(self) -> None:
        """Show about dialog"""
        messagebox.showinfo(
            "About SPsec Configurator",
            "SPsec Configurator GUI\n\n"
            "A graphical interface for managing SPsec\n"
            "devices, groups, and cryptographic keys.\n\n"
            "Features:\n"
            "• Secure encrypted key storage (AES-256-GCM)\n"
            "• Device discovery and management\n"
            "• Group-based key distribution\n\n"
            "Built with Python and Tkinter"
        )
    
    def _on_close(self) -> None:
        """Handle window close"""
        if self._hb_listener:
            self._hb_listener.cancel()

        if self._current_worker and self._current_worker.is_alive():
            if not messagebox.askyesno(
                "Operation in Progress",
                "An operation is in progress. Cancel and exit?",
            ):
                return
            self._current_worker.cancel()

        # Cancelling only sets a flag the thread's loop polls (up to ~500ms for
        # the heartbeat listener) - join so the CAN socket each thread owns is
        # actually closed before the window (and process) goes away.
        if self._hb_listener:
            self._hb_listener.join(timeout=2.0)
        if self._current_worker:
            self._current_worker.join(timeout=5.0)

        self.destroy()


    def _start_heartbeat_listener(self) -> None:
        """Start background heartbeat listener"""
        if self._hb_listener and self._hb_listener.is_alive():
            return
            
        from .workers import HeartbeatListener
        
        def on_heartbeat(pid: int, status: int):
            self._update_queue.put({
                "type": "heartbeat",
                "pid": pid,
                "status": status,
                "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            })
            
        self._hb_listener = HeartbeatListener(
            interface=self._settings["interface"],
            on_heartbeat=on_heartbeat
        )
        self._hb_listener.start()

    def _on_heartbeat_received(self, pid: int, status: int, timestamp: str) -> None:
        """Handle received heartbeat"""
        from ..core.logging_util import log_info
        if not self._group_manager:
            return
            
        # Update device in panel
        self.device_panel.update_heartbeat(pid, status, timestamp)
        
        # Update device in manager
        device = self._group_manager.get_device(pid)
        if device:
            if device.last_heartbeat is None:
                log_info("gui", "First heartbeat received from PID %d", pid)
            device.last_heartbeat = timestamp
            device.status = status


def run_gui():
    """Run the GUI application"""
    app = MainWindow()
    app.mainloop()

