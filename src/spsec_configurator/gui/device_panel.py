# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Device list panel: TreeView, details, and per-device context menu."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional, Callable, List, Dict, Any
from dataclasses import dataclass

from ..core.spsec_definitions import (
    SPSEC_STATE_WAITING,
    SPSEC_STATE_SECURE,
    SPSEC_STATE_WARNING,
    SPSEC_STATE_CONFIGURATION,
    SPSEC_STATE_SHUTDOWN,
    SPSEC_STATE_NOT_SET,
)


@dataclass
class DeviceDisplayInfo:
    """Device information for display"""
    participant_id: int
    device_type: Optional[str] = None
    firmware_version: Optional[str] = None
    core_version: Optional[str] = None
    mapping_version: Optional[str] = None
    device_identification: Optional[str] = None
    mcu_serial_number: Optional[str] = None
    provisioning_key_id: Optional[int] = None
    integrator_key_id: Optional[int] = None
    seed_key_id: Optional[int] = None
    status: Optional[int] = None
    last_security_event: Optional[int] = None
    groups: List[int] = None
    reachable: bool = False
    last_seen: Optional[str] = None  # Last session/discovery time
    last_heartbeat: Optional[str] = None  # Last heartbeat received
    
    @property
    def sync_status(self) -> str:
        """Determine synchronization status based on Seed Key presence and Status"""
        if self.status == 5:
            return "OFFLINE"
            
        seed_missing = self.seed_key_id in (None, 0, 0xFFFFFFFF)
        current_state = self.status & 0x0F if self.status is not None else None
        
        if seed_missing:
            return "NOT_APPLICABLE (needs Seed Key)"
            
        if current_state == SPSEC_STATE_WAITING:
            return "NOT_SYNCHRONIZED (Waiting)"
        elif current_state == SPSEC_STATE_SECURE:
            return "SYNCHRONIZED (Secure)"
        elif current_state == SPSEC_STATE_WARNING:
            return "SYNC_LOST / UNDER_ATTACK (Warning)"
        elif current_state == SPSEC_STATE_CONFIGURATION:
            return "SYNCHRONIZED (Configuring)"
        elif current_state == SPSEC_STATE_SHUTDOWN:
            return "OFFLINE"
            
        return "UNKNOWN"
    
    def __post_init__(self):
        if self.groups is None:
            self.groups = []


class DevicePanel(ttk.Frame):
    """Device list (TreeView) with details, context menu, and discovery."""
    
    def __init__(
        self,
        parent: tk.Widget,
        on_device_select: Optional[Callable[[int], None]] = None,
        on_device_bootstrap: Optional[Callable[[int], None]] = None,
        on_device_reset: Optional[Callable[[int], None]] = None,
        on_device_add_to_group: Optional[Callable[[int], None]] = None,
        on_refresh: Optional[Callable[[], None]] = None,
    ):
        super().__init__(parent)
        
        self.on_device_select = on_device_select
        self.on_device_bootstrap = on_device_bootstrap
        self.on_device_reset = on_device_reset
        self.on_device_add_to_group = on_device_add_to_group
        self.on_refresh = on_refresh
        
        self.devices: Dict[int, DeviceDisplayInfo] = {}
        self.selected_pid: Optional[int] = None
        
        self._create_widgets()
        self._create_context_menu()

    def update_heartbeat(self, pid: int, status: int, timestamp: str) -> None:
        """Update heartbeat for a specific device"""
        if pid in self.devices:
            device = self.devices[pid]
            device.last_heartbeat = timestamp
            device.status = status
            device.reachable = True
            
            # Update treeview if visible
            item_id = f"device_{pid}"
            if self.tree.exists(item_id):
                # Update status in treeview
                state_names = {
                    SPSEC_STATE_NOT_SET: "Not set",
                    SPSEC_STATE_WAITING: "Waiting",
                    SPSEC_STATE_SECURE: "Secure",
                    SPSEC_STATE_WARNING: "Warning",
                    SPSEC_STATE_CONFIGURATION: "Config",
                    SPSEC_STATE_SHUTDOWN: "Shutdown"
                }
                status_text = f"0x{status:02X} ({state_names.get(status & 0x0F, 'Unknown')})"
                self.tree.set(item_id, "status", status_text)
                
            # If this is the selected device, update details
            if self.selected_pid == pid:
                self._update_details(device)
    
    def _create_widgets(self) -> None:
        """Create panel widgets"""
        # Main paned window for resizable split
        self.paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        self.paned.pack(fill=tk.BOTH, expand=True)
        
        # Left side: Device list
        list_frame = ttk.Frame(self.paned)
        self.paned.add(list_frame, weight=1)
        
        # Toolbar
        toolbar = ttk.Frame(list_frame)
        toolbar.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(toolbar, text="Devices", font=("TkDefaultFont", 11, "bold")).pack(side=tk.LEFT)
        
        refresh_btn = ttk.Button(
            toolbar,
            text="↻ Refresh",
            command=self._on_refresh_click,
            width=10,
        )
        refresh_btn.pack(side=tk.RIGHT)
        
        # TreeView for devices
        tree_frame = ttk.Frame(list_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.tree = ttk.Treeview(
            tree_frame,
            columns=("status", "version", "groups"),
            show="tree headings",
            selectmode="browse",
        )
        
        # Configure columns
        self.tree.heading("#0", text="Device")
        self.tree.heading("status", text="Status")
        self.tree.heading("version", text="Version")
        self.tree.heading("groups", text="Groups")
        
        self.tree.column("#0", width=120, minwidth=80)
        self.tree.column("status", width=80, minwidth=60)
        self.tree.column("version", width=100, minwidth=80)
        self.tree.column("groups", width=80, minwidth=60)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind events
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<Double-1>", self._on_double_click)
        
        # Right side: Device details
        details_frame = ttk.Frame(self.paned)
        self.paned.add(details_frame, weight=1)
        
        self._create_details_panel(details_frame)
    
    def _create_details_panel(self, parent: ttk.Frame) -> None:
        """Create device details panel"""
        # Header
        header = ttk.Frame(parent)
        header.pack(fill=tk.X, pady=(0, 10))
        
        self.details_title = ttk.Label(
            header,
            text="No device selected",
            font=("TkDefaultFont", 12, "bold"),
        )
        self.details_title.pack(anchor=tk.W)
        
        # Details content
        details_container = ttk.LabelFrame(parent, text="Device Information", padding=10)
        details_container.pack(fill=tk.BOTH, expand=True)
        
        # Info grid
        info_frame = ttk.Frame(details_container)
        info_frame.pack(fill=tk.X, anchor=tk.N)
        
        self.detail_labels = {}
        
        fields = [
            ("pid", "Participant ID:"),
            ("status", "Status:"),
            ("sync_status", "Sync Status:"),
            ("core_version", "Core Version:"),
            ("mapping_version", "Mapping Version:"),
            ("device_identification", "Device ID:"),
            ("mcu_serial", "MCU Serial:"),
            ("provisioning_key", "Prov Key ID:"),
            ("integrator_key", "Int Key ID:"),
            ("seed_key", "Seed Key ID:"),
            ("last_event", "Last Event:"),
            ("device_type", "Device Type:"),
            ("firmware", "Firmware:"),
            ("groups", "Groups:"),
            ("last_seen", "Last Session:"),
            ("last_heartbeat", "Last Heartbeat:"),
            ("reachable", "Reachable:"),
        ]
        
        for i, (key, label) in enumerate(fields):
            ttk.Label(info_frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=2)
            value_label = ttk.Label(info_frame, text="-", foreground="gray")
            value_label.grid(row=i, column=1, sticky=tk.W, padx=(10, 0), pady=2)
            self.detail_labels[key] = value_label
        
        # Action buttons
        action_frame = ttk.Frame(details_container)
        action_frame.pack(fill=tk.X, pady=(20, 0))
        
        self.bootstrap_btn = ttk.Button(
            action_frame,
            text="Bootstrap",
            command=self._on_bootstrap_click,
            state=tk.DISABLED,
        )
        self.bootstrap_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.reset_btn = ttk.Button(
            action_frame,
            text="Factory Reset",
            command=self._on_reset_click,
            state=tk.DISABLED,
        )
        self.reset_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.add_to_group_btn = ttk.Button(
            action_frame,
            text="Add to Group",
            command=self._on_add_to_group_click,
            state=tk.DISABLED,
        )
        self.add_to_group_btn.pack(side=tk.LEFT)
    
    def _create_context_menu(self) -> None:
        """Create right-click context menu"""
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Bootstrap", command=self._on_bootstrap_click)
        self.context_menu.add_command(label="Factory Reset", command=self._on_reset_click)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Add to Group", command=self._on_add_to_group_click)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Refresh", command=self._on_refresh_click)
    
    def _on_tree_select(self, event: tk.Event) -> None:
        """Handle tree selection change"""
        selection = self.tree.selection()
        if not selection:
            self.selected_pid = None
            self._update_details(None)
            return
        
        item_id = selection[0]
        # Extract PID from item ID (format: "device_XXX")
        if item_id.startswith("device_"):
            try:
                pid = int(item_id[7:])
                self.selected_pid = pid
                self._update_details(self.devices.get(pid))
                if self.on_device_select:
                    self.on_device_select(pid)
            except ValueError:
                self.selected_pid = None
                self._update_details(None)
    
    def _on_right_click(self, event: tk.Event) -> None:
        """Handle right-click for context menu"""
        # Select item under cursor
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self._on_tree_select(event)
            self.context_menu.post(event.x_root, event.y_root)
    
    def _on_double_click(self, event: tk.Event) -> None:
        """Handle double-click on device"""
        if self.selected_pid and self.on_device_bootstrap:
            self.on_device_bootstrap(self.selected_pid)
    
    def _on_refresh_click(self) -> None:
        """Handle refresh button click"""
        if self.on_refresh:
            self.on_refresh()
    
    def _on_bootstrap_click(self) -> None:
        """Handle bootstrap button click"""
        if self.selected_pid and self.on_device_bootstrap:
            self.on_device_bootstrap(self.selected_pid)
    
    def _on_reset_click(self) -> None:
        """Handle reset button click"""
        if self.selected_pid and self.on_device_reset:
            self.on_device_reset(self.selected_pid)
    
    def _on_add_to_group_click(self) -> None:
        """Handle add to group button click"""
        if self.selected_pid and self.on_device_add_to_group:
            self.on_device_add_to_group(self.selected_pid)
    
    def _update_details(self, device: Optional[DeviceDisplayInfo]) -> None:
        """Update details panel with device info"""
        if device is None:
            self.details_title.configure(text="No device selected")
            for label in self.detail_labels.values():
                label.configure(text="-", foreground="gray")
            self.bootstrap_btn.configure(state=tk.DISABLED)
            self.reset_btn.configure(state=tk.DISABLED)
            self.add_to_group_btn.configure(state=tk.DISABLED)
            return
        
        self.details_title.configure(text=f"Device PID {device.participant_id}")
        
        # Update fields
        self.detail_labels["pid"].configure(
            text=str(device.participant_id),
            foreground="black",
        )
        
        status_state = device.status & 0x0F if device.status is not None else None
        status_alert = (device.status & 0x80) >> 7 if device.status is not None else None
        status_text = f"0x{device.status:02X}" if device.status is not None else "-"
        if device.status is not None:
            state_names = {0: "Not set", 1: "Waiting", 2: "Secure", 3: "Warning", 4: "Configuration", 5: "Shutdown"}
            status_text += f" ({state_names.get(status_state, 'Unknown')})"
            if status_alert:
                status_text += " [ALERT]"
                
        self.detail_labels["status"].configure(
            text=status_text,
            foreground="black" if device.status is not None else "gray",
        )
        
        self.detail_labels["sync_status"].configure(
            text=device.sync_status,
            foreground="black",
        )
        
        self.detail_labels["core_version"].configure(
            text=device.core_version or "-",
            foreground="black" if device.core_version else "gray",
        )
        
        self.detail_labels["mapping_version"].configure(
            text=device.mapping_version or "-",
            foreground="black" if device.mapping_version else "gray",
        )
        
        self.detail_labels["device_identification"].configure(
            text=device.device_identification or "-",
            foreground="black" if device.device_identification else "gray",
        )
        
        self.detail_labels["mcu_serial"].configure(
            text=device.mcu_serial_number or "-",
            foreground="black" if device.mcu_serial_number else "gray",
        )
        
        def fmt_key(key_id):
            if key_id is None: return "-"
            if key_id == 0 or key_id == 0xFFFFFFFF: return "Not installed"
            return f"0x{key_id:08X}"
            
        self.detail_labels["provisioning_key"].configure(
            text=fmt_key(device.provisioning_key_id),
            foreground="black" if device.provisioning_key_id is not None else "gray",
        )
        
        self.detail_labels["integrator_key"].configure(
            text=fmt_key(device.integrator_key_id),
            foreground="black" if device.integrator_key_id is not None else "gray",
        )
        
        self.detail_labels["seed_key"].configure(
            text=fmt_key(device.seed_key_id),
            foreground="black" if device.seed_key_id is not None else "gray",
        )
        
        self.detail_labels["last_event"].configure(
            text=f"0x{device.last_security_event:02X}" if device.last_security_event is not None else "-",
            foreground="black" if device.last_security_event is not None else "gray",
        )
        
        self.detail_labels["device_type"].configure(
            text=device.device_type or "-",
            foreground="black" if device.device_type else "gray",
        )
        
        self.detail_labels["firmware"].configure(
            text=device.firmware_version or "-",
            foreground="black" if device.firmware_version else "gray",
        )
        
        groups_text = ", ".join(map(str, device.groups)) if device.groups else "None"
        self.detail_labels["groups"].configure(
            text=groups_text,
            foreground="black" if device.groups else "gray",
        )
        
        self.detail_labels["last_seen"].configure(
            text=device.last_seen or "-",
            foreground="black" if device.last_seen else "gray",
        )
        
        self.detail_labels["last_heartbeat"].configure(
            text=device.last_heartbeat or "-",
            foreground="black" if device.last_heartbeat else "gray",
        )
        
        self.detail_labels["reachable"].configure(
            text="Yes" if device.reachable else "No",
            foreground="green" if device.reachable else "red",
        )
        
        # Enable/disable buttons
        self.bootstrap_btn.configure(state=tk.NORMAL)
        self.reset_btn.configure(state=tk.NORMAL)
        self.add_to_group_btn.configure(state=tk.NORMAL)
    
    def add_device(self, device: DeviceDisplayInfo) -> None:
        """Add or update a device in the list"""
        self.devices[device.participant_id] = device
        self._refresh_tree()
    
    def remove_device(self, participant_id: int) -> None:
        """Remove a device from the list"""
        if participant_id in self.devices:
            del self.devices[participant_id]
            self._refresh_tree()
    
    def clear_devices(self) -> None:
        """Clear all devices from the list"""
        self.devices.clear()
        self._refresh_tree()
    
    def set_devices(self, devices: List[DeviceDisplayInfo]) -> None:
        """Set the device list"""
        self.devices = {d.participant_id: d for d in devices}
        self._refresh_tree()
    
    def update_device(self, participant_id: int, **kwargs) -> None:
        """Update device properties"""
        if participant_id in self.devices:
            device = self.devices[participant_id]
            for key, value in kwargs.items():
                if hasattr(device, key):
                    setattr(device, key, value)
            self._refresh_tree()
            if self.selected_pid == participant_id:
                self._update_details(device)
    
    def _refresh_tree(self) -> None:
        """Refresh the tree view"""
        # Remember selection
        old_selection = self.selected_pid
        
        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add devices sorted by PID
        for pid in sorted(self.devices.keys()):
            device = self.devices[pid]
            
            # Determine status display
            if device.reachable:
                status = "● Online"
            else:
                status = "○ Offline"
            
            # Version display
            version = device.core_version or device.firmware_version or "-"
            
            # Groups display
            groups = ", ".join(map(str, device.groups)) if device.groups else "-"
            
            item_id = f"device_{pid}"
            self.tree.insert(
                "",
                tk.END,
                iid=item_id,
                text=f"PID {pid}",
                values=(status, version, groups),
            )
        
        # Restore selection
        if old_selection and f"device_{old_selection}" in self.tree.get_children():
            self.tree.selection_set(f"device_{old_selection}")
    
    def get_selected_device(self) -> Optional[DeviceDisplayInfo]:
        """Get currently selected device"""
        if self.selected_pid:
            return self.devices.get(self.selected_pid)
        return None
    
    def get_all_devices(self) -> List[DeviceDisplayInfo]:
        """Get all devices"""
        return list(self.devices.values())
    
    def highlight_device(self, participant_id: int) -> None:
        """Highlight and select a device"""
        item_id = f"device_{participant_id}"
        if item_id in self.tree.get_children():
            self.tree.selection_set(item_id)
            self.tree.see(item_id)
            self._on_tree_select(None)

