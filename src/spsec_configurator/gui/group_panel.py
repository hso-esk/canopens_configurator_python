# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Group panel: group list, member management, key operations."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Callable, List, Dict, Any
from dataclasses import dataclass


@dataclass
class GroupDisplayInfo:
    """Group information for display"""
    group_id: int
    name: str
    description: Optional[str] = None
    member_pids: List[int] = None
    has_keys: bool = False
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    
    def __post_init__(self):
        if self.member_pids is None:
            self.member_pids = []


class GroupPanel(ttk.Frame):
    """Group list with member/key management and key generation."""
    
    def __init__(
        self,
        parent: tk.Widget,
        on_group_select: Optional[Callable[[int], None]] = None,
        on_group_create: Optional[Callable[[], None]] = None,
        on_group_delete: Optional[Callable[[int], None]] = None,
        on_group_distribute_keys: Optional[Callable[[int], None]] = None,
        on_group_verify_keys: Optional[Callable[[int], None]] = None,
        on_member_add: Optional[Callable[[int], None]] = None,
        on_member_remove: Optional[Callable[[int, int], None]] = None,
        on_refresh: Optional[Callable[[], None]] = None,
    ):
        super().__init__(parent)
        
        self.on_group_select = on_group_select
        self.on_group_create = on_group_create
        self.on_group_delete = on_group_delete
        self.on_group_distribute_keys = on_group_distribute_keys
        self.on_group_verify_keys = on_group_verify_keys
        self.on_member_add = on_member_add
        self.on_member_remove = on_member_remove
        self.on_refresh = on_refresh
        
        self.groups: Dict[int, GroupDisplayInfo] = {}
        self.selected_group_id: Optional[int] = None
        
        self._create_widgets()
        self._create_context_menus()
    
    def _create_widgets(self) -> None:
        """Create panel widgets"""
        # Main paned window
        self.paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        self.paned.pack(fill=tk.BOTH, expand=True)
        
        # Left side: Group list
        list_frame = ttk.Frame(self.paned)
        self.paned.add(list_frame, weight=1)
        
        # Toolbar
        toolbar = ttk.Frame(list_frame)
        toolbar.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(toolbar, text="Groups", font=("TkDefaultFont", 11, "bold")).pack(side=tk.LEFT)
        
        # Toolbar buttons
        btn_frame = ttk.Frame(toolbar)
        btn_frame.pack(side=tk.RIGHT)
        
        ttk.Button(
            btn_frame,
            text="+",
            width=3,
            command=self._on_create_click,
        ).pack(side=tk.LEFT, padx=1)
        
        ttk.Button(
            btn_frame,
            text="-",
            width=3,
            command=self._on_delete_click,
        ).pack(side=tk.LEFT, padx=1)
        
        ttk.Button(
            btn_frame,
            text="↻",
            width=3,
            command=self._on_refresh_click,
        ).pack(side=tk.LEFT, padx=1)
        
        # Group list
        tree_frame = ttk.Frame(list_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.group_tree = ttk.Treeview(
            tree_frame,
            columns=("members", "keys"),
            show="tree headings",
            selectmode="browse",
        )
        
        self.group_tree.heading("#0", text="Group")
        self.group_tree.heading("members", text="Members")
        self.group_tree.heading("keys", text="Keys")
        
        self.group_tree.column("#0", width=150, minwidth=100)
        self.group_tree.column("members", width=70, minwidth=50)
        self.group_tree.column("keys", width=60, minwidth=40)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.group_tree.yview)
        self.group_tree.configure(yscrollcommand=scrollbar.set)
        
        self.group_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.group_tree.bind("<<TreeviewSelect>>", self._on_group_select)
        self.group_tree.bind("<Button-3>", self._on_group_right_click)
        
        # Right side: Group details and members
        details_frame = ttk.Frame(self.paned)
        self.paned.add(details_frame, weight=2)
        
        self._create_details_panel(details_frame)
    
    def _create_details_panel(self, parent: ttk.Frame) -> None:
        """Create group details and members panel"""
        # Header
        header = ttk.Frame(parent)
        header.pack(fill=tk.X, pady=(0, 10))
        
        self.details_title = ttk.Label(
            header,
            text="No group selected",
            font=("TkDefaultFont", 12, "bold"),
        )
        self.details_title.pack(anchor=tk.W)
        
        self.details_subtitle = ttk.Label(
            header,
            text="",
            foreground="gray",
        )
        self.details_subtitle.pack(anchor=tk.W)
        
        # Notebook for details/members tabs
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Info tab
        info_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(info_frame, text="Information")
        
        self._create_info_tab(info_frame)
        
        # Members tab
        members_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(members_frame, text="Members")
        
        self._create_members_tab(members_frame)
        
        # Keys tab
        keys_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(keys_frame, text="Keys")
        
        self._create_keys_tab(keys_frame)
    
    def _create_info_tab(self, parent: ttk.Frame) -> None:
        """Create info tab content"""
        # Info grid
        info_frame = ttk.LabelFrame(parent, text="Group Details", padding=10)
        info_frame.pack(fill=tk.X)
        
        self.info_labels = {}
        
        fields = [
            ("id", "Group ID:"),
            ("name", "Name:"),
            ("description", "Description:"),
            ("member_count", "Members:"),
            ("has_keys", "Has Keys:"),
            ("created", "Created:"),
            ("updated", "Last Updated:"),
        ]
        
        for i, (key, label) in enumerate(fields):
            ttk.Label(info_frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=2)
            value_label = ttk.Label(info_frame, text="-", foreground="gray")
            value_label.grid(row=i, column=1, sticky=tk.W, padx=(10, 0), pady=2)
            self.info_labels[key] = value_label
    
    def _create_members_tab(self, parent: ttk.Frame) -> None:
        """Create members tab content"""
        # Toolbar
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill=tk.X, pady=(0, 5))
        
        self.add_member_btn = ttk.Button(
            toolbar,
            text="Add Device",
            command=self._on_add_member_click,
            state=tk.DISABLED,
        )
        self.add_member_btn.pack(side=tk.LEFT)
        
        self.remove_member_btn = ttk.Button(
            toolbar,
            text="Remove",
            command=self._on_remove_member_click,
            state=tk.DISABLED,
        )
        self.remove_member_btn.pack(side=tk.LEFT, padx=(5, 0))
        
        # Members list
        list_frame = ttk.Frame(parent)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.members_tree = ttk.Treeview(
            list_frame,
            columns=("device", "status"),
            show="headings",
            selectmode="extended",
        )
        
        self.members_tree.heading("device", text="Device (PID)")
        self.members_tree.heading("status", text="Status")
        
        self.members_tree.column("device", width=150)
        self.members_tree.column("status", width=100)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.members_tree.yview)
        self.members_tree.configure(yscrollcommand=scrollbar.set)
        
        self.members_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.members_tree.bind("<<TreeviewSelect>>", self._on_member_select)
        self.members_tree.bind("<Button-3>", self._on_member_right_click)
    
    def _create_keys_tab(self, parent: ttk.Frame) -> None:
        """Create keys tab content"""
        # Key status
        status_frame = ttk.LabelFrame(parent, text="Key Status", padding=10)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.key_status_label = ttk.Label(
            status_frame,
            text="No keys configured",
            foreground="gray",
        )
        self.key_status_label.pack(anchor=tk.W)
        
        # Key actions
        action_frame = ttk.LabelFrame(parent, text="Key Operations", padding=10)
        action_frame.pack(fill=tk.X)
        
        self.generate_keys_btn = ttk.Button(
            action_frame,
            text="Generate New Keys",
            command=self._on_generate_keys_click,
            state=tk.DISABLED,
        )
        self.generate_keys_btn.pack(anchor=tk.W, pady=2)
        
        self.distribute_keys_btn = ttk.Button(
            action_frame,
            text="Distribute Keys to Members",
            command=self._on_distribute_keys_click,
            state=tk.DISABLED,
        )
        self.distribute_keys_btn.pack(anchor=tk.W, pady=2)
        
        self.verify_keys_btn = ttk.Button(
            action_frame,
            text="Verify Member Keys",
            command=self._on_verify_keys_click,
            state=tk.DISABLED,
        )
        self.verify_keys_btn.pack(anchor=tk.W, pady=2)
    
    def _create_context_menus(self) -> None:
        """Create context menus"""
        # Group context menu
        self.group_menu = tk.Menu(self, tearoff=0)
        self.group_menu.add_command(label="Distribute Keys", command=self._on_distribute_keys_click)
        self.group_menu.add_command(label="Verify Keys", command=self._on_verify_keys_click)
        self.group_menu.add_separator()
        self.group_menu.add_command(label="Delete Group", command=self._on_delete_click)
        
        # Member context menu
        self.member_menu = tk.Menu(self, tearoff=0)
        self.member_menu.add_command(label="Remove from Group", command=self._on_remove_member_click)
    
    def _on_group_select(self, event: tk.Event) -> None:
        """Handle group selection"""
        selection = self.group_tree.selection()
        if not selection:
            self.selected_group_id = None
            self._update_details(None)
            return
        
        item_id = selection[0]
        if item_id.startswith("group_"):
            try:
                group_id = int(item_id[6:])
                self.selected_group_id = group_id
                self._update_details(self.groups.get(group_id))
                if self.on_group_select:
                    self.on_group_select(group_id)
            except ValueError:
                self.selected_group_id = None
                self._update_details(None)
    
    def _on_group_right_click(self, event: tk.Event) -> None:
        """Handle group right-click"""
        item = self.group_tree.identify_row(event.y)
        if item:
            self.group_tree.selection_set(item)
            self._on_group_select(event)
            self.group_menu.post(event.x_root, event.y_root)
    
    def _on_member_select(self, event: tk.Event) -> None:
        """Handle member selection"""
        selection = self.members_tree.selection()
        self.remove_member_btn.configure(
            state=tk.NORMAL if selection else tk.DISABLED
        )
    
    def _on_member_right_click(self, event: tk.Event) -> None:
        """Handle member right-click"""
        item = self.members_tree.identify_row(event.y)
        if item:
            self.members_tree.selection_set(item)
            self.member_menu.post(event.x_root, event.y_root)
    
    def _on_create_click(self) -> None:
        """Handle create button"""
        if self.on_group_create:
            self.on_group_create()
    
    def _on_delete_click(self) -> None:
        """Handle delete button"""
        if self.selected_group_id and self.on_group_delete:
            self.on_group_delete(self.selected_group_id)
    
    def _on_refresh_click(self) -> None:
        """Handle refresh button"""
        if self.on_refresh:
            self.on_refresh()
    
    def _on_add_member_click(self) -> None:
        """Handle add member button"""
        if self.selected_group_id and self.on_member_add:
            self.on_member_add(self.selected_group_id)
    
    def _on_remove_member_click(self) -> None:
        """Handle remove member button"""
        if not self.selected_group_id:
            return
        
        selection = self.members_tree.selection()
        if not selection:
            return
        
        for item_id in selection:
            if item_id.startswith("member_"):
                try:
                    pid = int(item_id[7:])
                    if self.on_member_remove:
                        self.on_member_remove(self.selected_group_id, pid)
                except ValueError:
                    pass
    
    def _on_generate_keys_click(self) -> None:
        """Handle generate keys button"""
        if self.selected_group_id:
            # This will be handled by the main window
            pass
    
    def _on_distribute_keys_click(self) -> None:
        """Handle distribute keys button"""
        if self.selected_group_id and self.on_group_distribute_keys:
            self.on_group_distribute_keys(self.selected_group_id)
    
    def _on_verify_keys_click(self) -> None:
        """Handle verify keys button"""
        if self.selected_group_id and self.on_group_verify_keys:
            self.on_group_verify_keys(self.selected_group_id)
    
    def _update_details(self, group: Optional[GroupDisplayInfo]) -> None:
        """Update details panel"""
        if group is None:
            self.details_title.configure(text="No group selected")
            self.details_subtitle.configure(text="")
            
            for label in self.info_labels.values():
                label.configure(text="-", foreground="gray")
            
            self._clear_members()
            self._update_buttons(False)
            return
        
        self.details_title.configure(text=group.name)
        self.details_subtitle.configure(
            text=group.description or "No description"
        )
        
        # Update info tab
        self.info_labels["id"].configure(text=str(group.group_id), foreground="black")
        self.info_labels["name"].configure(text=group.name, foreground="black")
        self.info_labels["description"].configure(
            text=group.description or "-",
            foreground="black" if group.description else "gray"
        )
        self.info_labels["member_count"].configure(
            text=str(len(group.member_pids)),
            foreground="black"
        )
        
        keys_text = "Yes" if group.has_keys else "No"
        keys_color = "green" if group.has_keys else "orange"
        self.info_labels["has_keys"].configure(text=keys_text, foreground=keys_color)
        
        self.info_labels["created"].configure(
            text=group.created_at or "-",
            foreground="black" if group.created_at else "gray"
        )
        self.info_labels["updated"].configure(
            text=group.updated_at or "-",
            foreground="black" if group.updated_at else "gray"
        )
        
        # Update members tab
        self._update_members(group.member_pids)
        
        # Update keys tab
        if group.has_keys:
            self.key_status_label.configure(
                text="Keys are configured for this group",
                foreground="green"
            )
        else:
            self.key_status_label.configure(
                text="No keys configured - generate or import keys",
                foreground="orange"
            )
        
        self._update_buttons(True)
    
    def _update_members(self, member_pids: List[int]) -> None:
        """Update members list"""
        self._clear_members()
        
        for pid in sorted(member_pids):
            item_id = f"member_{pid}"
            self.members_tree.insert(
                "",
                tk.END,
                iid=item_id,
                values=(f"PID {pid}", "Unknown"),
            )
    
    def _clear_members(self) -> None:
        """Clear members list"""
        for item in self.members_tree.get_children():
            self.members_tree.delete(item)
    
    def _update_buttons(self, enabled: bool) -> None:
        """Update button states"""
        state = tk.NORMAL if enabled else tk.DISABLED
        
        self.add_member_btn.configure(state=state)
        self.generate_keys_btn.configure(state=state)
        self.distribute_keys_btn.configure(state=state)
        self.verify_keys_btn.configure(state=state)
        
        # Remove member requires selection
        self.remove_member_btn.configure(state=tk.DISABLED)
    
    def add_group(self, group: GroupDisplayInfo) -> None:
        """Add or update a group"""
        self.groups[group.group_id] = group
        self._refresh_tree()
    
    def remove_group(self, group_id: int) -> None:
        """Remove a group"""
        if group_id in self.groups:
            del self.groups[group_id]
            self._refresh_tree()
    
    def clear_groups(self) -> None:
        """Clear all groups"""
        self.groups.clear()
        self._refresh_tree()
    
    def set_groups(self, groups: List[GroupDisplayInfo]) -> None:
        """Set the group list"""
        self.groups = {g.group_id: g for g in groups}
        self._refresh_tree()
    
    def _refresh_tree(self) -> None:
        """Refresh the group tree"""
        old_selection = self.selected_group_id
        
        for item in self.group_tree.get_children():
            self.group_tree.delete(item)
        
        for group_id in sorted(self.groups.keys()):
            group = self.groups[group_id]
            
            item_id = f"group_{group_id}"
            members = str(len(group.member_pids))
            keys = "✓" if group.has_keys else "✗"
            
            self.group_tree.insert(
                "",
                tk.END,
                iid=item_id,
                text=f"{group.name}",
                values=(members, keys),
            )
        
        if old_selection and f"group_{old_selection}" in self.group_tree.get_children():
            self.group_tree.selection_set(f"group_{old_selection}")
    
    def get_selected_group(self) -> Optional[GroupDisplayInfo]:
        """Get selected group"""
        if self.selected_group_id:
            return self.groups.get(self.selected_group_id)
        return None
    
    def get_all_groups(self) -> List[GroupDisplayInfo]:
        """Get all groups"""
        return list(self.groups.values())
    
    def update_member_status(self, pid: int, status: str) -> None:
        """Update a member's status display"""
        item_id = f"member_{pid}"
        if item_id in self.members_tree.get_children():
            self.members_tree.item(item_id, values=(f"PID {pid}", status))

