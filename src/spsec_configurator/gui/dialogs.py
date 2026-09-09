# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Reusable dialogs: confirmations, progress, key input, error messages."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any, Optional, List, Tuple
from ..core.keys import generate_key_id
import secrets


class BaseDialog(tk.Toplevel):
    """Base class for modal dialogs"""
    
    def __init__(
        self,
        parent: tk.Widget,
        title: str = "Dialog",
        width: int = 400,
        height: int = 300,
    ):
        super().__init__(parent)
        self.title(title)
        self.result: Optional[Any] = None
        
        # Make modal
        self.transient(parent)
        self.grab_set()
        
        # Center on parent
        self.geometry(f"{width}x{height}")
        self.update_idletasks()
        
        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_w = parent.winfo_width()
        parent_h = parent.winfo_height()
        
        x = parent_x + (parent_w - width) // 2
        y = parent_y + (parent_h - height) // 2
        self.geometry(f"+{x}+{y}")
        
        # Handle close button
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        
        # Create content
        self.create_widgets()
        
        # Bind escape key
        self.bind("<Escape>", lambda e: self.on_cancel())
    
    def create_widgets(self) -> None:
        """Override in subclasses to create dialog content"""
        pass
    
    def on_ok(self) -> None:
        """Handle OK button"""
        self.destroy()
    
    def on_cancel(self) -> None:
        """Handle Cancel button"""
        self.result = None
        self.destroy()
    
    def show(self) -> Optional[Any]:
        """Show dialog and return result"""
        self.wait_window()
        return self.result


class ConfirmDialog(BaseDialog):
    """Confirmation dialog with customizable message and buttons"""
    
    def __init__(
        self,
        parent: tk.Widget,
        title: str = "Confirm",
        message: str = "Are you sure?",
        detail: str = "",
        ok_text: str = "OK",
        cancel_text: str = "Cancel",
        warning: bool = False,
    ):
        self.message = message
        self.detail = detail
        self.ok_text = ok_text
        self.cancel_text = cancel_text
        self.warning = warning
        super().__init__(parent, title, 400, 180)
    
    def create_widgets(self) -> None:
        # Main frame with padding
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Icon and message frame
        msg_frame = ttk.Frame(main_frame)
        msg_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Message
        msg_label = ttk.Label(
            msg_frame,
            text=self.message,
            font=("TkDefaultFont", 11, "bold"),
            wraplength=350,
        )
        msg_label.pack(anchor=tk.W)
        
        if self.detail:
            detail_label = ttk.Label(
                msg_frame,
                text=self.detail,
                wraplength=350,
                foreground="gray",
            )
            detail_label.pack(anchor=tk.W, pady=(5, 0))
        
        # Button frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        cancel_btn = ttk.Button(
            btn_frame,
            text=self.cancel_text,
            command=self.on_cancel,
        )
        cancel_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        style = "Accent.TButton" if not self.warning else "TButton"
        ok_btn = ttk.Button(
            btn_frame,
            text=self.ok_text,
            command=self.on_ok,
            style=style,
        )
        ok_btn.pack(side=tk.RIGHT)
        ok_btn.focus_set()
        
        self.bind("<Return>", lambda e: self.on_ok())
    
    def on_ok(self) -> None:
        self.result = True
        self.destroy()


class ErrorDialog(BaseDialog):
    """Error dialog with details expansion"""
    
    def __init__(
        self,
        parent: tk.Widget,
        title: str = "Error",
        message: str = "An error occurred",
        details: str = "",
    ):
        self.message = message
        self.details = details
        height = 200 if details else 150
        super().__init__(parent, title, 450, height)
    
    def create_widgets(self) -> None:
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Error message
        msg_label = ttk.Label(
            main_frame,
            text=self.message,
            font=("TkDefaultFont", 11),
            wraplength=400,
            foreground="red",
        )
        msg_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Details (if any)
        if self.details:
            details_frame = ttk.LabelFrame(main_frame, text="Details", padding=10)
            details_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
            
            details_text = tk.Text(
                details_frame,
                height=4,
                wrap=tk.WORD,
                font=("TkFixedFont", 9),
            )
            details_text.insert(tk.END, self.details)
            details_text.configure(state=tk.DISABLED)
            details_text.pack(fill=tk.BOTH, expand=True)
        
        # OK button
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        ok_btn = ttk.Button(btn_frame, text="OK", command=self.on_ok)
        ok_btn.pack(side=tk.RIGHT)
        ok_btn.focus_set()
        
        self.bind("<Return>", lambda e: self.on_ok())


class KeyInputDialog(BaseDialog):
    """Dialog for entering cryptographic keys"""
    
    def __init__(
        self,
        parent: tk.Widget,
        title: str = "Enter Keys",
        show_integrator: bool = True,
        show_seed: bool = True,
        allow_generate: bool = True,
    ):
        self.show_integrator = show_integrator
        self.show_seed = show_seed
        self.allow_generate = allow_generate
        height = 400 if show_integrator and show_seed else 280
        super().__init__(parent, title, 550, height)
    
    def create_widgets(self) -> None:
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scrollable content
        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=canvas.yview)
        content_frame = ttk.Frame(canvas)
        
        content_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=content_frame, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        self.entries = {}
        
        if self.show_integrator:
            self._create_key_section(
                content_frame,
                "Integrator",
                "integrator",
            )
        
        if self.show_seed:
            self._create_key_section(
                content_frame,
                "Seed",
                "seed",
            )
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        if self.allow_generate:
            gen_btn = ttk.Button(
                btn_frame,
                text="Generate Random",
                command=self._generate_random,
            )
            gen_btn.pack(side=tk.LEFT)
        
        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.on_cancel)
        cancel_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        ok_btn = ttk.Button(btn_frame, text="OK", command=self.on_ok)
        ok_btn.pack(side=tk.RIGHT)
    
    def _create_key_section(
        self,
        parent: ttk.Frame,
        label: str,
        prefix: str,
    ) -> None:
        """Create a key input section"""
        frame = ttk.LabelFrame(parent, text=f"{label} Keys", padding=10)
        frame.pack(fill=tk.X, pady=(0, 10))
        
        # Key
        key_label = ttk.Label(frame, text="Key (32 bytes hex):")
        key_label.grid(row=0, column=0, sticky=tk.W, pady=2)
        
        key_entry = ttk.Entry(frame, width=70, font=("TkFixedFont", 9))
        key_entry.grid(row=1, column=0, sticky=tk.EW, pady=(0, 5))
        self.entries[f"{prefix}_key"] = key_entry
        
        # Salt
        salt_label = ttk.Label(frame, text="Salt (16 bytes hex):")
        salt_label.grid(row=2, column=0, sticky=tk.W, pady=2)
        
        salt_entry = ttk.Entry(frame, width=70, font=("TkFixedFont", 9))
        salt_entry.grid(row=3, column=0, sticky=tk.EW, pady=(0, 5))
        self.entries[f"{prefix}_salt"] = salt_entry
        
        # Key ID
        id_label = ttk.Label(frame, text="Key ID:")
        id_label.grid(row=4, column=0, sticky=tk.W, pady=2)
        
        id_entry = ttk.Entry(frame, width=20)
        id_entry.grid(row=5, column=0, sticky=tk.W)
        self.entries[f"{prefix}_key_id"] = id_entry
        
        frame.columnconfigure(0, weight=1)
    
    def _generate_random(self) -> None:
        """Generate random keys and salts"""
        for name, entry in self.entries.items():
            if name.endswith("_key"):
                entry.delete(0, tk.END)
                entry.insert(0, secrets.token_hex(32))
            elif name.endswith("_salt"):
                entry.delete(0, tk.END)
                entry.insert(0, secrets.token_hex(16))
            elif name.endswith("_key_id"):
                entry.delete(0, tk.END)
                entry.insert(0, str(generate_key_id()))
    
    def on_ok(self) -> None:
        """Validate and return keys"""
        result = {}
        
        try:
            for name, entry in self.entries.items():
                value = entry.get().strip()
                
                if name.endswith("_key"):
                    if len(value) != 64:
                        raise ValueError(f"Key must be 64 hex characters (32 bytes)")
                    result[name] = bytes.fromhex(value)
                elif name.endswith("_salt"):
                    if len(value) != 32:
                        raise ValueError(f"Salt must be 32 hex characters (16 bytes)")
                    result[name] = bytes.fromhex(value)
                elif name.endswith("_key_id"):
                    result[name] = int(value)
            
            self.result = result
            self.destroy()
        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e), parent=self)


class DeviceSelectDialog(BaseDialog):
    """Dialog for selecting devices from a list"""
    
    def __init__(
        self,
        parent: tk.Widget,
        title: str = "Select Devices",
        devices: List[Tuple[int, str]] = None,
        multi_select: bool = True,
    ):
        self.devices = devices or []
        self.multi_select = multi_select
        super().__init__(parent, title, 400, 350)
    
    def create_widgets(self) -> None:
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Instructions
        label = ttk.Label(
            main_frame,
            text="Select device(s):" if self.multi_select else "Select a device:",
        )
        label.pack(anchor=tk.W, pady=(0, 10))
        
        # Device list
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        selectmode = tk.EXTENDED if self.multi_select else tk.BROWSE
        self.listbox = tk.Listbox(
            list_frame,
            selectmode=selectmode,
            yscrollcommand=scrollbar.set,
            font=("TkFixedFont", 10),
        )
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.configure(command=self.listbox.yview)
        
        for pid, info in self.devices:
            self.listbox.insert(tk.END, f"PID {pid}: {info}")
        
        # Select all / none buttons (multi-select only)
        if self.multi_select:
            sel_frame = ttk.Frame(main_frame)
            sel_frame.pack(fill=tk.X, pady=(0, 10))
            
            sel_all_btn = ttk.Button(
                sel_frame,
                text="Select All",
                command=lambda: self.listbox.select_set(0, tk.END),
            )
            sel_all_btn.pack(side=tk.LEFT)
            
            sel_none_btn = ttk.Button(
                sel_frame,
                text="Select None",
                command=lambda: self.listbox.select_clear(0, tk.END),
            )
            sel_none_btn.pack(side=tk.LEFT, padx=(5, 0))
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)
        
        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.on_cancel)
        cancel_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        ok_btn = ttk.Button(btn_frame, text="OK", command=self.on_ok)
        ok_btn.pack(side=tk.RIGHT)
    
    def on_ok(self) -> None:
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select at least one device.", parent=self)
            return
        
        self.result = [self.devices[i][0] for i in selection]
        self.destroy()


class GroupSelectDialog(BaseDialog):
    """Dialog for selecting a group"""
    
    def __init__(
        self,
        parent: tk.Widget,
        title: str = "Select Group",
        groups: List[Tuple[int, str, int]] = None,
    ):
        self.groups = groups or []  # List of (group_id, name, member_count)
        super().__init__(parent, title, 400, 300)
    
    def create_widgets(self) -> None:
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Instructions
        label = ttk.Label(main_frame, text="Select a group:")
        label.pack(anchor=tk.W, pady=(0, 10))
        
        # Group list
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.listbox = tk.Listbox(
            list_frame,
            selectmode=tk.BROWSE,
            yscrollcommand=scrollbar.set,
            font=("TkFixedFont", 10),
        )
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.configure(command=self.listbox.yview)
        
        for group_id, name, member_count in self.groups:
            self.listbox.insert(tk.END, f"Group {group_id}: {name} ({member_count} members)")
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)
        
        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.on_cancel)
        cancel_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        ok_btn = ttk.Button(btn_frame, text="OK", command=self.on_ok)
        ok_btn.pack(side=tk.RIGHT)
    
    def on_ok(self) -> None:
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a group.", parent=self)
            return
        
        self.result = self.groups[selection[0]][0]
        self.destroy()


class CreateGroupDialog(BaseDialog):
    """Dialog for creating a new group"""
    
    def __init__(
        self,
        parent: tk.Widget,
        title: str = "Create Group",
    ):
        super().__init__(parent, title, 400, 280)
    
    def create_widgets(self) -> None:
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Group ID
        id_label = ttk.Label(main_frame, text="Group ID:")
        id_label.grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.id_entry = ttk.Entry(main_frame, width=10)
        self.id_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Group name
        name_label = ttk.Label(main_frame, text="Name:")
        name_label.grid(row=1, column=0, sticky=tk.W, pady=5)
        
        self.name_entry = ttk.Entry(main_frame, width=40)
        self.name_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        
        # Description
        desc_label = ttk.Label(main_frame, text="Description:")
        desc_label.grid(row=2, column=0, sticky=tk.NW, pady=5)
        
        self.desc_text = tk.Text(main_frame, height=4, width=40)
        self.desc_text.grid(row=2, column=1, sticky=tk.EW, pady=5)
        
        # Generate keys checkbox
        self.generate_keys_var = tk.BooleanVar(value=True)
        gen_check = ttk.Checkbutton(
            main_frame,
            text="Generate keys for this group",
            variable=self.generate_keys_var,
        )
        gen_check.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=10)
        
        main_frame.columnconfigure(1, weight=1)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=4, column=0, columnspan=2, sticky=tk.E, pady=(20, 0))
        
        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.on_cancel)
        cancel_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        ok_btn = ttk.Button(btn_frame, text="Create", command=self.on_ok)
        ok_btn.pack(side=tk.RIGHT)
        
        self.id_entry.focus_set()
    
    def on_ok(self) -> None:
        try:
            group_id = int(self.id_entry.get().strip())
            name = self.name_entry.get().strip()
            description = self.desc_text.get("1.0", tk.END).strip()
            generate_keys = self.generate_keys_var.get()
            
            if not name:
                raise ValueError("Group name is required")
            
            self.result = {
                "group_id": group_id,
                "name": name,
                "description": description or None,
                "generate_keys": generate_keys,
            }
            self.destroy()
        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e), parent=self)


def show_info(parent: tk.Widget, title: str, message: str) -> None:
    """Show an information message"""
    messagebox.showinfo(title, message, parent=parent)


def show_warning(parent: tk.Widget, title: str, message: str) -> None:
    """Show a warning message"""
    messagebox.showwarning(title, message, parent=parent)


def show_error(parent: tk.Widget, title: str, message: str, details: str = "") -> None:
    """Show an error message"""
    if details:
        dialog = ErrorDialog(parent, title, message, details)
        dialog.show()
    else:
        messagebox.showerror(title, message, parent=parent)


def ask_yes_no(parent: tk.Widget, title: str, message: str) -> bool:
    """Ask a yes/no question"""
    return messagebox.askyesno(title, message, parent=parent)

