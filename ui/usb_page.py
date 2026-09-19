"""LocalGuard Antivirus - USB protection page.

Shows connected removable drives with capacity/free space/filesystem
and scan controls (spec section 10). Includes USB scan results and
the auto-scan setting toggle.
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING, Dict, List

import tkinter.ttk as ttk

from ui.theme import colors
from ui.widgets import Card, StatRow, add_tooltip, make_treeview

if TYPE_CHECKING:  # pragma: no cover
    from ui.app import LocalGuardApp


class USBPage(ttk.Frame):
    """USB protection page."""

    def __init__(self, master: tk.Widget, app: "LocalGuardApp") -> None:
        super().__init__(master)
        self.app = app
        self._devices: List[Dict[str, object]] = []
        self._build()

    def _build(self) -> None:
        """Construct USB page widgets."""
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=16, pady=12)

        header = Card(container)
        header.pack(fill="x", pady=(0, 12))
        ttk.Label(header, text="USB PROTECTION", style="H2.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Removable drives are scanned before use. Scans inspect "
                 "executables, scripts, shortcuts, autorun.inf, hidden files, "
                 "and double-extension files.",
            style="CardDim.TLabel", wraplength=780, justify="left",
        ).pack(anchor="w", pady=(4, 8))

        self.autoscan_var = tk.BooleanVar(
            value=bool(self.app.settings.get("protection.usb_autoscan", True)))
        autoscan_check = ttk.Checkbutton(
            header, text="Automatically scan newly inserted removable drives",
            variable=self.autoscan_var, style="Card.TCheckbutton",
            command=self._toggle_autoscan)
        autoscan_check.pack(anchor="w")
        add_tooltip(autoscan_check,
                    "Scan drives as soon as they are inserted "
                    "(recommended)")

        # Device list card
        devices_card = Card(container)
        devices_card.pack(fill="both", expand=True, pady=(0, 12))
        ttk.Label(devices_card, text="CONNECTED REMOVABLE DEVICES",
                  style="H2.TLabel").pack(anchor="w", pady=(0, 6))

        columns = {
            "drive": ("Drive", 70, "w"),
            "name": ("Volume Name", 160, "w"),
            "capacity": ("Capacity", 100, "e"),
            "free": ("Free Space", 100, "e"),
            "fs": ("File System", 90, "w"),
            "status": ("Last Scan Status", 140, "w"),
        }
        self.device_tree = make_treeview(devices_card, columns, heights=5)
        self.device_tree._scrollframe.pack(fill="both", expand=True)

        device_btn_row = ttk.Frame(devices_card, style="Card.TFrame")
        device_btn_row.pack(fill="x", pady=(8, 0))
        ttk.Button(device_btn_row, text="Refresh Devices",
                   command=self.refresh).pack(side="left", padx=(0, 8))
        self.scan_btn = ttk.Button(device_btn_row, text="SCAN USB",
                                   style="Accent.TButton",
                                   command=self._scan_selected,
                                   state="disabled")
        self.scan_btn.pack(side="left")
        add_tooltip(self.scan_btn,
                    "Scan the selected drive for malware and suspicious files")
        self.trust_btn = ttk.Button(device_btn_row, text="Trust This Device",
                                    command=self._trust_selected,
                                    state="disabled")
        self.trust_btn.pack(side="left", padx=(8, 0))
        add_tooltip(self.trust_btn,
                    "Remember this drive (by serial and volume label) and "
                    "skip automatic rescans of it. Scanning stays available "
                    "here at any time.")

        # Known devices history card
        history_card = Card(container)
        history_card.pack(fill="both", expand=True)
        ttk.Label(history_card, text="PREVIOUSLY SEEN DEVICES",
                  style="H2.TLabel").pack(anchor="w", pady=(0, 6))

        known_columns = {
            "drive": ("Drive", 70, "w"),
            "name": ("Volume Name", 160, "w"),
            "serial": ("Serial", 110, "w"),
            "seen": ("Last Seen", 150, "w"),
            "scan": ("Last Scan", 150, "w"),
            "status": ("Status", 120, "w"),
        }
        self.known_tree = make_treeview(history_card, known_columns, heights=5)
        self.known_tree._scrollframe.pack(fill="both", expand=True)

        # Trusted devices card
        trusted_card = Card(container)
        trusted_card.pack(fill="both", expand=True)
        ttk.Label(trusted_card, text="TRUSTED DEVICES",
                  style="H2.TLabel").pack(anchor="w", pady=(0, 6))
        ttk.Label(
            trusted_card,
            text="Trusted drives skip the automatic scan when inserted. "
                 "Trust is tied to the drive's serial number and volume "
                 "label, so a different drive is never trusted by accident.",
            style="CardDim.TLabel", wraplength=780, justify="left",
        ).pack(anchor="w", pady=(0, 6))

        trusted_columns = {
            "name": ("Volume Name", 180, "w"),
            "serial": ("Serial", 120, "w"),
            "label": ("Note", 220, "w"),
            "since": ("Trusted Since", 170, "w"),
        }
        self.trusted_tree = make_treeview(trusted_card, trusted_columns,
                                          heights=4)
        self.trusted_tree._scrollframe.pack(fill="both", expand=True)

        trusted_btn_row = ttk.Frame(trusted_card, style="Card.TFrame")
        trusted_btn_row.pack(fill="x", pady=(8, 0))
        ttk.Button(trusted_btn_row, text="Revoke Trust",
                   command=self._untrust_selected).pack(side="left")
        add_tooltip(
            trusted_btn_row.children["!button"],
            "Remove trust so this drive is scanned automatically again")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _toggle_autoscan(self) -> None:
        """Persist the USB auto-scan setting."""
        self.app.settings.set("protection.usb_autoscan",
                              bool(self.autoscan_var.get()))

    def _scan_selected(self) -> None:
        """Start a USB scan for the selected drive."""
        selection = self.device_tree.selection()
        if not selection:
            tk.messagebox.showinfo("LocalGuard",
                                   "Select a removable drive first.", parent=self)
            return
        values = self.device_tree.item(selection[0], "values")
        drive_letter = str(values[0])
        self.app.start_usb_scan(drive_letter)

    def _trust_selected(self) -> None:
        """Trust the selected drive (by serial + volume label)."""
        selection = self.device_tree.selection()
        if not selection:
            tk.messagebox.showinfo("LocalGuard",
                                   "Select a removable drive first.", parent=self)
            return
        index = self.device_tree.index(selection[0])
        if index >= len(self._devices):
            return
        device = self._devices[index]
        serial = str(device.get("serial", "") or "")
        volume = str(device.get("volume_name", "") or "")
        if not serial or not volume:
            tk.messagebox.showwarning(
                "LocalGuard",
                "This drive cannot be identified reliably (no serial or "
                "volume label), so it cannot be trusted. It will be "
                "scanned automatically every time.", parent=self)
            return
        self.app.database.trust_usb_device(serial, volume, volume)
        self.app.database.add_event(
            "usb_trust_granted",
            f"USB device trusted: {device.get('drive_letter')} "
            f"'{volume}' (serial {serial}) - auto-scan skipped for it")
        self.refresh()

    def _untrust_selected(self) -> None:
        """Revoke trust for the selected trusted device."""
        selection = self.trusted_tree.selection()
        if not selection:
            tk.messagebox.showinfo(
                "LocalGuard", "Select a trusted device first.", parent=self)
            return
        values = self.trusted_tree.item(selection[0], "values")
        serial, volume = str(values[1]), str(values[0])
        if not tk.messagebox.askyesno(
                "LocalGuard",
                f"Stop trusting '{volume}' (serial {serial})?\n\n"
                "It will be scanned automatically on every insertion.",
                parent=self):
            return
        self.app.database.untrust_usb_device(serial, volume)
        self.app.database.add_event(
            "usb_trust_revoked",
            f"USB device trust revoked: '{volume}' (serial {serial})")
        self.refresh()

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Reload device lists."""
        palette = colors()
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        for item in self.known_tree.get_children():
            self.known_tree.delete(item)

        self._devices = self.app.list_usb_devices()
        trusted = {
            (str(r.get("serial", "")), str(r.get("volume_name", "")))
            for r in self.app.database.list_trusted_usb_devices()
        }
        for device in self._devices:
            capacity = device.get("capacity_bytes")
            free = device.get("free_bytes")
            identity = (str(device.get("serial", "") or ""),
                        str(device.get("volume_name", "") or ""))
            values = (
                str(device.get("drive_letter", "")),
                str(device.get("volume_name", "") or "(no label)"),
                self._fmt_bytes(capacity),
                self._fmt_bytes(free),
                str(device.get("file_system", "") or "?"),
                "TRUSTED" if identity in trusted else "NOT SCANNED",
            )
            self.device_tree.insert("", "end", values=values)
            self.scan_btn.configure(state="normal" if self._devices else "disabled")
            self.trust_btn.configure(state="normal" if self._devices else "disabled")

        for record in self.app.list_known_usb_records():
            self.known_tree.insert("", "end", values=(
                str(record.get("drive_letter", "")),
                str(record.get("volume_name", "") or "(no label)"),
                str(record.get("serial", "") or "-"),
                str(record.get("last_seen", "")),
                str(record.get("last_scan_time", "") or "never"),
                str(record.get("last_scan_status", "not_scanned")),
            ))

        for item in self.trusted_tree.get_children():
            self.trusted_tree.delete(item)
        for record in self.app.database.list_trusted_usb_devices():
            self.trusted_tree.insert("", "end", values=(
                str(record.get("volume_name", "") or "(no label)"),
                str(record.get("serial", "") or "-"),
                str(record.get("label", "") or ""),
                str(record.get("trusted_at", "")),
            ))

    @staticmethod
    def _fmt_bytes(num_bytes: object) -> str:
        """Human-readable byte formatting for device rows."""
        try:
            value = float(num_bytes)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return "?"
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if value < 1024 or unit == "TB":
                return f"{value:.1f} {unit}"
            value /= 1024
        return f"{value:.1f} TB"
