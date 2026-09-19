"""Khokhar & Son's Antivirus - quarantine page.

Lists quarantined items with Restore / Delete Permanently / Details
actions (spec section 21). Both destructive actions require explicit
confirmation dialogs.
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING

import tkinter.ttk as ttk

from ui.widgets import Card, add_tooltip, make_treeview

if TYPE_CHECKING:  # pragma: no cover
    from ui.app import KhokharGuardApp


class QuarantinePage(ttk.Frame):
    """Quarantine management page."""

    def __init__(self, master: tk.Widget, app: "KhokharGuardApp") -> None:
        super().__init__(master)
        self.app = app
        self._build()

    def _build(self) -> None:
        """Construct quarantine page widgets."""
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=16, pady=12)

        header = Card(container)
        header.pack(fill="x", pady=(0, 12))
        ttk.Label(header, text="QUARANTINE", style="H2.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Quarantined files are isolated with a non-executable "
                 "wrapper and cannot run from here. Restoring returns the "
                 "file to its original location; deletion is permanent.",
            style="CardDim.TLabel", wraplength=780, justify="left",
        ).pack(anchor="w", pady=(4, 0))

        list_card = Card(container)
        list_card.pack(fill="both", expand=True, pady=(0, 12))

        columns = {
            "threat": ("Threat", 170, "w"),
            "original": ("Original Location", 300, "w"),
            "detection": ("Detection", 90, "w"),
            "severity": ("Severity", 80, "w"),
            "date": ("Date", 130, "w"),
            "size": ("Size", 80, "e"),
        }
        self.tree = make_treeview(list_card, columns, heights=12)
        self.tree._scrollframe.pack(fill="both", expand=True)

        btn_row = ttk.Frame(list_card, style="Card.TFrame")
        btn_row.pack(fill="x", pady=(8, 0))
        restore_btn = ttk.Button(btn_row, text="Restore",
                                 style="Accent.TButton",
                                 command=self._restore_selected)
        restore_btn.pack(side="left", padx=(0, 8))
        add_tooltip(restore_btn,
                    "Return the file to its original location "
                    "(asks for confirmation)")
        delete_btn = ttk.Button(btn_row, text="Delete Permanently",
                                style="Danger.TButton",
                                command=self._delete_selected)
        delete_btn.pack(side="left", padx=(0, 8))
        add_tooltip(delete_btn,
                    "Permanently destroy the quarantined file - cannot "
                    "be undone")
        ttk.Button(btn_row, text="Details...",
                   command=self._show_details).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Refresh",
                   command=self.refresh).pack(side="left")
    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _selected_record(self):
        """Return the DB record behind the selected row.

        Service-originated rows (background protection vault) are
        included: restore/delete for them is routed through the
        authenticated service IPC by the app layer.
        """
        selection = self.tree.selection()
        if not selection:
            tk.messagebox.showinfo("KhokharGuard", "Select a quarantined item first.",
                                   parent=self)
            return None
        return self.app.quarantine_record_for_row(self.tree.item(
            selection[0], "values"))

    def _restore_selected(self) -> None:
        """Restore the selected item after explicit confirmation."""
        record = self._selected_record()
        if record is None:
            return
        if not tk.messagebox.askyesno(
            "Confirm Restore",
            f"Restore '{record.get('detection_name')}' to\n"
            f"{record.get('original_path')}?\n\n"
            "Only restore files you are certain are safe.",
            parent=self,
        ):
            return
        if record.get("origin") == "service":
            self.app.service_quarantine_action(
                int(record["quarantine_id"]), "restore", parent=self)
        else:
            self.app.restore_quarantined(int(record["quarantine_id"]),
                                         parent=self)
        self.refresh()

    def _delete_selected(self) -> None:
        """Permanently delete the selected item after typed confirmation."""
        record = self._selected_record()
        if record is None:
            return
        if not tk.messagebox.askyesno(
            "Confirm Permanent Deletion",
            f"Permanently delete '{record.get('detection_name')}'?\n\n"
            "This cannot be undone.",
            parent=self,
        ):
            return
        if record.get("origin") == "service":
            self.app.service_quarantine_action(
                int(record["quarantine_id"]), "delete", parent=self)
        else:
            self.app.delete_quarantined(int(record["quarantine_id"]),
                                        parent=self)
        self.refresh()

    def _show_details(self) -> None:
        """Show full metadata for the selected record."""
        record = self._selected_record(allow_service=True)
        if record is None:
            return
        self.app.show_quarantine_details(record, parent=self)

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Reload quarantine records."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        for record in self.app.list_quarantine_records():
            service_origin = record.get("origin") == "service"
            threat = str(record.get("detection_name", ""))
            if service_origin:
                threat += "  [service]"
            self.tree.insert("", "end", values=(
                threat,
                str(record.get("original_path", "")),
                str(record.get("detection_type", "")),
                str(record.get("severity", "")).upper(),
                str(record.get("quarantine_date", "")),
                self._fmt_size(record.get("file_size")),
            ))

    @staticmethod
    def _fmt_size(num_bytes: object) -> str:
        """Human-readable size."""
        try:
            value = float(num_bytes)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return "?"
        for unit in ("B", "KB", "MB", "GB"):
            if value < 1024 or unit == "GB":
                return f"{value:.1f} {unit}"
            value /= 1024
        return f"{value:.1f} GB"
