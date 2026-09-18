"""LocalGuard Antivirus - scan history page.

Lists recorded scans with per-scan results, export to TXT/CSV/JSON,
and delete controls (spec sections 30, 32).
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING

import tkinter.ttk as ttk

from ui.widgets import Card, make_treeview

if TYPE_CHECKING:  # pragma: no cover
    from ui.app import LocalGuardApp


class HistoryPage(ttk.Frame):
    """Scan history page."""

    def __init__(self, master: tk.Widget, app: "LocalGuardApp") -> None:
        super().__init__(master)
        self.app = app
        self._build()

    def _build(self) -> None:
        """Construct history page widgets."""
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=16, pady=12)

        list_card = Card(container)
        list_card.pack(fill="both", expand=True, pady=(0, 12))
        ttk.Label(list_card, text="SCAN HISTORY", style="H2.TLabel").pack(
            anchor="w", pady=(0, 6))

        columns = {
            "id": ("ID", 50, "e"),
            "type": ("Type", 90, "w"),
            "start": ("Started", 130, "w"),
            "duration": ("Duration", 80, "e"),
            "files": ("Files", 90, "e"),
            "threats": ("Threats", 70, "e"),
            "suspicious": ("Suspicious", 90, "e"),
            "status": ("Status", 90, "w"),
        }
        self.tree = make_treeview(list_card, columns, heights=8)
        self.tree._scrollframe.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", self._show_scan_results)

        btn_row = ttk.Frame(list_card, style="Card.TFrame")
        btn_row.pack(fill="x", pady=(8, 0))
        ttk.Button(btn_row, text="View Results",
                   command=self._show_scan_results).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Export TXT",
                   command=lambda: self._export("txt")).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Export CSV",
                   command=lambda: self._export("csv")).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Export JSON",
                   command=lambda: self._export("json")).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Delete Selected",
                   command=self._delete_selected).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Clear All History",
                   style="Danger.TButton",
                   command=self._clear_all).pack(side="left")

        # Security events card
        events_card = Card(container)
        events_card.pack(fill="both", expand=True)
        ttk.Label(events_card, text="SECURITY EVENTS", style="H2.TLabel").pack(
            anchor="w", pady=(0, 6))

        event_columns = {
            "time": ("Time", 130, "w"),
            "type": ("Event", 130, "w"),
            "severity": ("Severity", 80, "w"),
            "description": ("Description", 420, "w"),
        }
        self.events_tree = make_treeview(events_card, event_columns, heights=7)
        self.events_tree._scrollframe.pack(fill="both", expand=True)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _selected_scan_id(self) -> int | None:
        """Return the scan_id of the selected row."""
        selection = self.tree.selection()
        if not selection:
            tk.messagebox.showinfo("LocalGuard", "Select a scan first.",
                                   parent=self)
            return None
        values = self.tree.item(selection[0], "values")
        try:
            return int(values[0])
        except (ValueError, TypeError):
            return None

    def _show_scan_results(self, _event=None) -> None:
        """Open a results dialog for the selected scan."""
        scan_id = self._selected_scan_id()
        if scan_id is not None:
            self.app.show_scan_results_dialog(scan_id, parent=self)

    def _export(self, fmt: str) -> None:
        """Export the selected scan report."""
        scan_id = self._selected_scan_id()
        if scan_id is None:
            return
        target = tk.filedialog.asksaveasfilename(
            parent=self, defaultextension=f".{fmt}",
            filetypes=[(f"{fmt.upper()} report", f"*.{fmt}")],
            initialfile=f"localguard_report_{scan_id}.{fmt}",
        )
        if not target:
            return
        self.app.export_scan_report(scan_id, fmt, target)

    def _delete_selected(self) -> None:
        """Delete the selected scan from history."""
        scan_id = self._selected_scan_id()
        if scan_id is None:
            return
        if not tk.messagebox.askyesno("LocalGuard",
                                      "Delete the selected scan record?",
                                      parent=self):
            return
        self.app.delete_scan_record(scan_id)
        self.refresh()

    def _clear_all(self) -> None:
        """Wipe all scan history after confirmation."""
        if not tk.messagebox.askyesno(
            "LocalGuard", "Delete ALL scan history records?", parent=self
        ):
            return
        self.app.clear_scan_history()
        self.refresh()

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Reload scan history and events."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        for scan in self.app.list_scans():
            duration = scan.get("duration_secs") or 0
            minutes, seconds = divmod(int(float(duration)), 60)
            self.tree.insert("", "end", values=(
                str(scan.get("scan_id", "")),
                str(scan.get("scan_type", "")),
                str(scan.get("start_time", "")),
                f"{minutes:02d}:{seconds:02d}",
                f"{int(scan.get('files_scanned', 0)):,}",
                str(scan.get("threats_found", 0)),
                str(scan.get("suspicious_found", 0)),
                str(scan.get("status", "")),
            ))

        for item in self.events_tree.get_children():
            self.events_tree.delete(item)
        for event in self.app.recent_events(50):
            self.events_tree.insert("", "end", values=(
                str(event.get("created_at", "")),
                str(event.get("event_type", "")),
                str(event.get("severity", "")),
                str(event.get("description", ""))[:100],
            ))
