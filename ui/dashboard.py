"""Khokhar & Son's Antivirus - dashboard page.

The main security dashboard (spec sections 5, 40): protection status
banner, component status rows, scan action buttons, recent security
events, and quick threat statistics.
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING

import tkinter.ttk as ttk

from ui.theme import colors
from ui.widgets import Card, StatRow, StatusBanner, add_tooltip, make_treeview

if TYPE_CHECKING:  # pragma: no cover
    from ui.app import KhokharGuardApp


class DashboardPage(ttk.Frame):
    """Main dashboard."""

    def __init__(self, master: tk.Widget, app: "KhokharGuardApp") -> None:
        super().__init__(master)
        self.app = app
        palette = colors()
        self._build()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build(self) -> None:
        """Construct all dashboard widgets."""
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=16, pady=12)

        # Status banner
        self.banner = StatusBanner(container)
        self.banner.pack(fill="x", pady=(0, 12))

        # Middle section: status + actions side by side
        middle = ttk.Frame(container)
        middle.pack(fill="x", pady=(0, 12))

        status_card = Card(middle)
        status_card.pack(side="left", fill="both", expand=True, padx=(0, 12))

        ttk.Label(status_card, text="PROTECTION COMPONENTS", style="H2.TLabel").pack(
            anchor="w", pady=(0, 8))

        self.realtime_row = StatRow(status_card, "Real-Time Protection", "...")
        self.realtime_row.pack(fill="x", pady=2)
        self.usb_row = StatRow(status_card, "USB Protection", "...")
        self.usb_row.pack(fill="x", pady=2)
        self.defender_row = StatRow(status_card, "Windows Security", "...")
        self.defender_row.pack(fill="x", pady=2)
        self.signature_row = StatRow(status_card, "Signature Database", "...")
        self.signature_row.pack(fill="x", pady=2)
        self.last_scan_row = StatRow(status_card, "Last Scan", "Never")
        self.last_scan_row.pack(fill="x", pady=2)
        self.threats_row = StatRow(status_card, "Threats Found", "0")
        self.threats_row.pack(fill="x", pady=2)
        self.quarantine_row = StatRow(status_card, "Quarantined", "0")
        self.quarantine_row.pack(fill="x", pady=2)
        self.admin_row = StatRow(status_card, "Administrator Privileges", "...")
        self.admin_row.pack(fill="x", pady=2)

        # Action buttons
        actions = Card(middle)
        actions.pack(side="left", fill="both", padx=(0, 0))

        ttk.Label(actions, text="SCAN ACTIONS", style="H2.TLabel").pack(
            anchor="w", pady=(0, 8))

        self.quick_btn = ttk.Button(actions, text="QUICK SCAN",
                                    style="Accent.TButton",
                                    command=self.app.start_quick_scan)
        self.quick_btn.pack(fill="x", pady=4)
        add_tooltip(self.quick_btn, "Scan Downloads, Desktop, Temp and "
                                    "startup locations (fast)")

        self.full_btn = ttk.Button(actions, text="FULL SYSTEM SCAN",
                                   command=self.app.start_full_scan)
        self.full_btn.pack(fill="x", pady=4)
        add_tooltip(self.full_btn, "Scan all local drives (slow, thorough)")

        self.usb_btn = ttk.Button(actions, text="SCAN USB",
                                  command=self.app.show_usb_page)
        self.usb_btn.pack(fill="x", pady=4)
        add_tooltip(self.usb_btn, "Scan a connected removable drive")

        self.custom_btn = ttk.Button(actions, text="CUSTOM SCAN",
                                     command=self.app.show_scan_page)
        self.custom_btn.pack(fill="x", pady=4)
        add_tooltip(self.custom_btn, "Choose specific files or folders")

        # Bottom section: events + stats
        bottom = ttk.Frame(container)
        bottom.pack(fill="both", expand=True)

        events_card = Card(bottom)
        events_card.pack(side="left", fill="both", expand=True, padx=(0, 12))
        ttk.Label(events_card, text="RECENT SECURITY EVENTS", style="H2.TLabel").pack(
            anchor="w", pady=(0, 6))
        event_columns = {
            "time": ("Time", 120, "w"),
            "type": ("Event", 130, "w"),
            "description": ("Description", 340, "w"),
        }
        self.events_tree = make_treeview(events_card, event_columns, heights=7)
        self.events_tree._scrollframe.pack(fill="both", expand=True)

        stats_card = Card(bottom)
        stats_card.pack(side="left", fill="both")
        ttk.Label(stats_card, text="THREAT STATISTICS", style="H2.TLabel").pack(
            anchor="w", pady=(0, 6))
        self.stat_open = StatRow(stats_card, "Open threats", "0")
        self.stat_open.pack(fill="x", pady=2)
        self.stat_quarantined = StatRow(stats_card, "Quarantined", "0")
        self.stat_quarantined.pack(fill="x", pady=2)
        self.stat_allowed = StatRow(stats_card, "Allowed by user", "0")
        self.stat_allowed.pack(fill="x", pady=2)
        self.stat_total = StatRow(stats_card, "Total detections", "0")
        self.stat_total.pack(fill="x", pady=2)
        self.stat_scans = StatRow(stats_card, "Scans recorded", "0")
        self.stat_scans.pack(fill="x", pady=2)

        open_threats_btn = ttk.Button(stats_card, text="Review open threats",
                                      command=self.app.show_history_page)
        open_threats_btn.pack(fill="x", pady=(10, 0))

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Pull current status from app services into the widgets."""
        status = self.app.protection_status()
        palette = colors()

        if status.get("paused"):
            self.banner.set_state("PAUSED",
                                  "Protection paused - real-time and USB "
                                  "monitoring are OFF", "warning")
        elif status.get("realtime_enabled") or status.get("usb_monitoring"):
            self.banner.set_state("PROTECTED",
                                  "Real-time protection and USB monitoring active",
                                  "success")
        else:
            self.banner.set_state("NOT PROTECTED",
                                  "Protection components are disabled", "danger")

        self.realtime_row.set("ON" if status.get("realtime_enabled") else "OFF")
        self.usb_row.set("ON" if status.get("usb_monitoring") else "OFF")

        defender = self.app.defender_status()
        if defender.get("available"):
            rt = defender.get("realtime_enabled")
            self.defender_row.set(
                f"Connected ({'RT ON' if rt else 'RT OFF'})")
        else:
            self.defender_row.set("Not detected")

        self.signature_row.set(self.app.signature_version_label())

        last_scan = self.app.last_scan_summary()
        self.last_scan_row.set(last_scan)

        counts = self.app.threat_counts()
        self.threats_row.set(str(counts.get("open", 0)))
        self.quarantine_row.set(str(self.app.quarantine_count()))

        self.stat_open.set(str(counts.get("open", 0)))
        self.stat_quarantined.set(str(counts.get("quarantined", 0)))
        self.stat_allowed.set(str(counts.get("allowed", 0)))
        self.stat_total.set(str(counts.get("total", 0)))
        self.stat_scans.set(str(self.app.total_scans()))

        is_admin = self.app.is_admin()
        self.admin_row.set("YES" if is_admin else "NO (limited cleanup)")

        self._refresh_events()

    def _refresh_events(self) -> None:
        """Reload the recent events list."""
        tree = self.events_tree
        for item in tree.get_children():
            tree.delete(item)
        for event in self.app.recent_events(20):
            tree.insert("", "end", values=(
                str(event.get("created_at", "")),
                str(event.get("event_type", "")),
                str(event.get("description", ""))[:90],
            ))
