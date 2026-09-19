"""Khokhar & Son's Antivirus - scan page.

Quick/Full/Custom scan UI with live progress, pause/resume/stop, and
the results table (spec sections 7, 8, 9). All scanning happens in
worker threads; the UI only renders progress snapshots, so it never
freezes (spec section 6).
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional

import tkinter.ttk as ttk

from ui.theme import colors, severity_color
from ui.widgets import Card, add_tooltip, make_treeview

if TYPE_CHECKING:  # pragma: no cover
    from ui.app import KhokharGuardApp


class ScanPage(ttk.Frame):
    """Scan controls and progress."""

    def __init__(self, master: tk.Widget, app: "KhokharGuardApp") -> None:
        super().__init__(master)
        self.app = app
        self._selected_targets: List[Path] = []
        self._build()

    def _build(self) -> None:
        """Construct scan page widgets."""
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=16, pady=12)

        # --- Controls card ---
        controls = Card(container)
        controls.pack(fill="x", pady=(0, 12))

        row1 = ttk.Frame(controls, style="Card.TFrame")
        row1.pack(fill="x", pady=4)
        ttk.Button(row1, text="Quick Scan", style="Accent.TButton",
                   command=self.app.start_quick_scan).pack(side="left", padx=(0, 8))
        ttk.Button(row1, text="Full System Scan",
                   command=self.app.start_full_scan).pack(side="left", padx=(0, 8))
        add_tooltip(row1, "Quick: common infection points. Full: every local drive.")

        row2 = ttk.Frame(controls, style="Card.TFrame")
        row2.pack(fill="x", pady=4)
        ttk.Button(row2, text="Select Folder...",
                   command=self._select_folder).pack(side="left", padx=(0, 8))
        ttk.Button(row2, text="Select File...",
                   command=self._select_file).pack(side="left", padx=(0, 8))
        self.custom_start_btn = ttk.Button(row2, text="Start Custom Scan",
                                           command=self._start_custom,
                                           state="disabled")
        self.custom_start_btn.pack(side="left", padx=(0, 8))
        self.target_label = ttk.Label(row2, text="No custom targets selected",
                                      style="CardDim.TLabel")
        self.target_label.pack(side="left", padx=(8, 0))

        # --- Progress card ---
        progress = Card(container)
        progress.pack(fill="x", pady=(0, 12))

        self.status_var = tk.StringVar(value="Ready. No scan running.")
        ttk.Label(progress, textvariable=self.status_var,
                  style="Card.TLabel").pack(anchor="w")

        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(
            progress, variable=self.progress_var, maximum=100.0, mode="determinate"
        )
        self.progress_bar.pack(fill="x", pady=8)

        stats_frame = ttk.Frame(progress, style="Card.TFrame")
        stats_frame.pack(fill="x")
        self.stat_vars: Dict[str, tk.StringVar] = {}
        for key, label in (
            ("files", "Files scanned"), ("dirs", "Directories"),
            ("threats", "Threats"), ("suspicious", "Suspicious"),
            ("skipped", "Skipped"), ("errors", "Errors"), ("elapsed", "Elapsed"),
            ("current", "Current file"),
        ):
            var = tk.StringVar(value="0" if key != "current" else "-")
            self.stat_vars[key] = var
            lbl = ttk.Label(stats_frame, text=f"{label}:",
                            style="CardDim.TLabel")
            lbl.pack(side="left", padx=(0, 4))
            val = ttk.Label(stats_frame, textvariable=var, style="Card.TLabel")
            val.pack(side="left", padx=(0, 14))

        btn_row = ttk.Frame(progress, style="Card.TFrame")
        btn_row.pack(fill="x", pady=(8, 0))
        self.pause_btn = ttk.Button(btn_row, text="Pause",
                                    command=self._toggle_pause, state="disabled")
        self.pause_btn.pack(side="left", padx=(0, 8))
        self.stop_btn = ttk.Button(btn_row, text="Stop",
                                   style="Danger.TButton",
                                   command=self._stop_scan, state="disabled")
        self.stop_btn.pack(side="left")

        # --- Results card ---
        results = Card(container)
        results.pack(fill="both", expand=True)
        ttk.Label(results, text="SCAN RESULTS", style="H2.TLabel").pack(
            anchor="w", pady=(0, 6))

        columns = {
            "severity": ("Severity", 90, "w"),
            "name": ("Detection", 190, "w"),
            "path": ("File", 420, "w"),
            "score": ("Risk", 60, "e"),
            "method": ("Method", 100, "w"),
        }
        self.results_tree = make_treeview(results, columns, heights=10)
        self.results_tree._scrollframe.pack(fill="both", expand=True)

        action_row = ttk.Frame(results, style="Card.TFrame")
        action_row.pack(fill="x", pady=(8, 0))
        ttk.Button(action_row, text="Quarantine Selected",
                   style="Accent.TButton",
                   command=self._quarantine_selected).pack(side="left", padx=(0, 8))
        ttk.Button(action_row, text="Quarantine All Findings",
                   command=self._quarantine_all).pack(side="left", padx=(0, 8))
        ttk.Button(action_row, text="Details...",
                   command=self._show_details).pack(side="left", padx=(0, 8))
        ttk.Button(action_row, text="Allow Selected (mark safe)",
                   command=self._allow_selected).pack(side="left")

    # ------------------------------------------------------------------
    # Target selection
    # ------------------------------------------------------------------

    def _select_folder(self) -> None:
        """Pick a folder for custom scan."""
        chosen = tk.filedialog.askdirectory(parent=self)
        if chosen:
            self._set_targets([Path(chosen)])

    def _select_file(self) -> None:
        """Pick a file for custom scan."""
        chosen = tk.filedialog.askopenfilename(parent=self)
        if chosen:
            self._set_targets([Path(chosen)])

    def _set_targets(self, targets: List[Path]) -> None:
        """Update custom targets display."""
        self._selected_targets = targets
        summary = ", ".join(str(t) for t in targets[:2])
        if len(targets) > 2:
            summary += f" (+{len(targets) - 2} more)"
        self.target_label.configure(text=summary)
        self.custom_start_btn.configure(state="normal")

    def _start_custom(self) -> None:
        """Launch a custom scan on the selected targets."""
        if self._selected_targets:
            self.app.start_custom_scan(self._selected_targets)

    # ------------------------------------------------------------------
    # Scan control
    # ------------------------------------------------------------------

    def _toggle_pause(self) -> None:
        """Pause/resume the running scan."""
        self.app.toggle_scan_pause()

    def _stop_scan(self) -> None:
        """Stop the running scan."""
        if tk.messagebox.askyesno(
            "KhokharGuard", "Stop the running scan?", parent=self
        ):
            self.app.stop_scan()

    # ------------------------------------------------------------------
    # Progress rendering (called from UI thread via app polling)
    # ------------------------------------------------------------------

    def update_progress(self, snapshot: Dict[str, object]) -> None:
        """Render a progress snapshot (UI thread only)."""
        total = int(snapshot.get("total_files", 0) or 0)
        processed = int(snapshot.get("processed", 0) or 0)
        if total > 0:
            self.progress_var.set(min(100.0, processed * 100.0 / total))
            self.status_var.set(
                f"Scanning... {processed:,} of {total:,} files")
        else:
            self.status_var.set("Collecting files...")

        self.stat_vars["files"].set(f"{int(snapshot.get('files_scanned', 0)):,}")
        self.stat_vars["dirs"].set(f"{int(snapshot.get('directories_scanned', 0)):,}")
        self.stat_vars["threats"].set(str(snapshot.get("threats_found", 0)))
        self.stat_vars["suspicious"].set(str(snapshot.get("suspicious_found", 0)))
        self.stat_vars["skipped"].set(str(snapshot.get("skipped", 0)))
        self.stat_vars["errors"].set(str(snapshot.get("errors", 0)))
        elapsed = float(snapshot.get("elapsed", 0) or 0)
        self.stat_vars["elapsed"].set(
            f"{int(elapsed // 60):02d}:{int(elapsed % 60):02d}")
        current = str(snapshot.get("current_file", "") or "-")
        if len(current) > 70:
            current = "..." + current[-67:]
        self.stat_vars["current"].set(current)

    def set_scan_running(self, running: bool) -> None:
        """Enable/disable scan control buttons."""
        state_normal = "normal" if running else "disabled"
        self.pause_btn.configure(state=state_normal, text="Pause")
        self.stop_btn.configure(state=state_normal)
        self.progress_var.set(0.0)
        if not running:
            self.status_var.set("Ready. No scan running.")

    def mark_paused(self, paused: bool) -> None:
        """Update pause button label."""
        self.pause_btn.configure(text="Resume" if paused else "Pause")

    def scan_finished(self, status: str, stats_summary: str) -> None:
        """Render final scan state."""
        self.progress_var.set(100.0 if status == "completed" else 0.0)
        self.status_var.set(f"Scan {status}. {stats_summary}")
        self.pause_btn.configure(state="disabled", text="Pause")
        self.stop_btn.configure(state="disabled")

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def add_detection(self, detection) -> None:
        """Add one detection row to the results tree (UI thread)."""
        palette = colors()
        values = (
            detection.severity.upper(),
            detection.detection_name,
            detection.path,
            detection.risk_score,
            detection.detection_method,
        )
        item = self.results_tree.insert("", "end", values=values)
        self.results_tree.see(item)

    def clear_results(self) -> None:
        """Empty the results table."""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

    def _selected_detection(self):
        """Return the Detection stored on the selected row."""
        selection = self.results_tree.selection()
        if not selection:
            return None
        return self.app.detection_for_row(self.results_tree.item(
            selection[0], "values"))

    def _quarantine_selected(self) -> None:
        """Quarantine the selected finding after confirmation."""
        detection = self._selected_detection()
        if detection is None:
            tk.messagebox.showinfo("KhokharGuard", "Select a finding first.",
                                   parent=self)
            return
        self.app.quarantine_detection_with_confirmation(detection, parent=self)
        self._refresh_after_action(detection)

    def _quarantine_all(self) -> None:
        """Quarantine all findings on this page after confirmation."""
        self.app.quarantine_all_with_confirmation(parent=self,
                                                  refresh_callback=self.clear_results)

    def _allow_selected(self) -> None:
        """Mark the selected finding as allowed by the user."""
        detection = self._selected_detection()
        if detection is None:
            tk.messagebox.showinfo("KhokharGuard", "Select a finding first.",
                                   parent=self)
            return
        self.app.allow_detection(detection, parent=self)
        self._refresh_after_action(detection)

    def _refresh_after_action(self, detection) -> None:
        """Remove handled rows from the table."""
        for item in self.results_tree.get_children():
            values = self.results_tree.item(item, "values")
            if values and str(values[2]) == detection.path:
                self.results_tree.delete(item)

    def _show_details(self) -> None:
        """Open the technical details dialog for the selected finding."""
        detection = self._selected_detection()
        if detection is None:
            tk.messagebox.showinfo("KhokharGuard", "Select a finding first.",
                                   parent=self)
            return
        self.app.show_threat_details(detection, parent=self)
