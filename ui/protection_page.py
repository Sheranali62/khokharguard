"""LocalGuard Antivirus - protection page.

Advanced protection surface (spec sections 22-26): startup persistence
entries, scheduled tasks, Windows services, Windows Security status,
and download-folder checks. Analysis is read-only; any removal flows
through cleanup modules with explicit confirmation.
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING, Dict, List, Optional

import tkinter.ttk as ttk

from ui.widgets import Card, add_tooltip, make_treeview

if TYPE_CHECKING:  # pragma: no cover
    from ui.app import LocalGuardApp


class ProtectionPage(ttk.Frame):
    """Startup / tasks / services / Windows Security page."""

    def __init__(self, master: tk.Widget, app: "LocalGuardApp") -> None:
        super().__init__(master)
        self.app = app
        self._startup_items: List = []
        self._task_items: List = []
        self._service_items: List = []
        self._build()

    def _build(self) -> None:
        """Construct the notebook tabs."""
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=16, pady=12)

        self.notebook = ttk.Notebook(container)
        self.notebook.pack(fill="both", expand=True)

        self._build_startup_tab()
        self._build_tasks_tab()
        self._build_services_tab()
        self._build_security_tab()

    # ------------------------------------------------------------------
    # Startup tab
    # ------------------------------------------------------------------

    def _build_startup_tab(self) -> None:
        """Startup persistence entries tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Startup Entries")

        card = Card(tab)
        card.pack(fill="both", expand=True, padx=8, pady=8)
        ttk.Label(card, text="STARTUP PERSISTENCE ENTRIES",
                  style="H2.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(card,
                  text="Programs configured to run at Windows startup. "
                       "LocalGuard flags risk indicators but never removes "
                       "entries automatically.",
                  style="CardDim.TLabel", wraplength=760,
                  justify="left").pack(anchor="w", pady=(0, 8))

        columns = {
            "type": ("Type", 110, "w"),
            "name": ("Name", 150, "w"),
            "command": ("Command / Executable", 320, "w"),
            "location": ("Location", 180, "w"),
            "severity": ("Risk", 80, "w"),
            "indicators": ("Indicators", 200, "w"),
        }
        self.startup_tree = make_treeview(card, columns, heights=9)
        self.startup_tree._scrollframe.pack(fill="both", expand=True)

        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=(8, 0))
        ttk.Button(row, text="Scan Startup Entries",
                   style="Accent.TButton",
                   command=self._scan_startup).pack(side="left", padx=(0, 8))
        ttk.Button(row, text="Remove Selected Entry...",
                   command=self._remove_startup_entry).pack(side="left")
        add_tooltip(row, "Removal always asks for confirmation and records "
                         "a restore snapshot")

    def _scan_startup(self) -> None:
        """Run startup analysis in a worker thread."""
        def worker() -> None:
            """Background analysis."""
            items = self.app.scan_startup_entries()
            self.app.ui_call(lambda: self._show_startup_items(items))

        self.app.run_background(worker, "Analyzing startup entries...")

    def _show_startup_items(self, items: List) -> None:
        """Render startup analysis results."""
        self._startup_items = items
        for row in self.startup_tree.get_children():
            self.startup_tree.delete(row)
        for index, item in enumerate(items):
            self.startup_tree.insert("", "end", iid=str(index), values=(
                str(getattr(item, "item_type", "")),
                str(getattr(item, "name", "")),
                str(getattr(item, "command", ""))[:80],
                str(getattr(item, "location", ""))[:40],
                str(getattr(item, "severity", "")).upper(),
                "; ".join(getattr(item, "indicators", []))[:90],
            ))

    def _remove_startup_entry(self) -> None:
        """Remove the selected startup entry with confirmation + snapshot."""
        selection = self.startup_tree.selection()
        if not selection:
            tk.messagebox.showinfo("LocalGuard", "Select an entry first.",
                                   parent=self)
            return
        index = int(selection[0])
        if index >= len(self._startup_items):
            return
        item = self._startup_items[index]
        self.app.remove_startup_entry_with_confirmation(item, parent=self)
        self._scan_startup()

    # ------------------------------------------------------------------
    # Scheduled tasks tab
    # ------------------------------------------------------------------

    def _build_tasks_tab(self) -> None:
        """Scheduled tasks tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Scheduled Tasks")

        card = Card(tab)
        card.pack(fill="both", expand=True, padx=8, pady=8)
        ttk.Label(card, text="SCHEDULED TASKS", style="H2.TLabel").pack(
            anchor="w", pady=(0, 4))
        ttk.Label(card,
                  text="Windows scheduled tasks. Flags are evidence-based: "
                       "temp-directory commands, script hosts, missing "
                       "executables. Unfamiliar tasks are NOT removed "
                       "automatically.",
                  style="CardDim.TLabel", wraplength=760,
                  justify="left").pack(anchor="w", pady=(0, 8))

        columns = {
            "name": ("Task Name", 180, "w"),
            "command": ("Command", 330, "w"),
            "author": ("Author", 130, "w"),
            "status": ("Status", 80, "w"),
            "flags": ("Flags", 200, "w"),
        }
        self.tasks_tree = make_treeview(card, columns, heights=9)
        self.tasks_tree._scrollframe.pack(fill="both", expand=True)

        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=(8, 0))
        ttk.Button(row, text="Scan Scheduled Tasks", style="Accent.TButton",
                   command=self._scan_tasks).pack(side="left", padx=(0, 8))
        ttk.Button(row, text="Delete Selected Task...",
                   command=self._delete_task).pack(side="left")

    def _scan_tasks(self) -> None:
        """Run scheduled task analysis in a worker thread."""
        def worker() -> None:
            """Background analysis."""
            tasks = self.app.scan_scheduled_tasks()
            self.app.ui_call(lambda: self._show_tasks(tasks))

        self.app.run_background(worker, "Analyzing scheduled tasks...")

    def _show_tasks(self, tasks: List) -> None:
        """Render task analysis results."""
        self._task_items = tasks
        for row in self.tasks_tree.get_children():
            self.tasks_tree.delete(row)
        for index, task in enumerate(tasks):
            self.tasks_tree.insert("", "end", iid=str(index), values=(
                str(getattr(task, "name", "")),
                str(getattr(task, "command", ""))[:80],
                str(getattr(task, "author", "")),
                str(getattr(task, "status", "")),
                "; ".join(getattr(task, "flags", []))[:90],
            ))

    def _delete_task(self) -> None:
        """Delete the selected task with confirmation + XML backup."""
        selection = self.tasks_tree.selection()
        if not selection:
            tk.messagebox.showinfo("LocalGuard", "Select a task first.",
                                   parent=self)
            return
        index = int(selection[0])
        if index >= len(self._task_items):
            return
        task = self._task_items[index]
        self.app.delete_task_with_confirmation(task, parent=self)

    # ------------------------------------------------------------------
    # Services tab
    # ------------------------------------------------------------------

    def _build_services_tab(self) -> None:
        """Windows services tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Services")

        card = Card(tab)
        card.pack(fill="both", expand=True, padx=8, pady=8)
        ttk.Label(card, text="WINDOWS SERVICES", style="H2.TLabel").pack(
            anchor="w", pady=(0, 4))
        ttk.Label(card,
                  text="Installed services and their binaries. LocalGuard "
                       "flags suspicious images; service removal requires "
                       "Administrator privileges and confirmation.",
                  style="CardDim.TLabel", wraplength=760,
                  justify="left").pack(anchor="w", pady=(0, 8))

        columns = {
            "name": ("Service Name", 140, "w"),
            "display": ("Display Name", 170, "w"),
            "path": ("Binary Path", 300, "w"),
            "start": ("Startup", 90, "w"),
            "status": ("Status", 80, "w"),
            "flags": ("Flags", 180, "w"),
        }
        self.services_tree = make_treeview(card, columns, heights=9)
        self.services_tree._scrollframe.pack(fill="both", expand=True)

        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=(8, 0))
        ttk.Button(row, text="Scan Services", style="Accent.TButton",
                   command=self._scan_services).pack(side="left")

    def _scan_services(self) -> None:
        """Run service analysis in a worker thread."""
        def worker() -> None:
            """Background analysis."""
            services = self.app.scan_services()
            self.app.ui_call(lambda: self._show_services(services))

        self.app.run_background(worker, "Analyzing Windows services...")

    def _show_services(self, services: List) -> None:
        """Render service analysis results."""
        self._service_items = services
        for row in self.services_tree.get_children():
            self.services_tree.delete(row)
        for index, service in enumerate(services):
            self.services_tree.insert("", "end", iid=str(index), values=(
                str(getattr(service, "name", "")),
                str(getattr(service, "display_name", "")),
                str(getattr(service, "executable_path", ""))[:80],
                str(getattr(service, "startup_type", "")),
                str(getattr(service, "status", "")),
                "; ".join(getattr(service, "flags", []))[:90],
            ))

    # ------------------------------------------------------------------
    # Windows Security tab
    # ------------------------------------------------------------------

    def _build_security_tab(self) -> None:
        """Windows Security / Defender status tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Windows Security")

        card = Card(tab)
        card.pack(fill="both", expand=True, padx=8, pady=8)
        ttk.Label(card, text="WINDOWS SECURITY STATUS", style="H2.TLabel").pack(
            anchor="w", pady=(0, 4))
        ttk.Label(card,
                  text="LocalGuard complements Windows Security. Defender is "
                       "never modified or disabled by LocalGuard.",
                  style="CardDim.TLabel", wraplength=760,
                  justify="left").pack(anchor="w", pady=(0, 8))

        self.security_rows = {}
        for label in ("Microsoft Defender", "Real-Time Protection",
                      "Engine Version", "Signature Version",
                      "Signature Age (days)", "Administrator Privileges"):
            row = StatRowCard(card, label)
            row.pack(fill="x", pady=2)
            self.security_rows[label] = row

        btn_row = ttk.Frame(card, style="Card.TFrame")
        btn_row.pack(fill="x", pady=(10, 0))
        ttk.Button(btn_row, text="Check Status",
                   command=self._refresh_security).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Open Windows Security",
                   style="Accent.TButton",
                   command=self.app.open_windows_security).pack(side="left")

    def _refresh_security(self) -> None:
        """Query and display Defender status."""
        status = self.app.defender_status(force=True)
        is_admin = self.app.is_admin()
        self.security_rows["Microsoft Defender"].set(
            "Available" if status.get("available") else "Not detected")
        self.security_rows["Real-Time Protection"].set(
            self._fmt_state(status.get("realtime_enabled")))
        self.security_rows["Engine Version"].set(
            str(status.get("engine_version") or "-"))
        self.security_rows["Signature Version"].set(
            str(status.get("signature_version") or "-"))
        self.security_rows["Signature Age (days)"].set(
            str(status.get("signature_age_days") if
                status.get("signature_age_days") is not None else "-"))
        self.security_rows["Administrator Privileges"].set(
            "YES" if is_admin else "NO")

    @staticmethod
    def _fmt_state(value: object) -> str:
        """Format tri-state boolean."""
        if value is True:
            return "ON"
        if value is False:
            return "OFF"
        return "Unknown"


class StatRowCard(ttk.Frame):
    """Label/value row on a card (local duplicate to avoid circulars)."""

    def __init__(self, master: tk.Widget, label: str) -> None:
        super().__init__(master, style="Card.TFrame")
        self.value_var = tk.StringVar(value="...")
        ttk.Label(self, text=label, style="CardDim.TLabel").pack(side="left")
        ttk.Label(self, textvariable=self.value_var,
                  style="Card.TLabel").pack(side="right")

    def set(self, value: str) -> None:
        """Update the value."""
        self.value_var.set(value)


# StatRow import kept at the bottom to avoid a circular module import.
from ui.widgets import StatRow  # noqa: E402
