"""LocalGuard Antivirus - settings page.

All user-configurable settings (spec section 42) organised in
categories, plus exclusions management (spec section 29). Every change
is saved to settings.json immediately and visibly.
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING

import tkinter.ttk as ttk

from ui.widgets import Card, ScrollFrame, add_tooltip

if TYPE_CHECKING:  # pragma: no cover
    from ui.app import LocalGuardApp


class SettingsPage(ttk.Frame):
    """Settings and exclusions management."""

    def __init__(self, master: tk.Widget, app: "LocalGuardApp") -> None:
        super().__init__(master)
        self.app = app
        self._vars: dict = {}
        self._build()

    def _build(self) -> None:
        """Build all settings categories."""
        scroll = ScrollFrame(self)
        scroll.pack(fill="both", expand=True)
        container = scroll.inner

        pad = {"padx": 16, "pady": 8}

        # --- General ---
        general = Card(container)
        general.pack(fill="x", in_=container, **pad)
        ttk.Label(general, text="GENERAL", style="H2.TLabel").pack(
            anchor="w", pady=(0, 8))

        self._check(general, "Start LocalGuard with Windows",
                    "general.start_with_windows",
                    tooltip="Registers LocalGuard in the HKCU Run key "
                            "(visible, reversible)")
        self._check(general, "Minimize to system tray",
                    "general.minimize_to_tray")
        self._check(general, "Show notifications",
                    "general.show_notifications")

        theme_row = ttk.Frame(general, style="Card.TFrame")
        theme_row.pack(fill="x", pady=4)
        ttk.Label(theme_row, text="Theme:", style="CardDim.TLabel").pack(side="left")
        self.theme_var = tk.StringVar(
            value=str(self.app.settings.get("general.theme", "dark")))
        theme_box = ttk.Combobox(theme_row, textvariable=self.theme_var,
                                 values=["dark", "light"], state="readonly",
                                 width=10)
        theme_box.pack(side="left", padx=8)
        theme_box.bind("<<ComboboxSelected>>",
                       lambda _e: self.app.set_theme(str(self.theme_var.get())))

        # --- Protection ---
        protection = Card(container)
        protection.pack(fill="x", in_=container, **pad)
        ttk.Label(protection, text="PROTECTION", style="H2.TLabel").pack(
            anchor="w", pady=(0, 8))
        self._check(protection, "Real-time protection",
                    "protection.realtime_enabled",
                    tooltip="Watch Downloads/Desktop/Temp for new "
                            "suspicious files")
        self._check(protection, "Automatically scan USB drives",
                    "protection.usb_autoscan")
        self._check(protection, "Automatically quarantine confirmed threats",
                    "protection.auto_quarantine",
                    tooltip="Only signature-confirmed malware is quarantined "
                            "automatically; heuristics never auto-quarantine")
        self._check(protection, "Scan inside archives",
                    "protection.scan_archives",
                    tooltip="Inspect ZIP/7z/RAR/TAR contents with strict "
                            "bomb-protection limits")

        # --- Notifications ---
        notif = Card(container)
        notif.pack(fill="x", in_=container, **pad)
        ttk.Label(notif, text="NOTIFICATIONS", style="H2.TLabel").pack(
            anchor="w", pady=(0, 4))
        ttk.Label(notif,
                  text="Choose which events show a Windows notification "
                       "and how often. Security events are always recorded "
                       "in Scan History even when their notification is "
                       "off.",
                  style="CardDim.TLabel", wraplength=700,
                  justify="left").pack(anchor="w", pady=(0, 8))

        self._check(notif, "Show notifications",
                    "general.show_notifications",
                    tooltip="Master switch - turns every notification on "
                            "or off")
        for kind, label, tooltip in (
            ("usb_detected", "USB drive detected",
             "When a removable drive is inserted"),
            ("threat_detected", "Threat detected",
             "When a scan or real-time protection flags a file"),
            ("scan_complete", "Scan finished",
             "When a scan completes"),
            ("protection_disabled", "Protection paused",
             "When real-time or USB protection is paused"),
            ("update_available", "Signature update available",
             "When a signature database update is found"),
        ):
            self._check(notif, label, f"notifications.enable_{kind}",
                        tooltip=tooltip)

        limits_row = ttk.Frame(notif, style="Card.TFrame")
        limits_row.pack(fill="x", pady=(6, 2))
        ttk.Label(limits_row, text="Minimum seconds between notifications:",
                  style="CardDim.TLabel").pack(side="left")
        self._rate_vars: dict = {}
        self._rate_spinboxes: dict = {}
        for kind, label in (
            ("threat_detected", "threats"),
            ("usb_detected", "USB"),
            ("scan_complete", "scan done"),
        ):
            column = ttk.Frame(limits_row, style="Card.TFrame")
            column.pack(side="left", padx=(14, 0))
            ttk.Label(column, text=label, style="CardDim.TLabel").pack(
                anchor="w")
            var = tk.IntVar(value=int(self.app.settings.get(
                f"notifications.rate_limit_{kind}", 10)))
            self._rate_vars[kind] = var
            spin = ttk.Spinbox(column, from_=1, to=3600, width=6,
                               textvariable=var,
                               command=self._save_notification_limits)
            spin.pack(anchor="w")
            add_tooltip(spin, f"Minimum seconds between {label} "
                              "notifications")
            self._rate_spinboxes[kind] = spin
        ttk.Button(notif, text="Apply Notification Settings",
                   command=self._save_notification_limits).pack(
            anchor="w", pady=(6, 0))

        # --- Performance ---
        perf = Card(container)
        perf.pack(fill="x", in_=container, **pad)
        ttk.Label(perf, text="PERFORMANCE", style="H2.TLabel").pack(
            anchor="w", pady=(0, 8))

        threads_row = ttk.Frame(perf, style="Card.TFrame")
        threads_row.pack(fill="x", pady=4)
        ttk.Label(threads_row, text="Scan threads:", style="CardDim.TLabel").pack(
            side="left")
        self.threads_var = tk.IntVar(
            value=int(self.app.settings.get("performance.scan_threads", 4)))
        spin = ttk.Spinbox(threads_row, from_=1, to=16, width=5,
                           textvariable=self.threads_var,
                           command=self._save_performance)
        spin.pack(side="left", padx=8)

        priority_row = ttk.Frame(perf, style="Card.TFrame")
        priority_row.pack(fill="x", pady=4)
        ttk.Label(priority_row, text="Scan priority:", style="CardDim.TLabel").pack(
            side="left")
        self.priority_var = tk.StringVar(
            value=str(self.app.settings.get("performance.scan_priority",
                                            "below_normal")))
        prio_box = ttk.Combobox(priority_row, textvariable=self.priority_var,
                                values=["idle", "below_normal", "normal"],
                                state="readonly", width=14)
        prio_box.pack(side="left", padx=8)
        prio_box.bind("<<ComboboxSelected>>", lambda _e: self._save_performance())

        self._check(perf, "Cache file hashes during scans",
                    "performance.cache_hashes")
        self._check(perf, "Skip unchanged files (faster repeat scans)",
                    "performance.skip_unchanged_files")

        # --- Background service ---
        service_card = Card(container)
        service_card.pack(fill="x", in_=container, **pad)
        ttk.Label(service_card, text="BACKGROUND SERVICE",
                  style="H2.TLabel").pack(anchor="w", pady=(0, 4))
        self._service_info = ttk.Label(
            service_card,
            text="Checking...",
            style="CardDim.TLabel", wraplength=700, justify="left")
        self._service_info.pack(anchor="w", pady=(0, 6))
        self._service_row = ttk.Frame(service_card, style="Card.TFrame")
        self._service_row.pack(fill="x")
        self._service_install_btn = ttk.Button(
            service_card, text="Install Service",
            command=self._service_install)
        self._service_start_btn = ttk.Button(
            service_card, text="Start Service",
            command=self._service_start)
        self._service_stop_btn = ttk.Button(
            service_card, text="Stop Service",
            command=self._service_stop)
        self._service_uninstall_btn = ttk.Button(
            service_card, text="Remove Service", style="Danger.TButton",
            command=self._service_uninstall)
        self._service_refresh_btn = ttk.Button(
            service_card, text="Refresh Status",
            command=self._service_refresh)
        for btn in (self._service_install_btn, self._service_start_btn,
                    self._service_stop_btn, self._service_uninstall_btn,
                    self._service_refresh_btn):
            btn.pack(side="left", padx=(0, 8))
        add_tooltip(
            self._service_install_btn,
            "Registers the LocalGuard protection service with Windows "
            "(services.msc). Requires Administrator approval.")
        add_tooltip(
            self._service_start_btn,
            "Starts background real-time and USB protection that keeps "
            "running when the LocalGuard window is closed.")

        # --- Exclusions ---
        exclusions = Card(container)
        exclusions.pack(fill="x", in_=container, **pad)
        ttk.Label(exclusions, text="EXCLUSIONS", style="H2.TLabel").pack(
            anchor="w", pady=(0, 4))
        ttk.Label(exclusions,
                  text="Excluded items are never scanned or flagged. Every "
                       "exclusion is listed here - nothing is hidden.",
                  style="CardDim.TLabel", wraplength=700,
                  justify="left").pack(anchor="w", pady=(0, 8))

        columns = {"type": ("Type", 90, "w"), "value": ("Value", 380, "w"),
                   "scope": ("Scope", 70, "w")}
        self.exclusions_tree = ttk.Treeview(exclusions, columns=list(columns),
                                            show="headings", height=5)
        for col_id, (text, width, anchor) in columns.items():
            self.exclusions_tree.heading(col_id, text=text)
            self.exclusions_tree.column(col_id, width=width, anchor=anchor)
        self.exclusions_tree.pack(fill="x")

        excl_row = ttk.Frame(exclusions, style="Card.TFrame")
        excl_row.pack(fill="x", pady=(8, 0))
        ttk.Button(excl_row, text="Exclude File...",
                   command=self._exclude_file).pack(side="left", padx=(0, 8))
        ttk.Button(excl_row, text="Exclude Folder...",
                   command=self._exclude_folder).pack(side="left", padx=(0, 8))
        ttk.Button(excl_row, text="Exclude Extension...",
                   command=self._exclude_extension).pack(side="left", padx=(0, 8))
        ttk.Button(excl_row, text="Exclude Hash...",
                   command=self._exclude_hash).pack(side="left", padx=(0, 8))
        ttk.Button(excl_row, text="Remove Selected", style="Danger.TButton",
                   command=self._remove_exclusion).pack(side="left")

        # --- Privacy ---
        privacy = Card(container)
        privacy.pack(fill="x", in_=container, **pad)
        ttk.Label(privacy, text="PRIVACY", style="H2.TLabel").pack(
            anchor="w", pady=(0, 4))
        ttk.Label(privacy,
                  text="LocalGuard is local-first. Telemetry, cloud "
                       "reputation and file uploads are OFF by default and "
                       "can stay OFF forever.",
                  style="CardDim.TLabel", wraplength=700,
                  justify="left").pack(anchor="w", pady=(0, 8))
        self._check(privacy, "Anonymous telemetry (OFF by default)",
                    "privacy.telemetry")
        self._check(privacy, "Cloud reputation lookups (OFF by default)",
                    "privacy.cloud_reputation")
        self._check(privacy, "Allow file uploads (never recommended)",
                    "privacy.file_upload")

        ttk.Label(container, text="LocalGuard Antivirus 1.0.0 - "
                                  "local-first Windows malware protection",
                  style="Dim.TLabel").pack(pady=12)

        self.refresh()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check(self, master: tk.Widget, label: str, key: str,
               tooltip: str = "") -> ttk.Checkbutton:
        """Create a settings checkbox bound to a settings key."""
        var = tk.BooleanVar(value=bool(self.app.settings.get(key, False)))
        self._vars[key] = var
        box = ttk.Checkbutton(master, text=label, variable=var,
                              style="Card.TCheckbutton",
                              command=lambda: self._save_bool(key, var))
        box.pack(anchor="w", pady=2)
        if tooltip:
            add_tooltip(box, tooltip)
        return box

    def _save_bool(self, key: str, var: tk.BooleanVar) -> None:
        """Persist a boolean setting."""
        self.app.settings.set(key, bool(var.get()))
        self.app.on_setting_changed(key)

    def _save_performance(self) -> None:
        """Persist performance settings."""
        try:
            threads = max(1, min(16, int(self.threads_var.get())))
        except (tk.TclError, ValueError):
            threads = 4
        self.app.settings.set("performance.scan_threads", threads)
        self.app.settings.set("performance.scan_priority",
                              str(self.priority_var.get()))
        self.app.on_setting_changed("performance")

    # ------------------------------------------------------------------
    # Background service management
    # ------------------------------------------------------------------

    def _service_refresh(self) -> None:
        """Update the service status line and button availability."""
        try:
            from services.service_control import (
                is_service_protection_active,
                service_installed,
                service_running,
            )

            installed = service_installed()
            running = service_running()
            reachable = is_service_protection_active()
            if reachable:
                text = (
                    "Background protection: ACTIVE - real-time and USB "
                    "monitoring keep running when this window is closed. "
                    "The dashboard reflects the background state.")
            elif installed and running:
                text = (
                    "Service is RUNNING but not reporting into this "
                    "session (it runs under its own account). In-session "
                    "protection stays on.")
            elif installed:
                text = "Service installed but stopped."
            else:
                text = (
                    "No background service. Protection runs only while "
                    "this window is open (minimising to the tray keeps "
                    "it active). Installing the service keeps real-time "
                    "and USB protection running without the window - "
                    "manage it here or in services.msc.")
            self._service_info.configure(text=text)
            self._service_install_btn.state(
                ["disabled"] if installed else ["!disabled"])
            self._service_start_btn.state(
                ["disabled"] if running or not installed else ["!disabled"])
            self._service_stop_btn.state(
                ["!disabled"] if running else ["disabled"])
            self._service_uninstall_btn.state(
                ["!disabled"] if installed else ["disabled"])
        except Exception:  # noqa: BLE001
            self._service_info.configure(
                text="Service status unavailable on this system.")
            for btn in (self._service_install_btn, self._service_start_btn,
                        self._service_stop_btn, self._service_uninstall_btn):
                btn.state(["disabled"])

    def _service_run(self, action: str, busy: str) -> None:
        """Run a service lifecycle action in a worker thread."""
        def worker() -> None:
            """Execute the action off the UI thread."""
            import sys as _sys

            from services import service_control

            try:
                if action == "install":
                    service_control.install_service()
                elif action == "uninstall":
                    service_control.uninstall_service()
                elif action == "start":
                    service_control.start_service()
                elif action == "stop":
                    service_control.stop_service()
            except service_control.ServiceControlError as exc:
                self.app.ui_call(lambda: self._message(
                    f"Service {action} failed: {exc}\n\nAdministrator "
                    "privileges are required - Windows will ask for "
                    "approval.", "error"))
                return
            self.app.ui_call(self._service_refresh)

        self.app.run_background(worker, busy)

    def _service_install(self) -> None:
        """Install the Windows service."""
        self._service_run("install", "Installing service...")

    def _service_start(self) -> None:
        """Start the Windows service."""
        self._service_run("start", "Starting service...")

    def _service_stop(self) -> None:
        """Stop the Windows service."""
        self._service_run("stop", "Stopping service...")

    def _service_uninstall(self) -> None:
        """Remove the Windows service after confirmation."""
        import tkinter.messagebox as messagebox

        if messagebox.askyesno(
            "Remove Service",
            "Remove the LocalGuard background protection service?\n\n"
            "Real-time and USB protection will then run only while the "
            "LocalGuard window (or tray) is active.",
            parent=self,
        ):
            self._service_run("uninstall", "Removing service...")

    def _save_notification_limits(self) -> None:
        """Persist the notification rate-limit spinbox values."""
        for kind, var in self._rate_vars.items():
            try:
                seconds = int(var.get())
            except (tk.TclError, ValueError):
                seconds = 10
            seconds = max(1, min(3600, seconds))
            self.app.settings.set(f"notifications.rate_limit_{kind}",
                                  float(seconds))
        # Apply immediately rather than after the notify TTL.
        from utils.notify import invalidate_preferences

        invalidate_preferences()

    # ------------------------------------------------------------------
    # Exclusions
    # ------------------------------------------------------------------

    def _exclude_file(self) -> None:
        """Add a file exclusion."""
        chosen = tk.filedialog.askopenfilename(parent=self)
        if chosen:
            self.app.add_exclusion("file", chosen)
            self.refresh()

    def _exclude_folder(self) -> None:
        """Add a folder exclusion."""
        chosen = tk.filedialog.askdirectory(parent=self)
        if chosen:
            self.app.add_exclusion("folder", chosen)
            self.refresh()

    def _exclude_extension(self) -> None:
        """Add an extension exclusion via dialog."""
        answer = tk.simpledialog.askstring(
            "Exclude Extension", "Extension to exclude (e.g. log):", parent=self)
        if answer and answer.strip():
            self.app.add_exclusion("extension", answer.strip().lstrip("."))
            self.refresh()

    def _exclude_hash(self) -> None:
        """Add a SHA-256 hash exclusion via dialog."""
        answer = tk.simpledialog.askstring(
            "Exclude Hash", "SHA-256 hash to exclude:", parent=self)
        if answer and len(answer.strip()) == 64:
            self.app.add_exclusion("hash", answer.strip().lower())
            self.refresh()
        elif answer:
            tk.messagebox.showwarning("LocalGuard",
                                      "A SHA-256 hash is 64 hex characters.",
                                      parent=self)

    def _remove_exclusion(self) -> None:
        """Remove the selected exclusion (local scope only)."""
        selection = self.exclusions_tree.selection()
        if not selection:
            return
        values = self.exclusions_tree.item(selection[0], "values")
        if len(values) >= 3 and values[2] == "service":
            import tkinter.messagebox as messagebox

            messagebox.showinfo(
                "LocalGuard",
                "This exclusion is defined in the background service's "
                "own scope and is shown read-only here.",
                parent=self)
            return
        self.app.remove_exclusion_by_value(str(values[0]), str(values[1]))
        self.refresh()

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Sync checkbox vars and exclusion table from settings."""
        for key, var in self._vars.items():
            var.set(bool(self.app.settings.get(key, False)))
        for kind, var in self._rate_vars.items():
            try:
                var.set(int(float(self.app.settings.get(
                    f"notifications.rate_limit_{kind}", 10))))
            except (TypeError, ValueError):
                var.set(10)
        self._service_refresh()
        for item in self.exclusions_tree.get_children():
            self.exclusions_tree.delete(item)
        for record in self.app.list_exclusions_merged():
            # Service-scope exclusions are shown read-only with a
            # scope marker; the Remove button only acts on local rows.
            scope = ("service" if record.get("origin") == "service"
                     else "local")
            self.exclusions_tree.insert("", "end", values=(
                str(record.get("exclusion_type", "")),
                str(record.get("value", "")),
                scope,
            ))
