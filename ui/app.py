"""LocalGuard Antivirus - main application shell.

Owns the Tk root, sidebar navigation, service wiring (engine,
database, quarantine, protection), background-task marshalling to the
UI thread, and dialog helpers used by the pages. The GUI never blocks:
all long work runs in worker threads and callbacks are marshalled via
a queue polled on the UI thread (spec sections 6, 7, 8).
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
import tkinter.simpledialog as simpledialog
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import tkinter.ttk as ttk

from engine.file_analyzer import Detection, FileAnalyzer
from engine.scan_controller import ScanController
from quarantine.quarantine_manager import QuarantineError, QuarantineManager
from utils import get_logger, paths
from utils.settings import get_settings

logger = get_logger("app")

PAGES = [
    ("dashboard", "Dashboard", "\U0001F3E0"),
    ("scan", "Quick / Full / Custom Scan", "\U0001F50D"),
    ("usb", "USB Protection", "\U0001F50C"),
    ("quarantine", "Quarantine", "\U0001F9FA"),
    ("history", "Scan History", "\U0001F4DC"),
    ("protection", "Real-Time / Security", "\U0001F6E1"),
    ("settings", "Settings", "\u2699"),
    ("about", "About", "\u2139"),
]


class LocalGuardApp:
    """Tkinter application controller."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("LocalGuard Antivirus")
        self.settings = get_settings()
        self.version = paths.version()
        # Set before any UI build: page refreshes (dashboard) read this
        # via protection_status(), and _build_ui runs before the IPC
        # probe below assigns its real value.
        self.background_protection = False

        width = int(self.settings.get("gui.window_width", 1180))
        height = int(self.settings.get("general.gui_height",
                                       self.settings.get("gui.window_height", 740)))
        self.root.geometry(f"{width}x{height}")
        self.root.minsize(980, 620)

        # --- Services ---
        from engine.hash_engine import HashEngine
        from engine.signature_engine import SignatureEngine
        from engine.yara_engine import YaraEngine
        from database.database import get_database

        self.database = get_database()
        self.signature_engine = SignatureEngine(database=self.database)
        self.yara_engine = YaraEngine()

        scan_archives = bool(self.settings.get("protection.scan_archives", True))
        max_mb = int(self.settings.get("performance.max_file_size_mb", 512))
        self.analyzer = FileAnalyzer(
            signature_engine=self.signature_engine,
            yara_engine=self.yara_engine,
            scan_archives=scan_archives,
            max_file_size=max_mb * 1024 * 1024,
        )
        self.quarantine_manager = QuarantineManager()

        self.scan_controller = ScanController(
            analyzer=self.analyzer,
            database=self.database,
            exclusions=ExclusionChecker(self.database),
            threads=int(self.settings.get("performance.scan_threads", 4)),
        )
        self.scan_controller.on_detection = self._on_scan_detection
        self.scan_controller.on_progress = self._on_scan_progress
        self.scan_controller.on_finished = self._on_scan_finished

        from protection.protection_manager import ProtectionManager

        self.protection = ProtectionManager(self.analyzer, self.scan_controller)
        self.protection.on_state_changed = self._on_protection_state_changed
        # Real-time/USB findings flow through the same pipeline as scan
        # detections: UI row, red tray shield, notification.
        self.protection.on_threat = self._on_scan_detection
        # Background USB auto-scans also drive the tray progress hint.
        self.protection.on_usb_autoscan_started = (
            lambda: self.tray.set_scanning(True) if self.tray else None)

        # --- UI state ---
        self._ui_queue: "queue.Queue[Callable[[], None]]" = queue.Queue()
        self._background_count = 0
        self._detections_by_row: Dict[tuple, Detection] = {}
        self._defender_cache: Dict[str, object] = {"ts": 0.0}
        self._last_snapshot: Dict[str, object] = {}

        self._build_ui()
        self._apply_saved_theme()
        self._poll_ui_queue()

        # System tray (spec section 43). Optional: failure is non-fatal.
        self.tray = None
        self._warning_until = 0.0  # monotonic timestamp of warning expiry
        try:
            from ui.tray import create_tray

            self.tray = create_tray(self)
            if self.tray is not None:
                # Route all notifications through the tray balloon.
                from utils.notify import set_tray_provider

                set_tray_provider(self.tray.notify)
        except Exception:  # noqa: BLE001
            logger.exception("Tray initialisation skipped")

        self.root.protocol("WM_DELETE_WINDOW", self._on_close_request)

        # Defer to a running background protection core so the two
        # never double-watch the same folders (spec section 45). The
        # check is an authenticated IPC ping, never a blind registry
        # query.
        self.background_protection = False
        self._background_findings_seq = 0
        self._findings_poll_job: Optional[str] = None
        try:
            from services.service_control import is_service_protection_active

            self.background_protection = is_service_protection_active()
        except Exception:  # noqa: BLE001
            logger.exception("Background protection probe failed")

        # First-run experience + protection start
        if not self.settings.get("general.first_run_completed", False):
            self.root.after(400, self._show_first_run)
        elif self.background_protection:
            self.protection.stop()
            logger.info("Background protection core active; in-session "
                        "monitors stay idle")
        else:
            self.protection.start()
        self._refresh_current_page()
        self._sync_tray_state()
        # Stream background findings into this session so realtime/
        # USB detections raised while the GUI was closed (or raised by
        # a service under another account) appear exactly like local
        # findings. No-op when no background core is reachable.
        if self.background_protection:
            self._poll_background_findings()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Build sidebar and page container."""
        from ui.theme import apply_theme, colors

        apply_theme(self.root, str(self.settings.get("general.theme", "dark")))

        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(1, weight=1)

        # Header bar
        header = ttk.Frame(self.root)
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        ttk.Label(header, text="\U0001F6E1  LOCALGUARD ANTIVIRUS",
                  style="Title.TLabel").pack(side="left", padx=16, pady=10)
        self.status_label = ttk.Label(header, text="", style="Dim.TLabel")
        self.status_label.pack(side="right", padx=16)

        # Sidebar
        sidebar = ttk.Frame(self.root, width=220)
        sidebar.grid(row=1, column=0, sticky="ns", padx=(0, 4))
        sidebar.grid_propagate(False)

        self._nav_buttons: Dict[str, ttk.Button] = {}
        for key, label, icon in PAGES:
            btn = ttk.Button(sidebar, text=f" {icon}  {label}",
                             style="TButton",
                             command=lambda k=key: self.show_page(k))
            btn.pack(fill="x", pady=2, padx=8)
            self._nav_buttons[key] = btn

        # Page container
        self.page_container = ttk.Frame(self.root)
        self.page_container.grid(row=1, column=1, sticky="nsew", padx=(0, 8))

        self.pages: Dict[str, ttk.Frame] = {}
        from ui.about_page import AboutPage
        from ui.dashboard import DashboardPage
        from ui.history_page import HistoryPage
        from ui.protection_page import ProtectionPage
        from ui.quarantine_page import QuarantinePage
        from ui.scan_page import ScanPage
        from ui.settings_page import SettingsPage
        from ui.usb_page import USBPage

        page_classes = {
            "dashboard": DashboardPage,
            "scan": ScanPage,
            "usb": USBPage,
            "quarantine": QuarantinePage,
            "history": HistoryPage,
            "protection": ProtectionPage,
            "settings": SettingsPage,
            "about": AboutPage,
        }
        for key, page_class in page_classes.items():
            self.pages[key] = page_class(self.page_container, self)

        self.show_page("dashboard")

    def show_page(self, key: str) -> None:
        """Switch to the named page and refresh it."""
        page = self.pages[key]
        page.tkraise()
        if hasattr(page, "refresh"):
            try:
                page.refresh()
            except Exception:  # noqa: BLE001
                logger.exception("Page refresh failed for %s", key)
        for page_key, button in self._nav_buttons.items():
            button.state(["active"] if page_key == key else ["!active"])

    def _on_protection_state_changed(self) -> None:
        """Hook for protection pause/resume; refresh tray + UI."""
        self._sync_tray_state()

    # ------------------------------------------------------------------
    # Protection pause/resume (background-aware)
    # ------------------------------------------------------------------

    def toggle_pause_protection(self) -> None:
        """Pause/resume protection - locally or on the background core.

        One entry point for the tray and pages so both surfaces stay
        consistent regardless of which layer is doing the monitoring.
        """
        paused = bool(self.protection_status().get("paused"))
        if self.background_protection:
            from services.service_control import (
                ServiceControlError,
                send_command,
            )

            try:
                send_command("resume" if paused else "pause")
            except ServiceControlError as exc:
                logger.error("Background pause/resume failed: %s", exc)
        elif paused:
            self.protection.resume_protection()
            self.database.add_event("protection_enabled",
                                    "Protection resumed")
        else:
            self.protection.pause_protection()
            self.database.add_event("protection_disabled",
                                    "Protection paused",
                                    severity="warning")
        self._sync_tray_state()

    def _sync_tray_state(self) -> None:
        """Push the current security state to the tray icon."""
        if self.tray is not None:
            try:
                self.tray.update_state()
            except Exception:  # noqa: BLE001
                logger.debug("Tray state sync failed", exc_info=True)

    # ------------------------------------------------------------------
    # Tray warning state (red shield while findings await review)
    # ------------------------------------------------------------------

    def tray_warning_active(self) -> bool:
        """True while recent findings await user review (tray warning)."""
        import time

        try:
            return time.monotonic() < self._warning_until
        except Exception:  # noqa: BLE001
            return False

    def tray_scan_progress(self) -> Optional[int]:
        """Files processed so far while a scan runs (tray tooltip)."""
        stats = self.scan_controller.stats
        if stats is None or not self.scan_controller.running:
            return None
        return int(getattr(stats, "files_scanned", 0))

    def _on_scan_detection(self, detection: Detection) -> None:
        """Queue detection row + notification + tray warning state.

        Handles findings from every source (scan worker threads,
        real-time/USB monitors via ``protection.on_threat``, and the
        background-service stream) so all detections behave exactly
        like scan findings.
        """
        import time

        # Red tray shield for 5 minutes after the latest finding.
        self._warning_until = time.monotonic() + 300.0

        def render() -> None:
            """Render on UI thread."""
            self._detections_by_row[self._row_key(detection)] = detection
            scan_page = self.pages["scan"]
            if hasattr(scan_page, "add_detection"):
                scan_page.add_detection(detection)
            if hasattr(self.pages["dashboard"], "refresh"):
                self.pages["dashboard"].refresh()

        self.ui_call(render)
        self._sync_tray_state()
        from utils.notify import notify

        notify("threat_detected", "LocalGuard - Threat Detected",
               f"{detection.detection_name}: {Path(detection.path).name}")

    # ------------------------------------------------------------------
    # Background findings streaming (service -> GUI)
    # ------------------------------------------------------------------

    _FINDINGS_POLL_INTERVAL_MS = 10_000

    def _poll_background_findings(self) -> None:
        """Fetch new background findings on a worker thread.

        A UI-thread timer schedules the fetch; the (blocking) IPC call
        runs off-thread so the GUI never stalls, and results re-enter
        the standard detection pipeline. The loop self-terminates when
        the window closes or the background core disappears.
        """
        if not self.background_protection:
            return

        def worker() -> None:
            """IPC fetch off the UI thread."""
            from services.service_control import ServiceControlError
            from services.windows_service import ServiceIPCClient

            if self.root is None:
                return
            try:
                info = ServiceIPCClient.from_discovery()
                if info is None:
                    raise ServiceControlError("token file gone")
                response = info.call("recent_findings", {
                    "since_seq": self._background_findings_seq,
                }, timeout=4.0)
            except Exception:  # noqa: BLE001 - service gone: stop polling
                self.background_protection = False
                return

            findings = response.get("findings", [])
            if isinstance(response.get("last_seq"), int):
                self._background_findings_seq = response["last_seq"]
            for entry in findings:
                if not isinstance(entry, dict):
                    continue
                data = entry.get("detection")
                if not isinstance(data, dict):
                    continue
                try:
                    detection = Detection(**{
                        key: value for key, value in data.items()
                        if key in Detection.__dataclass_fields__
                    })
                except TypeError:
                    logger.debug("Skipping malformed streamed finding")
                    continue
                self.ui_call(
                    lambda d=detection: self._on_scan_detection(d))
            if findings:
                logger.info("Streamed %d background finding(s)", len(findings))

        def schedule() -> None:
            """Run one fetch, then reschedule while alive."""
            self.run_background(worker, "Syncing background findings...")
            self._findings_poll_job = self.root.after(
                self._FINDINGS_POLL_INTERVAL_MS,
                self._poll_background_findings)

        try:
            schedule()
        except tk.TclError:
            self._findings_poll_job = None

    def _cancel_findings_poll(self) -> None:
        """Stop the background findings poller (window close)."""
        if self._findings_poll_job is not None:
            try:
                self.root.after_cancel(self._findings_poll_job)
            except tk.TclError:
                pass
            self._findings_poll_job = None

    # ------------------------------------------------------------------
    # Window / lifecycle control (used by pages and the tray)
    # ------------------------------------------------------------------

    def show_window(self) -> None:
        """Un-minimize, deiconify, and focus the main window."""
        try:
            self.root.after(0, lambda: (
                self.root.deiconify(),
                self.root.lift(),
                self.root.focus_force(),
            ))
        except tk.TclError:
            pass

    def minimize_to_tray(self) -> None:
        """Hide the window, leaving the tray icon in charge."""
        if self.tray is not None:
            self.root.withdraw()
        else:
            self.root.iconify()

    def exit_application(self) -> None:
        """Fully exit (tray Exit command)."""
        self._on_close()

    def notify_tray(self, message: str, title: str) -> bool:
        """Show a tray balloon directly (user-initiated, bypasses rates)."""
        if self.tray is not None:
            try:
                return self.tray.notify(message, title)
            except Exception:  # noqa: BLE001
                logger.debug("Tray balloon failed", exc_info=True)
        return False

    def _on_close_request(self) -> None:
        """Close button: minimize to tray when configured, else exit."""
        if bool(self.settings.get("general.minimize_to_tray", True)) \
                and self.tray is not None:
            self.minimize_to_tray()
        else:
            self._on_close()

    def _refresh_current_page(self) -> None:
        """Refresh whichever page is on top."""
        for key, page in self.pages.items():
            if page.winfo_ismapped():
                if hasattr(page, "refresh"):
                    try:
                        page.refresh()
                    except Exception:  # noqa: BLE001
                        pass
                break

    # ------------------------------------------------------------------
    # UI-thread marshalling
    # ------------------------------------------------------------------

    def ui_call(self, func: Callable[[], None]) -> None:
        """Schedule *func* to run on the UI thread."""
        self._ui_queue.put(func)

    def _poll_ui_queue(self) -> None:
        """Drain queued UI callbacks (runs every 100 ms)."""
        try:
            while True:
                func = self._ui_queue.get_nowait()
                try:
                    func()
                except Exception:  # noqa: BLE001
                    logger.exception("UI callback failed")
        except queue.Empty:
            pass
        self.root.after(100, self._poll_ui_queue)

    def run_background(self, worker: Callable[[], None], busy_text: str) -> None:
        """Run a worker in a daemon thread with a busy status."""
        self._background_count += 1
        self.status_label.configure(text=busy_text)

        def wrapper() -> None:
            """Execute worker then signal completion."""
            try:
                worker()
            except Exception:  # noqa: BLE001
                logger.exception("Background task failed")
            finally:
                self._background_count -= 1
                if self._background_count <= 0:
                    self.ui_call(lambda: self.status_label.configure(text=""))

        threading.Thread(target=wrapper, daemon=True,
                         name="localguard-bg").start()

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _apply_saved_theme(self) -> None:
        """Re-apply theme on widget creation completion."""
        self.root.after(
            50, lambda: __import__("ui.theme", fromlist=["apply_theme"]).apply_theme(
                self.root, str(self.settings.get("general.theme", "dark"))
            )
        )

    def set_theme(self, name: str) -> None:
        """Switch dark/light theme live."""
        from ui.theme import apply_theme

        apply_theme(self.root, name)
        self.settings.set("general.theme", name)

    # ------------------------------------------------------------------
    # Scan actions (called by pages)
    # ------------------------------------------------------------------

    def start_quick_scan(self) -> None:
        """Launch quick scan over common infection locations."""
        targets = self._quick_scan_targets()
        self.show_page("scan")
        self._begin_scan(targets, "quick", deep_extensions_only=True)

    def start_full_scan(self) -> None:
        """Launch full system scan over local drives."""
        from utils.windows_utils import get_fixed_and_removable_drives

        drives = [
            Path(str(d["mountpoint"]))
            for d in get_fixed_and_removable_drives()
            if d.get("drive_type") == "fixed"
        ]
        if not drives:
            self._message("No local drives detected.", "info")
            return
        self.show_page("scan")
        self._begin_scan(drives, "full", deep_extensions_only=False)

    def start_custom_scan(self, targets: List[Path]) -> None:
        """Launch custom scan on user-selected targets."""
        self._begin_scan(targets, "custom", deep_extensions_only=False)

    def start_usb_scan(self, drive_letter: str) -> None:
        """Scan a removable drive."""
        self.show_page("scan")
        self._begin_scan([Path(drive_letter)], "usb", deep_extensions_only=True)

    def show_usb_page(self) -> None:
        """Navigate to the USB page."""
        self.show_page("usb")

    def show_scan_page(self) -> None:
        """Navigate to the scan page."""
        self.show_page("scan")

    def show_history_page(self) -> None:
        """Navigate to the history page."""
        self.show_page("history")

    def _begin_scan(self, targets: List[Path], scan_type: str,
                    deep_extensions_only: bool) -> None:
        """Common scan start with UI reset."""
        if self.scan_controller.running:
            self._message("A scan is already running.", "warning")
            return

        scan_page = self.pages["scan"]
        if hasattr(scan_page, "clear_results"):
            scan_page.clear_results()
        if hasattr(scan_page, "set_scan_running"):
            scan_page.set_scan_running(True)

        self._detections_by_row.clear()
        self.scan_controller.start(
            targets, scan_type=scan_type,
            deep_extensions_only=deep_extensions_only,
        )
        # Tray progress hint while the scan runs (spec section 43).
        if self.tray is not None:
            try:
                self.tray.set_scanning(True)
            except Exception:  # noqa: BLE001
                logger.debug("Tray scan hint failed", exc_info=True)

    def _quick_scan_targets(self) -> List[Path]:
        """Resolve quick-scan locations from environment (no hardcoded
        usernames)."""
        targets: List[Path] = []
        userprofile = Path(os_environ("USERPROFILE"))
        appdata_local = os_environ("LOCALAPPDATA") or str(userprofile / "AppData" / "Local")
        appdata_roaming = os_environ("APPDATA") or str(userprofile / "AppData" / "Roaming")
        programdata = os_environ("PROGRAMDATA") or r"C:\ProgramData"

        candidates = [
            userprofile / "Downloads", userprofile / "Desktop",
            Path(appdata_local) / "Temp",
            Path(appdata_roaming) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp",
            Path(appdata_local) / "Google" / "Chrome" / "User Data" / "Default",
            Path(appdata_local) / "Microsoft" / "Edge" / "User Data" / "Default",
        ]
        for candidate in candidates:
            if candidate.is_dir():
                targets.append(candidate)

        # Recently modified executables in user profile (bounded depth).
        try:
            import time

            now = time.time()
            for entry in (userprofile / "Downloads").glob("*"):
                try:
                    if entry.is_file() and now - entry.stat().st_mtime < 7 * 86400:
                        targets.append(entry)
                    elif entry.is_dir():
                        for sub in list(entry.glob("*"))[:50]:
                            if sub.is_file() and now - sub.stat().st_mtime < 7 * 86400:
                                targets.append(sub)
                except OSError:
                    continue
        except OSError:
            pass
        return targets

    # ------------------------------------------------------------------
    # Scan callbacks (worker thread -> ui_call)
    # ------------------------------------------------------------------

    def _on_scan_progress(self, snapshot: Dict[str, object]) -> None:
        """Queue progress rendering."""
        self._last_snapshot = dict(snapshot)

        def render() -> None:
            """Render on UI thread."""
            scan_page = self.pages["scan"]
            if hasattr(scan_page, "update_progress"):
                scan_page.update_progress(snapshot)

        self.ui_call(render)

    def _on_scan_finished(self, status: str) -> None:
        """Queue completion rendering."""
        stats = self.scan_controller.stats
        findings = 0
        if stats is not None:
            findings = stats.threats_found + stats.suspicious_found

        # End the tray progress hint and restore the correct state
        # icon. A clean scan also clears any stale warning shield.
        if self.tray is not None:
            try:
                self.tray.set_scanning(False)
            except Exception:  # noqa: BLE001
                logger.debug("Tray scan hint stop failed", exc_info=True)
        if findings == 0:
            import time

            self._warning_until = time.monotonic()

        def render() -> None:
            """Render on UI thread."""
            summary = ""
            if stats is not None:
                summary = (
                    f"Files scanned: {stats.files_scanned:,} - "
                    f"Threats: {stats.threats_found} - "
                    f"Suspicious: {stats.suspicious_found} - "
                    f"Skipped: {stats.skipped} - Errors: {stats.errors}"
                )
            scan_page = self.pages["scan"]
            if hasattr(scan_page, "scan_finished"):
                scan_page.scan_finished(status, summary)
            if hasattr(self.pages["dashboard"], "refresh"):
                self.pages["dashboard"].refresh()
            if hasattr(self.pages["history"], "refresh"):
                self.pages["history"].refresh()
            from utils.notify import notify

            if status == "completed":
                notify("scan_complete", "LocalGuard - Scan Complete", summary or "")

        self.ui_call(render)
        self._sync_tray_state()

    def toggle_scan_pause(self) -> None:
        """Pause/resume the active scan and update UI."""
        controller = self.scan_controller
        if controller.state.paused:
            controller.resume()
            self.pages["scan"].mark_paused(False) if hasattr(
                self.pages["scan"], "mark_paused") else None
        else:
            controller.pause()
            if hasattr(self.pages["scan"], "mark_paused"):
                self.pages["scan"].mark_paused(True)

    def stop_scan(self) -> None:
        """Stop the running scan."""
        self.scan_controller.stop()

    def detection_for_row(self, values) -> Optional[Detection]:
        """Map a results-table row back to its Detection."""
        if not values or len(values) < 3:
            return None
        return self._detections_by_row.get((str(values[0]), str(values[1]),
                                            str(values[2])))

    @staticmethod
    def _row_key(detection: Detection) -> tuple:
        """Row identity key for detections."""
        return (detection.severity.upper(), detection.detection_name, detection.path)

    # ------------------------------------------------------------------
    # Quarantine actions
    # ------------------------------------------------------------------

    def quarantine_detection_with_confirmation(self, detection: Detection,
                                               parent=None) -> None:
        """Ask, then quarantine one file."""
        import tkinter.messagebox as messagebox

        if not messagebox.askyesno(
            "Confirm Quarantine",
            f"Quarantine '{Path(detection.path).name}'?\n\n"
            f"Detection: {detection.detection_name}\n"
            f"Severity: {detection.severity}\n\n"
            "The file is moved to an isolated vault and can be restored.",
            parent=parent,
        ):
            return
        self.run_background(
            lambda: self._quarantine_worker(detection),
            "Quarantining...",
        )

    def _quarantine_worker(self, detection: Detection) -> None:
        """Quarantine execution in background."""
        try:
            self.quarantine_manager.quarantine_detection(detection)
            self.ui_call(lambda: self._message(
                "File quarantined successfully.", "info"))
        except QuarantineError as exc:
            self.ui_call(lambda: self._message(
                f"Quarantine failed: {exc}", "error"))

    def quarantine_all_with_confirmation(self, parent=None,
                                         refresh_callback=None) -> None:
        """Quarantine every current finding after confirmation."""
        import tkinter.messagebox as messagebox

        detections = list(self._detections_by_row.values())
        if not detections:
            self._message("No findings to quarantine.", "info")
            return
        if not messagebox.askyesno(
            "Confirm Quarantine All",
            f"Quarantine all {len(detections)} finding(s)?",
            parent=parent,
        ):
            return

        def worker() -> None:
            """Quarantine all in background."""
            ok, failed = 0, 0
            for detection in detections:
                try:
                    if Path(detection.path).exists():
                        self.quarantine_manager.quarantine_detection(detection)
                        ok += 1
                except QuarantineError:
                    failed += 1
            self.ui_call(lambda: self._message(
                f"Quarantined {ok} file(s)"
                + (f", {failed} failed" if failed else ""), "info"))
            if refresh_callback is not None:
                self.ui_call(refresh_callback)

        self.run_background(worker, "Quarantining...")

    def allow_detection(self, detection: Detection, parent=None) -> None:
        """Mark a detection as allowed by the user."""
        try:
            self.database.add_event(
                "threat_allowed",
                f"User allowed {detection.detection_name} at {detection.path}",
                severity="warning")
            self.database.add_threat({
                "file_path": detection.path,
                "sha256": detection.sha256,
                "file_size": detection.file_size,
                "detection_name": detection.detection_name,
                "detection_type": detection.detection_method,
                "severity": detection.severity,
                "confidence": detection.confidence,
                "risk_score": detection.risk_score,
                "reason": detection.reason,
                "recommended_action": "Allowed by user",
                "status": "allowed",
                "source": "scan",
            })
            self._message("File marked as allowed. It will still be "
                          "re-flagged in future scans unless excluded.",
                          "info")
        except Exception:  # noqa: BLE001
            logger.exception("Allow action failed")

    # ------------------------------------------------------------------
    # Quarantine page support
    # ------------------------------------------------------------------

    def list_quarantine_records(self) -> List[Dict[str, Any]]:
        """Active quarantine records, merged with the service's.

        Service rows are marked ``origin="service"``; their vault
        paths live on the service's filesystem, so Restore/Details
        actions stay local-only (a service row shows the detection
        but no action buttons - enforced by the page via the flag).
        """
        local = self.database.list_quarantine(active_only=True)
        remote = self._remote_history().get("quarantined", [])
        if not remote:
            return local
        merged = [dict(row) for row in local]
        for row in remote:
            entry = dict(row)
            entry["origin"] = "service"
            merged.append(entry)
        return merged

    def quarantine_record_for_row(self, values) -> Optional[Dict[str, Any]]:
        """Map a quarantine table row back to its DB record.

        Local rows resolve to their database record. Rows contributed
        by the background service resolve to the merged service record
        flagged ``origin="service"`` so the quarantine page can keep
        Restore/Delete disabled for them (their vault files live on
        the service's filesystem, not this session's).
        """
        if not values or len(values) < 2:
            return None
        for record in self.database.list_quarantine(active_only=True):
            if (str(record.get("detection_name", "")) == str(values[0])
                    and str(record.get("original_path", "")) == str(values[1])):
                return record
        for record in self.list_quarantine_records():
            if record.get("origin") != "service":
                continue
            name = str(record.get("detection_name", ""))
            # The page marks service rows with a "[service]" suffix.
            if str(values[0]).removesuffix("  [service]") == name \
                    and str(record.get("original_path", "")) == str(values[1]):
                return record
        return None

    def restore_quarantined(self, quarantine_id: int, parent=None) -> None:
        """Restore with explicit user confirmation (already given)."""
        def worker() -> None:
            """Restore in background."""
            try:
                from quarantine.restore_manager import RestoreManager

                RestoreManager(self.quarantine_manager).restore_quarantined(
                    quarantine_id, user_confirmed=True)
                self.ui_call(lambda: self._message("File restored.", "info"))
                self.ui_call(lambda: self.pages["quarantine"].refresh())
            except QuarantineError as exc:
                self.ui_call(lambda: self._message(
                    f"Restore failed: {exc}", "error"))

        self.run_background(worker, "Restoring...")

    def delete_quarantined(self, quarantine_id: int, parent=None) -> None:
        """Permanently delete a quarantined file (confirmation given)."""
        def worker() -> None:
            """Delete in background."""
            try:
                self.quarantine_manager.delete_permanently(
                    quarantine_id, user_confirmed=True)
                self.ui_call(lambda: self._message("File permanently deleted.",
                                                   "info"))
            except QuarantineError as exc:
                self.ui_call(lambda: self._message(
                    f"Delete failed: {exc}", "error"))

        self.run_background(worker, "Deleting...")

    def service_quarantine_action(self, quarantine_id: int, action: str,
                                  parent=None) -> None:
        """Restore/delete a service-quarantined item over authenticated IPC.

        Called only after the user confirmed in the GUI; the confirmation
        flag travels with the authenticated request and the service
        re-checks it before touching the vault.
        """
        past_tense = "restored" if action == "restore" else "permanently deleted"

        def worker() -> None:
            """IPC round-trip off the UI thread."""
            from services.windows_service import ServiceIPCClient

            try:
                client = ServiceIPCClient.from_discovery()
                if client is None:
                    raise RuntimeError("background service is not running")
                response = client.call(
                    f"quarantine_{action}",
                    {"quarantine_id": quarantine_id, "user_confirmed": True},
                    timeout=10.0,
                )
            except Exception as exc:  # noqa: BLE001 - surfaced to the user
                message = str(exc)
                self.ui_call(lambda: self._message(
                    f"Service {action} failed: {message}", "error"))
                return
            if response.get("error"):
                error = str(response["error"])
                self.ui_call(lambda: self._message(
                    f"Service {action} failed: {error}", "error"))
                return
            self.ui_call(lambda: self._message(
                f"File {past_tense} by the background service.", "info"))
            self.ui_call(self.refresh_merged_views)

        self.run_background(worker, f"{action.title()}ing via service...")

    def refresh_merged_views(self) -> None:
        """Refresh pages that blend service data into local rows."""
        for name in ("quarantine", "history"):
            page = self.pages.get(name)
            refresh = getattr(page, "refresh", None)
            if callable(refresh):
                try:
                    refresh()
                except Exception:  # noqa: BLE001
                    logger.exception("Refresh of %s page failed", name)

    def show_quarantine_details(self, record: Dict[str, Any], parent=None) -> None:
        """Show metadata for a quarantine record."""
        import tkinter.messagebox as messagebox

        details = "\n".join([
            f"Threat: {record.get('detection_name')}",
            f"Original location: {record.get('original_path')}",
            f"SHA-256: {record.get('sha256')}",
            f"Severity: {record.get('severity')}",
            f"Detection type: {record.get('detection_type')}",
            f"Quarantined: {record.get('quarantine_date')}",
            f"File size: {record.get('file_size')} bytes",
        ])
        messagebox.showinfo("Quarantine Details", details, parent=parent)

    # ------------------------------------------------------------------
    # History / reports
    # ------------------------------------------------------------------

    def list_scans(self) -> List[Dict[str, Any]]:
        """Recent scans, merged with the background service's history.

        When a background core is protecting (possibly under another
        account, with its own database), its scan rows are pulled over
        authenticated IPC and shown alongside local rows, marked
        ``origin="service"``. Failures fall back to local data only.
        """
        local = self.database.list_scans()
        merged: Dict[int, Dict[str, Any]] = {}
        for row in local:
            merged[id(row)] = dict(row)
        remote = self._remote_history().get("scans", [])
        for row in remote:
            entry = dict(row)
            entry["scan_id"] = f"svc-{entry.get('scan_id', '?')}"
            entry["origin"] = "service"
            merged[id(entry)] = entry
        rows = sorted(
            merged.values(),
            key=lambda r: str(r.get("start_time", "")),
            reverse=True)
        return rows[:200]

    def _remote_history(self) -> Dict[str, Any]:
        """Cached service-history snapshot (empty when unavailable).

        Cached for 30 seconds so page refreshes never hammer the IPC
        channel; the cache also degrades gracefully when the service
        stops answering.
        """
        import time

        now = time.monotonic()
        if not self.background_protection:
            return {}
        cached = getattr(self, "_remote_history_cache", None)
        if cached is not None and now - cached[0] < 30.0:
            return cached[1]
        snapshot: Dict[str, Any] = {"scans": [], "threats": []}
        try:
            from services.service_control import send_command

            snapshot = send_command("get_history", {
                "scans_limit": 100, "threats_limit": 100,
            })
            self._remote_history_cache = (now, snapshot)
        except Exception:  # noqa: BLE001 - service may have just stopped
            logger.debug("Service history fetch failed", exc_info=True)
            self._remote_history_cache = (now, snapshot)
        return snapshot

    def recent_events(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Recent security events."""
        return self.database.list_events(limit=limit)

    def threat_counts(self) -> Dict[str, int]:
        """Threat status counts, merged with the background service's."""
        counts = self.database.threat_counts()
        remote = self._remote_history().get("threats", [])
        for row in remote:
            key = str(row.get("status", "open"))
            if key in ("open", "quarantined", "allowed"):
                counts[key] = counts.get(key, 0) + 1
            counts["total"] = counts.get("total", 0) + 1
        return counts

    def quarantine_count(self) -> int:
        """Active quarantine count (local + service)."""
        remote = self._remote_history().get("quarantined", [])
        return self.database.quarantine_count() + len(remote)

    def list_exclusions_merged(self) -> List[Dict[str, Any]]:
        """All exclusions: local (editable) plus service mirror.

        Service-scope exclusions are shown read-only (``origin=
        "service"``) so the user sees the complete effective set;
        editing them is a future service-side command.
        """
        local = self.list_exclusions()
        remote = self._remote_history().get("exclusions", [])
        if not remote:
            return local
        merged = [dict(row) for row in local]
        local_keys = {
            (str(r.get("exclusion_type")), str(r.get("value")))
            for r in local
        }
        for row in remote:
            key = (str(row.get("exclusion_type")), str(row.get("value")))
            if key in local_keys:
                continue  # same exclusion configured in both scopes
            entry = dict(row)
            entry["origin"] = "service"
            merged.append(entry)
        return merged

    def total_scans(self) -> int:
        """Number of recorded scans."""
        rows = self.database.query(
            "SELECT COUNT(*) AS n FROM scan_history")
        return int(rows[0]["n"]) if rows else 0

    def last_scan_summary(self) -> str:
        """Human-readable last-scan summary (local or service)."""
        candidates: List[Dict[str, Any]] = list(self.database.list_scans(1))
        remote = self._remote_history().get("scans", [])
        if remote:
            candidates.extend(remote[:1])
        best = max(
            candidates,
            key=lambda s: str(s.get("end_time") or s.get("start_time") or ""),
            default=None)
        if best is None:
            return "Never"
        origin = " (service)" if best.get("origin") == "service" else ""
        return (f"{best.get('scan_type', 'scan')} - "
                f"{best.get('end_time', '')}{origin}")

    def show_scan_results_dialog(self, scan_id: int, parent=None) -> None:
        """Open a results window for a historical scan."""
        results = self.database.results_for_scan(scan_id)
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Scan #{scan_id} Results - LocalGuard")
        dialog.geometry("900x500")
        dialog.transient(self.root)

        columns = {
            "severity": ("Severity", 80, "w"),
            "name": ("Detection", 160, "w"),
            "path": ("File", 380, "w"),
            "score": ("Risk", 50, "e"),
            "action": ("Action", 120, "w"),
        }
        tree = ttk.Treeview(dialog, columns=list(columns), show="headings")
        for col_id, (text, width, anchor) in columns.items():
            tree.heading(col_id, text=text)
            tree.column(col_id, width=width, anchor=anchor)
        vsb = ttk.Scrollbar(dialog, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
        vsb.pack(side="right", fill="y", pady=8)
        for result in results:
            tree.insert("", "end", values=(
                str(result.get("severity", "")).upper(),
                str(result.get("detection_name", "")),
                str(result.get("file_path", "")),
                str(result.get("risk_score", "")),
                str(result.get("action_taken", "")),
            ))

    def export_scan_report(self, scan_id: int, fmt: str, target: str) -> None:
        """Export a scan report in the chosen format."""
        try:
            from services.reporting import export_report

            path = export_report(scan_id, fmt, Path(target))
            self._message(f"Report exported to {path}", "info")
        except Exception as exc:  # noqa: BLE001
            self._message(f"Export failed: {exc}", "error")

    def delete_scan_record(self, scan_id: int) -> None:
        """Delete one scan record."""
        self.database.delete_scan(scan_id)

    def clear_scan_history(self) -> None:
        """Delete all scan history."""
        self.database.clear_scan_history()

    # ------------------------------------------------------------------
    # Protection page support
    # ------------------------------------------------------------------

    def scan_startup_entries(self) -> List[Any]:
        """Analyze startup persistence (worker thread context)."""
        from protection.startup_monitor import StartupMonitor

        return StartupMonitor().scan()

    def remove_startup_entry_with_confirmation(self, item, parent=None) -> None:
        """Remove a startup entry with confirmation and snapshot."""
        import tkinter.messagebox as messagebox

        location = str(getattr(item, "location", ""))
        name = str(getattr(item, "name", ""))
        if not messagebox.askyesno(
            "Confirm Removal",
            f"Remove startup entry '{name}'?\n\nA restore snapshot is "
            "saved and recovery is possible via scan history.",
            parent=parent,
        ):
            return
        if str(getattr(item, "item_type", "")) == "registry_run":
            hive = str(getattr(item, "hive", "HKCU"))
            key_path = location.split("\\", 1)[-1] if "\\" in location else location
            def worker() -> None:
                """Registry removal in background."""
                from cleanup.startup_cleanup import remove_registry_value

                ok = remove_registry_value(hive, key_path, name,
                                           user_confirmed=True)
                self.ui_call(lambda: self._message(
                    "Entry removed." if ok else
                    "Removal failed (Administrator privileges may be "
                    "required for HKLM entries).", "info" if ok else "error"))
            self.run_background(worker, "Removing startup entry...")
        else:
            def worker() -> None:
                """File quarantine in background."""
                from cleanup.startup_cleanup import remove_startup_file

                ok = remove_startup_file(str(getattr(item, "command", "")),
                                         user_confirmed=True)
                self.ui_call(lambda: self._message(
                    "Entry quarantined." if ok else "Removal failed.",
                    "info" if ok else "error"))
            self.run_background(worker, "Removing startup entry...")

    def scan_scheduled_tasks(self) -> List[Any]:
        """Analyze scheduled tasks (worker thread context)."""
        from protection.scheduled_task_monitor import ScheduledTaskMonitor

        return ScheduledTaskMonitor().scan()

    def delete_task_with_confirmation(self, task, parent=None) -> None:
        """Delete a scheduled task with XML backup snapshot."""
        import tkinter.messagebox as messagebox

        name = str(getattr(task, "name", ""))
        if not messagebox.askyesno(
            "Confirm Task Deletion",
            f"Delete scheduled task '{name}'?\n\nAn XML backup is saved "
            "for recovery.",
            parent=parent,
        ):
            return
        def worker() -> None:
            """Deletion in background."""
            from cleanup.scheduled_task_cleanup import delete_task

            ok = delete_task(name, user_confirmed=True)
            self.ui_call(lambda: self._message(
                "Task deleted." if ok else
                "Deletion failed (Administrator privileges may be required).",
                "info" if ok else "error"))
        self.run_background(worker, "Deleting task...")

    def scan_services(self) -> List[Any]:
        """Analyze Windows services (worker thread context)."""
        from protection.service_monitor import ServiceMonitor

        return ServiceMonitor().scan()

    def open_windows_security(self) -> None:
        """Launch the Windows Security app."""
        from utils.windows_utils import open_windows_security

        open_windows_security()

    def protection_status(self) -> Dict[str, object]:
        """Protection manager status snapshot (merged with background)."""
        status = dict(self.protection.status())
        if self.background_protection:
            # Reflect the authoritative background state in the UI.
            try:
                from services.service_control import send_command

                remote = send_command("status")
                protection = remote.get("protection", {})
                status["realtime_enabled"] = protection.get(
                    "realtime_enabled", status.get("realtime_enabled"))
                status["usb_monitoring"] = protection.get(
                    "usb_monitoring", status.get("usb_monitoring"))
                status["paused"] = remote.get("paused",
                                              status.get("paused"))
                status["provided_by"] = "service"
            except Exception:  # noqa: BLE001 - fall back to local truth
                logger.debug("Background status query failed", exc_info=True)
                self.background_protection = False
        return status

    def defender_status(self, force: bool = False) -> Dict[str, object]:
        """Cached Defender status (queried at most every 5 min)."""
        import time

        now = time.monotonic()
        if force or now - float(self._defender_cache.get("ts", 0.0)) > 300:
            from utils.windows_utils import get_defender_status

            self._defender_cache = dict(get_defender_status())
            self._defender_cache["ts"] = now
        return self._defender_cache

    def is_admin(self) -> bool:
        """Administrator privileges check."""
        from utils.windows_utils import is_admin

        return is_admin()

    # ------------------------------------------------------------------
    # Misc helpers used by pages
    # ------------------------------------------------------------------

    def signature_version_label(self) -> str:
        """Signature DB summary for the dashboard."""
        return self.signature_engine.version_label()

    def engine_version(self) -> str:
        """Engine version string."""
        return f"{self.version}.0"

    def yara_status_label(self) -> str:
        """YARA availability label."""
        if self.yara_engine.available:
            return "Available"
        return "Not installed (optional)"

    def platform_label(self) -> str:
        """Platform label."""
        import sys

        return f"Windows ({sys.platform})"

    def list_usb_devices(self) -> List[Dict[str, Any]]:
        """Currently connected removable drives."""
        from protection.usb_monitor import enumerate_usb_devices

        return [d.to_dict() for d in enumerate_usb_devices()]

    def list_known_usb_records(self) -> List[Dict[str, Any]]:
        """Previously seen USB device records."""
        return self.database.list_usb_devices()

    def list_exclusions(self) -> List[Dict[str, Any]]:
        """All exclusions."""
        return self.database.list_exclusions()

    def add_exclusion(self, exclusion_type: str, value: str) -> None:
        """Persist a new exclusion."""
        from utils.security_utils import normalize_exclusion_value

        normalized = normalize_exclusion_value(value, exclusion_type)
        self.database.add_exclusion(exclusion_type, normalized)
        self.database.add_event("exclusion_added",
                                f"{exclusion_type} exclusion: {normalized}")

    def remove_exclusion_by_value(self, exclusion_type: str, value: str) -> None:
        """Remove an exclusion by type+value."""
        for record in self.database.list_exclusions():
            if (record["exclusion_type"] == exclusion_type
                    and record["value"] == value):
                self.database.remove_exclusion(int(record["exclusion_id"]))
                return

    def apply_protection_settings(self) -> None:
        """(Re)start protection to apply changed settings."""
        if self.background_protection:
            try:
                from services.service_control import send_command

                send_command("apply_settings")
                return
            except Exception:  # noqa: BLE001
                logger.exception("Could not push settings to background core")
        self.protection.stop()
        self.protection.start()

    def on_setting_changed(self, key: str) -> None:
        """React to changed settings."""
        if key.startswith("protection"):
            self.apply_protection_settings()
        if key == "general.start_with_windows":
            from services.startup_service import (
                disable_start_with_windows,
                enable_start_with_windows,
                is_registered,
            )

            if self.settings.get("general.start_with_windows", False):
                if not enable_start_with_windows():
                    self._message("Could not register startup entry.",
                                  "warning")
            elif is_registered():
                disable_start_with_windows()

    def show_threat_details(self, detection: Detection, parent=None) -> None:
        """Open the technical details dialog."""
        from ui.threat_details import show_detection_details

        show_detection_details(
            parent or self.root, detection,
            on_quarantine=lambda: self.quarantine_detection_with_confirmation(
                detection, parent=parent),
        )

    def _show_first_run(self) -> None:
        """Show the welcome wizard."""
        from ui.first_run import FirstRunDialog

        FirstRunDialog(self)

    def _message(self, text: str, level: str = "info") -> None:
        """Show a message box on the UI thread."""
        import tkinter.messagebox as messagebox

        if level == "error":
            messagebox.showerror("LocalGuard", text, parent=self.root)
        elif level == "warning":
            messagebox.showwarning("LocalGuard", text, parent=self.root)
        else:
            messagebox.showinfo("LocalGuard", text, parent=self.root)

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def _on_close(self) -> None:
        """Clean shutdown of services and the Tk loop."""
        logger.info("Application closing")
        self._cancel_findings_poll()
        try:
            if self.tray is not None:
                self.tray.stop()
        except Exception:  # noqa: BLE001
            logger.exception("Tray stop failed on close")
        finally:
            from utils.notify import set_tray_provider

            set_tray_provider(None)
        try:
            self.protection.stop()
        except Exception:  # noqa: BLE001
            logger.exception("Protection stop failed on close")
        try:
            if self.scan_controller.running:
                self.scan_controller.stop()
                self.scan_controller.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.database.close()
        except Exception:  # noqa: BLE001
            pass
        self.root.destroy()


class ExclusionChecker:
    """Exclusion matcher used by the Scanner."""

    def __init__(self, database) -> None:
        self._database = database
        self._lock = threading.Lock()
        self._reload()

    def _reload(self) -> None:
        """Load exclusions from DB into fast in-memory sets."""
        with self._lock:
            self._files: set = set()
            self._folders: set = set()
            self._extensions: set = set()
            self._hashes: set = set()
            try:
                for record in self._database.list_exclusions():
                    value = str(record.get("value", ""))
                    kind = str(record.get("exclusion_type", ""))
                    if kind == "file":
                        self._files.add(value.lower())
                    elif kind == "folder":
                        self._folders.add(value.rstrip("\\/").lower())
                    elif kind == "extension":
                        self._extensions.add(value.lower().lstrip("."))
                    elif kind == "hash":
                        self._hashes.add(value.lower())
            except Exception:  # noqa: BLE001
                logger.exception("Could not load exclusions")

    def is_excluded(self, path: Path) -> bool:
        """Check one path against exclusion rules."""
        path = Path(path)
        lowered = str(path).lower()
        with self._lock:
            if lowered in self._files:
                return True
            for folder in self._folders:
                if lowered.startswith(folder + "\\") or lowered.startswith(folder + "/"):
                    return True
            if path.suffix.lower().lstrip(".") in self._extensions:
                return True
            return False

    def is_excluded_hash(self, sha256: str) -> bool:
        """Check a hash against hash exclusions."""
        with self._lock:
            return (sha256 or "").lower() in self._hashes


def os_environ(name: str) -> str:
    """Safe environment read."""
    import os

    return os.environ.get(name, "")
