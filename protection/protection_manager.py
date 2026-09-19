"""Khokhar & Son's Antivirus - protection manager.

Central coordinator for USB monitoring, real-time monitoring, and
protection state reporting (spec sections 10, 11, 40). Wires monitor
events to scanning, notifications, and auto-quarantine based on
settings. Exposes one start/stop/pause surface for the UI and tray.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Callable, Dict, List, Optional

from engine.file_analyzer import Detection, FileAnalyzer
from engine.scan_controller import ScanController
from protection.canary import CanaryMonitor, monitor_from_settings
from protection.realtime_monitor import RealTimeMonitor, resolve_watch_locations
from protection.usb_monitor import USBDevice, USBMonitor
from utils import get_logger
from utils.settings import get_settings

logger = get_logger("protection_manager")


class ProtectionManager:
    """Starts/stops protection components per settings."""

    def __init__(self, analyzer: FileAnalyzer, scan_controller: ScanController,
                 database=None) -> None:
        self.analyzer = analyzer
        self.scan_controller = scan_controller
        self.settings = get_settings()
        # Used for the USB trusted-device lookup; resolved lazily so
        # tests can inject an isolated database.
        self.database = database

        self.usb_monitor = USBMonitor(on_inserted=self._on_usb_inserted)
        self.realtime_monitor: Optional[RealTimeMonitor] = None
        self.canary_monitor: Optional[CanaryMonitor] = None

        self._paused = False
        self._lock = threading.Lock()
        self.on_threat: Optional[Callable[[Detection], None]] = None
        self.on_state_changed: Optional[Callable[[], None]] = None
        # Fired when a USB auto-scan actually starts so the UI/tray can
        # show the progress hint for background scans too.
        self.on_usb_autoscan_started: Optional[Callable[[], None]] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start enabled protection components."""
        with self._lock:
            if self.settings.get("protection.usb_autoscan", True):
                self.usb_monitor.start()

            if self.settings.get("protection.realtime_enabled", True):
                self._start_realtime()

            if self.settings.get("protection.canary_enabled", True):
                self._start_canary()
        self._notify_state_changed()

    def _start_realtime(self) -> None:
        """Build and start the real-time monitor from settings."""
        names = self.settings.get("protection.realtime_watch_locations",
                                  ["downloads", "desktop", "temp"])
        locations = resolve_watch_locations(list(names))
        self.realtime_monitor = RealTimeMonitor(
            analyzer=self.analyzer,
            locations=locations,
            auto_quarantine=bool(self.settings.get("protection.auto_quarantine", False)),
            quarantine_callback=self._auto_quarantine,
            on_detection=self._on_realtime_detection,
        )
        self.realtime_monitor.start()

    def _start_canary(self) -> None:
        """Build and start the ransomware canary monitor from settings."""
        self.canary_monitor = monitor_from_settings(
            on_tampered=self._on_canary_tampered)
        self.canary_monitor.start()

    def stop(self) -> None:
        """Stop all protection components."""
        with self._lock:
            self.usb_monitor.stop()
            if self.realtime_monitor is not None:
                self.realtime_monitor.stop()
                self.realtime_monitor = None
            if self.canary_monitor is not None:
                self.canary_monitor.stop()
                self.canary_monitor = None
        self._notify_state_changed()

    def pause_protection(self) -> None:
        """Pause real-time + USB events (tray 'Pause Protection')."""
        with self._lock:
            self._paused = True
            if self.realtime_monitor is not None and self.realtime_monitor.running:
                self.realtime_monitor.stop()
            if self.usb_monitor.running:
                self.usb_monitor.stop()
            if self.canary_monitor is not None and self.canary_monitor.running:
                self.canary_monitor.stop()
        self._notify_state_changed()

    def resume_protection(self) -> None:
        """Resume previously paused protection.

        The lock is released before calling ``start()`` - the lock is
        a non-reentrant ``threading.Lock`` and ``start()`` acquires it
        itself; holding it across the call deadlocks (previously a
        latent bug that froze the GUI resume path).
        """
        with self._lock:
            self._paused = False
        self.start()

    def _notify_state_changed(self) -> None:
        """Fire the on_state_changed hook (UI/tray refresh), best-effort."""
        callback = self.on_state_changed
        if callback is None:
            return
        try:
            callback()
        except Exception:  # noqa: BLE001
            logger.exception("on_state_changed callback error")

    @property
    def paused(self) -> bool:
        """True when protection is paused."""
        return self._paused

    # ------------------------------------------------------------------
    # Event wiring
    # ------------------------------------------------------------------

    def _on_usb_inserted(self, device: USBDevice) -> None:
        """Handle a newly inserted removable drive."""
        if self._paused:
            return

        if not self.settings.get("protection.usb_autoscan", True):
            return

        # Trusted drives (user-approved by serial + volume label) skip
        # the automatic rescan; scanning stays available from the USB
        # page at any time. Unidentifiable drives are never trusted.
        try:
            database = self.database
            if database is None:
                from database.database import get_database

                database = get_database()
            if device.serial and database.is_usb_trusted(
                    device.serial, device.volume_name):
                logger.info(
                    "USB device %s (%s) is trusted - skipping auto-scan",
                    device.drive_letter, device.volume_name)
                from utils.notify import notify

                notify("usb_detected", "KhokharGuard - USB connected",
                       f"{device.drive_letter} {device.volume_name} is a "
                       "trusted device - auto-scan skipped")
                return
        except Exception:  # noqa: BLE001 - trust check must never break USB handling
            logger.exception("USB trust check failed; scanning anyway")

        logger.info("Auto-scanning inserted USB device %s", device.drive_letter)
        self._scan_usb_async(device)

    def _scan_usb_async(self, device: USBDevice) -> None:
        """Start a USB scan in the shared scan controller."""
        from utils.notify import notify

        previous_finished = self.scan_controller.on_finished

        def finished(status: str) -> None:
            """Chain the previous handler, then notify on completion."""
            if previous_finished is not None:
                try:
                    previous_finished(status)
                except Exception:  # noqa: BLE001
                    logger.exception("previous on_finished callback error")
            threat_count = 0
            if self.scan_controller.stats is not None:
                threat_count = (
                    self.scan_controller.stats.threats_found
                    + self.scan_controller.stats.suspicious_found
                )
            if status == "completed":
                notify(
                    "scan_complete", "KhokharGuard - USB Scan Complete",
                    f"{device.drive_letter}: {threat_count} finding(s)",
                )

        if not self.scan_controller.running:
            self.scan_controller.on_finished = finished
            started = self.scan_controller.start(
                [Path(device.drive_letter)], scan_type="usb",
                deep_extensions_only=True,
            )
            if started is not None and self.on_usb_autoscan_started is not None:
                try:
                    self.on_usb_autoscan_started()
                except Exception:  # noqa: BLE001
                    logger.exception("on_usb_autoscan_started callback error")

    def _on_realtime_detection(self, detection: Detection) -> None:
        """Forward real-time detections to UI callback."""
        if self.on_threat is not None:
            try:
                self.on_threat(detection)
            except Exception:  # noqa: BLE001
                logger.exception("on_threat callback error")

    def _on_canary_tampered(self, path: Path) -> None:
        """Alert the user that a ransomware canary was touched."""
        from utils.notify import notify

        notify(
            "threat_detected",
            "KhokharGuard - RANSOMWARE WARNING",
            f"A watched canary file changed: {path}. Something may be "
            "encrypting your files - review and quarantine now.",
            force=True,
        )

    def _auto_quarantine(self, detection: Detection) -> object:
        """Auto-quarantine signature-confirmed threats only."""
        try:
            from quarantine.quarantine_manager import QuarantineManager

            result = QuarantineManager().quarantine_detection(
                detection, source="realtime"
            )
            from utils.notify import notify

            notify("threat_detected", "KhokharGuard - Threat Quarantined",
                   f"{detection.detection_name} was quarantined",
                   force=True)
            return result
        except Exception:  # noqa: BLE001
            logger.exception("Auto-quarantine failed for %s", detection.path)
            return None

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> Dict[str, object]:
        """Dashboard status snapshot."""
        return {
            "realtime_enabled": (
                self.realtime_monitor is not None and self.realtime_monitor.running
            ),
            "usb_monitoring": self.usb_monitor.running,
            "paused": self._paused,
            "realtime_using_watchdog": (
                self.realtime_monitor.using_watchdog
                if self.realtime_monitor else False
            ),
            "watch_locations": (
                [str(p) for p in self.realtime_monitor.locations]
                if self.realtime_monitor else []
            ),
            "canary_enabled": (
                self.canary_monitor is not None and self.canary_monitor.running
            ),
        }
