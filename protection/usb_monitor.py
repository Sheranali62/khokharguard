"""Khokhar & Son's Antivirus - USB / removable drive monitor.

Detects removable drives appearing or disappearing and reports their
details (drive letter, volume name, capacity, free space, file system)
for the USB Protection page (spec section 10). Detection runs on a
light poller thread; scanning itself is left to the scan controller
so inserting a drive never blocks the UI.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

from utils import get_logger, windows_utils
from utils.notify import notify

logger = get_logger("usb_monitor")


class USBDevice:
    """Snapshot of one removable drive."""

    def __init__(self, drive_letter: str, volume_name: str, serial: str,
                 capacity: Optional[int], free: Optional[int],
                 file_system: str) -> None:
        self.drive_letter = drive_letter
        self.volume_name = volume_name
        self.serial = serial
        self.capacity_bytes = capacity
        self.free_bytes = free
        self.file_system = file_system

    def to_dict(self) -> Dict[str, object]:
        """Dictionary for UI display and DB upsert."""
        return {
            "drive_letter": self.drive_letter,
            "volume_name": self.volume_name,
            "serial": self.serial,
            "capacity_bytes": self.capacity_bytes,
            "free_bytes": self.free_bytes,
            "file_system": self.file_system,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<USBDevice {self.drive_letter} '{self.volume_name}'>"


def enumerate_usb_devices() -> List[USBDevice]:
    """Snapshot of currently connected removable drives."""
    devices: List[USBDevice] = []
    for drive in windows_utils.get_removable_drives():
        mount = Path(str(drive.get("mountpoint", "")))
        if not mount.exists():
            continue
        devices.append(
            USBDevice(
                drive_letter=str(drive.get("mountpoint")),
                volume_name=windows_utils.volume_label(mount),
                serial=windows_utils.drive_serial(mount),
                capacity=drive.get("capacity_bytes"),
                free=drive.get("free_bytes"),
                file_system=str(drive.get("fstype") or ""),
            )
        )
    return devices


class USBMonitor:
    """Polls for removable drive insertion/removal events."""

    def __init__(
        self,
        on_inserted: Optional[Callable[[USBDevice], None]] = None,
        on_removed: Optional[Callable[[str], None]] = None,
        poll_interval: float = 2.5,
    ) -> None:
        self.on_inserted = on_inserted
        self.on_removed = on_removed
        self.poll_interval = poll_interval
        self._known: Set[str] = set()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the polling thread (seeds current drives as known)."""
        if self.running:
            return
        with self._lock:
            self._known = {d.drive_letter for d in enumerate_usb_devices()}
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._poll_loop, name="localguard-usb", daemon=True
        )
        self._thread.start()
        self.running = True
        logger.info("USB monitor started (%d drive(s) known)", len(self._known))

    def stop(self) -> None:
        """Stop the polling thread."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self.running = False
        logger.info("USB monitor stopped")

    def current_devices(self) -> List[USBDevice]:
        """Current snapshot for the UI."""
        return enumerate_usb_devices()

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        """Poll removable drives and emit events."""
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception:  # noqa: BLE001 - monitor must never die
                logger.exception("USB poll error")
            self._stop_event.wait(self.poll_interval)

    def _poll_once(self) -> None:
        """One poll iteration: diff against known drives."""
        current = {d.drive_letter: d for d in enumerate_usb_devices()}
        with self._lock:
            known = set(self._known)

        inserted = [d for letter, d in current.items() if letter not in known]
        removed = [letter for letter in known if letter not in current]

        with self._lock:
            self._known = set(current.keys())

        for device in inserted:
            logger.info("USB inserted: %s (%s)", device.drive_letter,
                        device.volume_name)
            self._record_device(device)
            notify("usb_detected", "KhokharGuard",
                   f"USB device detected: {device.drive_letter} {device.volume_name}")
            if self.on_inserted is not None:
                try:
                    self.on_inserted(device)
                except Exception:  # noqa: BLE001
                    logger.exception("on_inserted callback error")

        for letter in removed:
            logger.info("USB removed: %s", letter)
            if self.on_removed is not None:
                try:
                    self.on_removed(letter)
                except Exception:  # noqa: BLE001
                    logger.exception("on_removed callback error")

    def _record_device(self, device: USBDevice) -> None:
        """Persist the device in usb_devices table (best effort)."""
        try:
            from database.database import get_database

            get_database().upsert_usb_device(
                device.drive_letter, device.volume_name, device.serial,
                device.capacity_bytes, device.free_bytes, device.file_system,
            )
            get_database().add_event(
                "usb_inserted",
                f"USB device inserted: {device.drive_letter} "
                f"'{device.volume_name}' ({device.file_system or 'unknown FS'})",
            )
        except Exception:  # noqa: BLE001
            logger.debug("Could not record USB device", exc_info=True)
