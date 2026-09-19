"""Khokhar & Son's Antivirus - real-time filesystem monitor.

Watches configurable locations (Downloads, Desktop, Temp) with
watchdog observers for file creation/modification/moves (spec section
11). New files are hashed, analysed, and risk-scored; alerts fire and
optional auto-quarantine applies only for signature-confirmed threats
- heuristics alone never trigger destructive action.

Falls back to a low-frequency poller when watchdog is unavailable.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

from engine.file_analyzer import Detection, FileAnalyzer
from utils import get_logger
from utils.file_utils import SUSPICIOUS_EXTENSIONS

logger = get_logger("realtime")

try:  # optional dependency
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    WATCHDOG_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on environment
    WATCHDOG_AVAILABLE = False


def default_watch_locations() -> List[Path]:
    """Resolve the default watched directories from environment."""
    locations: List[Path] = []
    userprofile = Path(os.environ.get("USERPROFILE", str(Path.home())))

    downloads = userprofile / "Downloads"
    desktop = userprofile / "Desktop"
    temp = Path(os.environ.get("TEMP", str(userprofile / "AppData" / "Local" / "Temp")))

    for candidate in (downloads, desktop, temp):
        if candidate.is_dir():
            locations.append(candidate)
    return locations


def resolve_watch_locations(names: List[str]) -> List[Path]:
    """Map settings keys (downloads/desktop/temp/custom paths) to dirs."""
    userprofile = Path(os.environ.get("USERPROFILE", str(Path.home())))
    mapping: Dict[str, Path] = {
        "downloads": userprofile / "Downloads",
        "desktop": userprofile / "Desktop",
        "temp": Path(os.environ.get("TEMP", str(userprofile / "AppData" / "Local" / "Temp"))),
        "documents": userprofile / "Documents",
    }
    resolved: List[Path] = []
    for name in names:
        if name in mapping:
            if mapping[name].is_dir():
                resolved.append(mapping[name])
        else:
            candidate = Path(name)
            if candidate.is_dir():
                resolved.append(candidate)
    return resolved


class _WatchdogHandler(FileSystemEventHandler):  # type: ignore[misc]
    """Forwards filesystem events to the RealTimeMonitor."""

    def __init__(self, monitor: "RealTimeMonitor") -> None:
        self._monitor = monitor

    def on_created(self, event) -> None:  # noqa: N802 - watchdog API
        if not event.is_directory:
            self._monitor.handle_new_file(Path(str(event.src_path)))

    def on_moved(self, event) -> None:  # noqa: N802 - watchdog API
        if not event.is_directory:
            self._monitor.handle_new_file(Path(str(event.dest_path)))


class RealTimeMonitor:
    """Watches configured locations and analyses new suspicious files."""

    def __init__(
        self,
        analyzer: FileAnalyzer,
        locations: Optional[List[Path]] = None,
        auto_quarantine: bool = False,
        quarantine_callback: Optional[Callable[[Detection], object]] = None,
        on_detection: Optional[Callable[[Detection], None]] = None,
        rate_limit_seconds: float = 0.5,
    ) -> None:
        self.analyzer = analyzer
        self.locations = locations if locations is not None else default_watch_locations()
        self.auto_quarantine = auto_quarantine
        self.quarantine_callback = quarantine_callback
        self.on_detection = on_detection
        self.rate_limit_seconds = rate_limit_seconds

        self._observer = None
        self._poll_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_handled: Dict[str, float] = {}
        self._known_snapshot: Dict[str, float] = {}
        self.running = False
        self.using_watchdog = WATCHDOG_AVAILABLE
        self.files_flagged = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start monitoring. Returns True when a mechanism is active."""
        if self.running:
            return True
        if not self.locations:
            logger.warning("Real-time monitor has no locations to watch")
            return False

        self._stop_event.clear()

        if WATCHDOG_AVAILABLE:
            try:
                self._observer = Observer(timeout=1.0)
                handler = _WatchdogHandler(self)
                for location in self.locations:
                    try:
                        self._observer.schedule(handler, str(location), recursive=True)
                    except OSError as exc:
                        logger.warning("Cannot watch %s: %s", location, exc)
                self._observer.start()
                self.using_watchdog = True
                logger.info("Real-time monitoring via watchdog on %d location(s)",
                            len(self.locations))
            except Exception:  # noqa: BLE001 - fall back to polling
                logger.exception("Watchdog start failed; falling back to polling")
                self._observer = None
                self.using_watchdog = False

        if not self.using_watchdog:
            self._known_snapshot = self._snapshot_locations()
            self._poll_thread = threading.Thread(
                target=self._poll_loop, name="khokharguard-rt-poll", daemon=True
            )
            self._poll_thread.start()
            logger.info("Real-time monitoring via polling on %d location(s)",
                        len(self.locations))

        self.running = True
        from database.database import get_database

        try:
            get_database().add_event("protection_enabled",
                                     "Real-time protection enabled")
        except Exception:  # noqa: BLE001
            pass
        return True

    def stop(self) -> None:
        """Stop monitoring cleanly."""
        self._stop_event.set()
        if self._observer is not None:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception:  # noqa: BLE001
                logger.debug("Observer stop error", exc_info=True)
            self._observer = None
        if self._poll_thread is not None:
            self._poll_thread.join(timeout=5)
            self._poll_thread = None
        self.running = False
        logger.info("Real-time monitoring stopped")
        from database.database import get_database

        try:
            get_database().add_event("protection_disabled",
                                     "Real-time protection disabled")
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------

    def handle_new_file(self, path: Path) -> None:
        """Analyse a newly created/moved file (rate-limited)."""
        path = Path(path)
        if not path.is_file():
            return
        if path.suffix.lower() not in SUSPICIOUS_EXTENSIONS:
            return  # do not interfere with normal file operations
        if path.name.startswith("~$"):
            return  # office temp files

        key = str(path)
        now = time.monotonic()
        if now - self._last_handled.get(key, 0.0) < self.rate_limit_seconds:
            return
        self._last_handled[key] = now
        if len(self._last_handled) > 5000:
            self._last_handled.clear()

        # Small settle delay lets writers finish (AV-like behaviour).
        time.sleep(0.2)
        if self._stop_event.is_set() or not path.is_file():
            return

        try:
            detection = self.analyzer.analyze_path(path)
        except Exception:  # noqa: BLE001 - never crash the monitor
            logger.exception("Real-time analysis failed for %s", path)
            return

        if detection.severity in {"medium", "high", "critical"}:
            self.files_flagged += 1
            logger.info("Real-time flag: %s (%s, score %d)",
                        path, detection.detection_name, detection.risk_score)
            self._record(detection)

            if self.on_detection is not None:
                try:
                    self.on_detection(detection)
                except Exception:  # noqa: BLE001
                    logger.exception("on_detection callback error")

            # Auto-quarantine ONLY signature-confirmed threats.
            if (
                self.auto_quarantine
                and detection.is_threat
                and self.quarantine_callback is not None
            ):
                try:
                    self.quarantine_callback(detection)
                except Exception:  # noqa: BLE001
                    logger.exception("Auto-quarantine failed for %s", path)

    # ------------------------------------------------------------------
    # Polling fallback
    # ------------------------------------------------------------------

    def _snapshot_locations(self) -> Dict[str, float]:
        """Map of suspicious-file path -> mtime for watched locations."""
        snapshot: Dict[str, float] = {}
        for location in self.locations:
            try:
                for dirpath, dirnames, filenames in os.walk(location):
                    dirnames[:] = [d for d in dirnames if not d.startswith(".")]
                    for filename in filenames:
                        if Path(filename).suffix.lower() in SUSPICIOUS_EXTENSIONS:
                            full = Path(dirpath) / filename
                            try:
                                snapshot[str(full)] = full.stat().st_mtime
                            except OSError:
                                continue
            except OSError:
                continue
        return snapshot

    def _poll_loop(self) -> None:
        """Poll for new/changed suspicious files when watchdog missing."""
        while not self._stop_event.is_set():
            self._stop_event.wait(4.0)
            if self._stop_event.is_set():
                break
            try:
                current = self._snapshot_locations()
                new_files = [
                    Path(p) for p, mtime in current.items()
                    if self._known_snapshot.get(p, 0.0) != mtime
                ]
                self._known_snapshot = current
                for path in new_files:
                    self.handle_new_file(path)
            except Exception:  # noqa: BLE001
                logger.exception("Real-time poll error")

    def _record(self, detection: Detection) -> None:
        """Persist detection to DB (best effort).

        User notification is owned by the app-level detection pipeline
        (``protection.on_threat`` -> UI), which applies rate limits and
        per-kind preferences in one place; the monitor must not notify
        separately or users would get double alerts.
        """
        try:
            from database.database import get_database

            get_database().add_threat({
                "file_path": detection.path,
                "sha256": detection.sha256,
                "file_size": detection.file_size,
                "detection_name": detection.detection_name,
                "detection_type": detection.detection_method,
                "severity": detection.severity,
                "confidence": detection.confidence,
                "risk_score": detection.risk_score,
                "reason": detection.reason,
                "recommended_action": detection.recommended_action,
                "source": "realtime",
            })
        except Exception:  # noqa: BLE001
            logger.debug("Could not persist realtime detection", exc_info=True)
