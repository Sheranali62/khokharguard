"""LocalGuard Antivirus - scan controller.

High-level orchestration of scan sessions: persists scan history,
routes detections to the threat store, records security events, and
exposes pause/resume/stop to the UI (spec sections 7, 8, 30, 31).
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Callable, Dict, List, Optional

from engine.file_analyzer import Detection, FileAnalyzer
from engine.scanner import ScanState, ScanStatistics, Scanner
from utils import get_logger

logger = get_logger("scan_controller")


class ScanController:
    """Runs one scan session in a worker thread with DB bookkeeping."""

    def __init__(
        self,
        analyzer: FileAnalyzer,
        database=None,
        exclusions=None,
        threads: int = 4,
    ) -> None:
        self.analyzer = analyzer
        self.database = database
        self.exclusions = exclusions
        self.threads = threads

        self.state = ScanState()
        self.stats: Optional[ScanStatistics] = None
        self.scan_id: Optional[int] = None
        self.scan_type = "custom"
        self._thread: Optional[threading.Thread] = None
        self._finished = threading.Event()

        # Callbacks for UI wiring.
        self.on_detection: Optional[Callable[[Detection], None]] = None
        self.on_progress: Optional[Callable[[Dict[str, object]], None]] = None
        self.on_finished: Optional[Callable[[str], None]] = None  # final status

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def start(self, targets: List[Path], scan_type: str = "custom",
              deep_extensions_only: bool = False,
              on_removable: bool = False) -> Optional[threading.Thread]:
        """Start a scan in a background thread. Returns the thread."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Scan already running")
            return None

        self.scan_type = scan_type
        self.state = ScanState()
        self._finished.clear()
        target_strs = [str(t) for t in targets]

        if self.database is not None:
            try:
                self.scan_id = self.database.scan_start(scan_type, target_strs)
                self.database.add_event(
                    "scan_started", f"{scan_type} scan started ({len(targets)} target(s))",
                    details={"targets": target_strs},
                )
            except Exception:  # noqa: BLE001
                logger.exception("Could not record scan start")

        scanner = Scanner(
            self.analyzer, exclusions=self.exclusions,
            threads=self.threads, state=self.state,
        )

        def run() -> None:
            """Worker thread body."""
            final_status = "completed"
            try:
                self.stats = scanner.scan_paths(
                    targets,
                    on_detection=self._handle_detection,
                    on_progress=self._handle_progress,
                    deep_extensions_only=deep_extensions_only,
                )
                if self.state.stopped:
                    final_status = "stopped"
            except Exception:  # noqa: BLE001
                logger.exception("Scan crashed")
                final_status = "failed"
                if self.stats is None:
                    self.stats = ScanStatistics()

            self._record_completion(final_status)
            self._finished.set()
            if self.on_finished is not None:
                try:
                    self.on_finished(final_status)
                except Exception:  # noqa: BLE001
                    logger.exception("on_finished callback error")

        self._thread = threading.Thread(
            target=run, name=f"localguard-scan-{scan_type}", daemon=True
        )
        self._thread.start()
        return self._thread

    def pause(self) -> None:
        """Pause the running scan."""
        self.state.pause()

    def resume(self) -> None:
        """Resume a paused scan."""
        self.state.resume()

    def stop(self) -> None:
        """Request scan stop."""
        self.state.stop()
        if self.database is not None:
            try:
                self.database.add_event("scan_stopped",
                                        f"{self.scan_type} scan stopped by user")
            except Exception:  # noqa: BLE001
                pass

    def wait(self, timeout: Optional[float] = None) -> bool:
        """Wait for scan completion; True when finished."""
        return self._finished.wait(timeout)

    @property
    def running(self) -> bool:
        """True while the scan thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _handle_detection(self, detection: Detection) -> None:
        """Persist a detection and notify listeners."""
        if self.database is not None:
            try:
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
                    "recommended_action": detection.recommended_action,
                    "source": self.scan_type if self.scan_type != "custom" else "scan",
                    "scan_id": self.scan_id,
                })
                if self.scan_id is not None:
                    self.database.add_scan_result(self.scan_id, {
                        "path": detection.path,
                        "sha256": detection.sha256,
                        "size": detection.file_size,
                        "detection_name": detection.detection_name,
                        "detection_type": detection.detection_method,
                        "severity": detection.severity,
                        "confidence": detection.confidence,
                        "risk_score": detection.risk_score,
                        "reason": detection.reason,
                        "recommended_action": detection.recommended_action,
                        "action_taken": "none",
                    })
                self.database.add_event(
                    "threat_detected",
                    f"{detection.detection_name} at {detection.path}",
                    severity="critical" if detection.severity == "critical" else "warning",
                    details={"sha256": detection.sha256,
                             "severity": detection.severity,
                             "risk_score": detection.risk_score},
                )
            except Exception:  # noqa: BLE001
                logger.exception("Could not persist detection")

        if self.on_detection is not None:
            try:
                self.on_detection(detection)
            except Exception:  # noqa: BLE001
                logger.exception("on_detection callback error")

    def _handle_progress(self, snapshot: Dict[str, object]) -> None:
        """Forward progress snapshots to the UI."""
        if self.on_progress is not None:
            try:
                self.on_progress(snapshot)
            except Exception:  # noqa: BLE001
                logger.exception("on_progress callback error")

    def _record_completion(self, status: str) -> None:
        """Write final statistics to scan_history."""
        if self.database is not None and self.scan_id is not None and self.stats:
            try:
                self.database.scan_finish(
                    self.scan_id, status,
                    files_scanned=self.stats.files_scanned,
                    threats=self.stats.threats_found,
                    suspicious=self.stats.suspicious_found,
                    quarantined=0,
                    skipped=self.stats.skipped,
                    errors=self.stats.errors,
                    duration_secs=self.stats.elapsed,
                    directories_scanned=self.stats.directories_scanned,
                )
                self.database.add_event(
                    "scan_completed",
                    f"{self.scan_type} scan {status}: "
                    f"{self.stats.files_scanned} files, "
                    f"{self.stats.threats_found + self.stats.suspicious_found} findings",
                    details={"status": status},
                )
            except Exception:  # noqa: BLE001
                logger.exception("Could not record scan completion")
