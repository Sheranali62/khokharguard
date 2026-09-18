"""LocalGuard Antivirus - scanning engine.

Walks files (quick, full, custom, USB targets), analyses them through
FileAnalyzer, and yields detections. Supports pause/resume/stop,
exclusions, threaded analysis with bounded workers, and full
statistics reporting (spec sections 7, 8, 34, 35).
"""

from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set

from engine.file_analyzer import Detection, FileAnalyzer
from utils import get_logger
from utils.file_utils import iter_directory_files
from utils.security_utils import is_reparse_point

logger = get_logger("scanner")


class ScanState:
    """Cooperative pause/stop flags shared with worker threads."""

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._paused = threading.Event()

    def stop(self) -> None:
        """Request scan stop."""
        self._stop.set()
        self._pause.clear()
        self._paused.clear()

    def pause(self) -> None:
        """Request scan pause."""
        self._pause.set()

    def resume(self) -> None:
        """Resume a paused scan."""
        self._pause.clear()

    def check(self) -> bool:
        """Block while paused; return False when stop was requested."""
        if self._pause.is_set():
            self._paused.set()
            while self._pause.is_set() and not self._stop.is_set():
                time.sleep(0.15)
            self._paused.clear()
        return not self._stop.is_set()

    @property
    def stopped(self) -> bool:
        """True when stop was requested."""
        return self._stop.is_set()

    @property
    def paused(self) -> bool:
        """True while the scan is paused."""
        return self._paused.is_set()


class ScanStatistics:
    """Live counters for one scan session."""

    def __init__(self) -> None:
        self.files_scanned = 0
        self.directories_scanned = 0
        self.threats_found = 0
        self.suspicious_found = 0
        self.skipped = 0
        self.errors = 0
        self.bytes_scanned = 0
        self.start_time = time.monotonic()
        self.current_file = ""
        self.detections: List[Detection] = []

    @property
    def elapsed(self) -> float:
        """Elapsed seconds since scan start."""
        return time.monotonic() - self.start_time

    def snapshot(self) -> Dict[str, object]:
        """Thread-safe-ish copy for UI updates."""
        return {
            "files_scanned": self.files_scanned,
            "directories_scanned": self.directories_scanned,
            "threats_found": self.threats_found,
            "suspicious_found": self.suspicious_found,
            "skipped": self.skipped,
            "errors": self.errors,
            "elapsed": self.elapsed,
            "current_file": self.current_file,
        }


class Scanner:
    """Filesystem scanner using FileAnalyzer with bounded concurrency."""

    def __init__(
        self,
        analyzer: FileAnalyzer,
        exclusions: Optional[object] = None,
        threads: int = 4,
        state: Optional[ScanState] = None,
    ) -> None:
        """
        ``exclusions`` is an object with ``is_excluded(path: Path) -> bool``.
        """
        self.analyzer = analyzer
        self.exclusions = exclusions
        self.threads = max(1, min(threads, 16))
        self.state = state or ScanState()

    # ------------------------------------------------------------------
    # Target collection
    # ------------------------------------------------------------------

    def collect_files(self, targets: Iterable[Path],
                      progress: Optional[Callable[[Path], None]] = None,
                      stats: Optional[ScanStatistics] = None) -> List[Path]:
        """Collect scannable file paths under *targets*.

        Handles access denied, symlinks, reparse points, and network
        paths safely (spec section 8). Never follows reparse points.
        """
        files: List[Path] = []
        for target in targets:
            if not self.state.check():
                break
            target = Path(target)
            try:
                if target.is_file():
                    files.append(target)
                    continue
                if not target.is_dir():
                    if stats is not None:
                        stats.skipped += 1
                    continue
                if is_reparse_point(target):
                    if stats is not None:
                        stats.skipped += 1
                    continue
                for path, error in iter_directory_files(target):
                    if not self.state.check():
                        break
                    if error is not None:
                        if stats is not None:
                            stats.skipped += 1
                        continue
                    if self._excluded(path):
                        continue
                    files.append(path)
                if stats is not None:
                    stats.directories_scanned += 1
            except OSError as exc:
                logger.debug("Target %s unreadable: %s", target, exc)
                if stats is not None:
                    stats.errors += 1
            if progress is not None:
                progress(target)
        return files

    def _excluded(self, path: Path) -> bool:
        """Check exclusion rules when configured."""
        if self.exclusions is None:
            return False
        try:
            return self.exclusions.is_excluded(path)
        except Exception:  # noqa: BLE001 - exclusions must never break scans
            logger.debug("Exclusion check failed for %s", path)
            return False

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan_paths(
        self,
        targets: Iterable[Path],
        on_detection: Optional[Callable[[Detection], None]] = None,
        on_progress: Optional[Callable[[Dict[str, object]], None]] = None,
        on_file: Optional[Callable[[Path], None]] = None,
        deep_extensions_only: bool = False,
        progress_interval: float = 0.4,
    ) -> ScanStatistics:
        """Scan *targets* and return final statistics.

        ``on_detection`` fires per finding; ``on_progress`` fires
        periodically with a statistics snapshot for the UI.
        """
        stats = ScanStatistics()
        files = self.collect_files(targets, progress=on_file, stats=stats)
        if self.state.stopped:
            return stats

        total = len(files)
        done = 0
        last_progress = 0.0

        def worker(path: Path) -> Optional[Detection]:
            """Analyse one file inside the pool."""
            if not self.state.check():
                return None
            try:
                if deep_extensions_only and not self._deep_worthy(path):
                    stats.files_scanned += 1
                    return None
                detection = self.analyzer.analyze_path(path)
                stats.files_scanned += 1
                if detection.severity in {"high", "critical"}:
                    if detection.detection_method == "signature":
                        stats.threats_found += 1
                    else:
                        stats.suspicious_found += 1
                    return detection
                if detection.severity == "medium":
                    stats.suspicious_found += 1
                    return detection
            except Exception as exc:  # noqa: BLE001 - one bad file must not stop the scan
                stats.errors += 1
                logger.warning("Analysis failed for %s: %s", path, exc)
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(worker, f): f for f in files}
            for future in as_completed(futures):
                if self.state.stopped:
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                done += 1
                stats.current_file = str(futures[future])
                try:
                    detection = future.result()
                except Exception:  # noqa: BLE001
                    detection = None
                if detection is not None:
                    stats.detections.append(detection)
                    if on_detection is not None:
                        try:
                            on_detection(detection)
                        except Exception:  # noqa: BLE001
                            logger.exception("on_detection callback error")
                now = time.monotonic()
                if on_progress is not None and now - last_progress >= progress_interval:
                    last_progress = now
                    snapshot = stats.snapshot()
                    snapshot["total_files"] = total
                    snapshot["processed"] = done
                    try:
                        on_progress(snapshot)
                    except Exception:  # noqa: BLE001
                        logger.exception("on_progress callback error")

        snapshot = stats.snapshot()
        snapshot["total_files"] = total
        snapshot["processed"] = done
        if on_progress is not None:
            try:
                on_progress(snapshot)
            except Exception:  # noqa: BLE001
                pass
        return stats

    @staticmethod
    def _deep_worthy(path: Path) -> bool:
        """Quick-scan filter: analyse only high-risk file types."""
        from engine.file_analyzer import DEEP_EXTENSIONS

        return path.suffix.lower() in DEEP_EXTENSIONS or path.name.lower() in {
            "autorun.inf"
        }


# Re-export for compatibility with spec naming.
ScanController = Scanner
