"""Khokhar & Son's Antivirus - ransomware canary files.

Plants harmless decoy documents ("canaries") in common user folders
and watches them for modification. Canaries are files no legitimate
program has a reason to touch, so any modification is strong evidence
of bulk-encryption activity - the classic early warning of a
ransomware attack (complements spec sections 11 and 40).

Design:

    - Canary content is a plain text note explaining what the file is;
      it never contains code and is never executed by anything.
    - The monitor polls canary fingerprints (size + mtime + hash of a
      small prefix) on a worker thread - no watchdog dependency, so
      canary coverage works everywhere real-time protection does.
    - A modified canary raises an immediate user notification and a
      ``canary_tampered`` security event, then restores the decoy so
      coverage continues after the event.
    - Tamper detection is advisory by design: KhokharGuard never kills
      processes or deletes files on a canary hit. The user decides.

This is a detection aid, not a guarantee: ransomware that only
touches user documents and ignores the decoys will not be caught by
canaries alone.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from utils import get_logger
from utils.settings import get_settings

logger = get_logger("canary")

CANARY_FILENAME = "READ_ME_KhokharGuard_Canary.txt"

CANARY_TEXT = """\
KhokharGuard ransomware canary file
=================================

This is a harmless decoy file placed by Khokhar & Son's Antivirus.

It exists so that bulk-encrypting malware (ransomware) touches a
watched file. If this file changes, KhokharGuard warns you immediately -
a strong sign that something is encrypting your documents.

You can delete this file at any time, or disable canaries in
KhokharGuard Settings > Protection. Deleting it is always safe.
"""


def canary_directories() -> List[Path]:
    """User folders that get a canary decoy.

    Documents, Desktop, and Pictures are the highest-value ransomware
    targets. Every location is resolved from the environment (no
    hardcoded usernames) and skipped when missing.
    """
    userprofile = Path(os.environ.get("USERPROFILE", str(Path.home())))
    candidates = [
        userprofile / "Documents",
        userprofile / "Desktop",
        userprofile / "Pictures",
    ]
    return [d for d in candidates if d.is_dir()]


def canary_fingerprint(path: Path) -> Optional[bytes]:
    """Small fingerprint of a canary: size + mtime + hash of its head.

    Returns None when the file cannot be read (deleted/locked) - the
    caller treats that as tampering too, since canaries are never
    deleted by KhokharGuard itself while enabled.
    """
    try:
        stat = path.stat()
        with open(path, "rb") as handle:
            head = handle.read(4096)
        digest = hashlib.sha256(head).digest()
        return b"%d:%d:%s" % (stat.st_size, int(stat.st_mtime), digest)
    except OSError:
        return None


class CanaryMonitor:
    """Plants, watches, and restores ransomware canary decoys."""

    def __init__(
        self,
        directories: Optional[List[Path]] = None,
        poll_interval: float = 10.0,
        on_tampered: Optional[Callable[[Path], None]] = None,
    ) -> None:
        """``on_tampered`` fires (worker thread) per tampered canary."""
        self.directories = (
            directories if directories is not None else canary_directories()
        )
        self.poll_interval = max(2.0, poll_interval)
        self.on_tampered = on_tampered

        self._baseline: Dict[Path, Optional[bytes]] = {}
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self.running = False
        self.tamper_events = 0

    # ------------------------------------------------------------------
    # Planting
    # ------------------------------------------------------------------

    @property
    def canary_paths(self) -> List[Path]:
        """Expected canary path per configured directory."""
        return [d / CANARY_FILENAME for d in self.directories]

    def plant(self) -> List[Path]:
        """Create any missing canary files; return the canary paths.

        Existing canaries are never overwritten (their baseline is
        re-read instead) so a user's customised decoy is respected.
        """
        planted: List[Path] = []
        for path in self.canary_paths:
            try:
                if not path.exists():
                    path.write_text(CANARY_TEXT, encoding="utf-8")
                    planted.append(path)
                    logger.info("Planted canary: %s", path)
            except OSError as exc:
                logger.warning("Could not plant canary %s: %s", path, exc)
        return planted

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Plant canaries and begin watching them."""
        if self.running:
            return True
        if not self.directories:
            logger.info("Canary monitor has no directories to protect")
            return False

        self.plant()
        with self._lock:
            self._baseline = {
                path: canary_fingerprint(path) for path in self.canary_paths
            }
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._poll_loop, name="localguard-canary", daemon=True
        )
        self._thread.start()
        self.running = True
        logger.info(
            "Canary monitoring started on %d folder(s), interval %.0fs",
            len(self.directories), self.poll_interval,
        )
        try:
            from database.database import get_database

            get_database().add_event(
                "canary_enabled",
                f"Ransomware canaries armed in {len(self.directories)} "
                "folder(s)",
            )
        except Exception:  # noqa: BLE001 - event log is best effort
            pass
        return True

    def stop(self) -> None:
        """Stop watching canaries (decoy files stay in place)."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self.running = False
        logger.info("Canary monitoring stopped")

    def remove_all(self) -> int:
        """Delete every canary decoy (user asked to disable them)."""
        removed = 0
        for path in self.canary_paths:
            try:
                path.unlink(missing_ok=True)
                removed += 1
            except OSError as exc:
                logger.warning("Could not remove canary %s: %s", path, exc)
        with self._lock:
            self._baseline.clear()
        logger.info("Removed %d canary file(s)", removed)
        return removed

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def check_once(self) -> List[Path]:
        """Single sweep; returns tampered paths and raises alerts.

        A canary is tampered when its fingerprint changed from the
        baseline, or when the file vanished. The decoy is restored
        after each tamper so monitoring continues.
        """
        tampered: List[Path] = []
        for path in self.canary_paths:
            current = canary_fingerprint(path)
            with self._lock:
                baseline = self._baseline.get(path)
                self._baseline[path] = current
            if current == baseline:
                continue
            if baseline is None and current is not None:
                continue  # planted just now - not tampering
            tampered.append(path)
            self._handle_tamper(path, vanished=current is None)
        return tampered

    def _handle_tamper(self, path: Path, vanished: bool) -> None:
        """Alert, record, and restore one tampered canary."""
        self.tamper_events += 1
        kind = "removed" if vanished else "modified"
        logger.warning("CANARY TAMPERED (%s): %s", kind, path)
        try:
            from database.database import get_database

            get_database().add_event(
                "canary_tampered",
                f"Ransomware canary {kind}: {path}. This is a strong "
                "indicator of bulk file encryption activity. Review "
                "recently changed files and quarantine suspicious ones.",
                severity="critical",
            )
        except Exception:  # noqa: BLE001
            logger.debug("Could not record canary event", exc_info=True)

        if self.on_tampered is not None:
            try:
                self.on_tampered(path)
            except Exception:  # noqa: BLE001
                logger.exception("on_tampered callback error")

        self._restore(path)

    def _restore(self, path: Path) -> None:
        """Re-plant the decoy and reset its baseline."""
        try:
            path.write_text(CANARY_TEXT, encoding="utf-8")
        except OSError as exc:
            logger.warning("Could not restore canary %s: %s", path, exc)
        with self._lock:
            self._baseline[path] = canary_fingerprint(path)

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        """Poll canary fingerprints until stopped."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self.poll_interval)
            if self._stop_event.is_set():
                break
            try:
                self.check_once()
            except Exception:  # noqa: BLE001 - monitor must never die
                logger.exception("Canary poll error")


# ----------------------------------------------------------------------
# Settings wiring
# ----------------------------------------------------------------------


def monitor_from_settings(
    on_tampered: Optional[Callable[[Path], None]] = None,
) -> CanaryMonitor:
    """Build a CanaryMonitor honouring the protection.* settings."""
    settings = get_settings()
    if not settings.get("protection.canary_enabled", True):
        return CanaryMonitor(directories=[], on_tampered=on_tampered)
    interval = float(settings.get("protection.canary_poll_interval", 10.0))
    return CanaryMonitor(
        poll_interval=interval, on_tampered=on_tampered
    )
