"""LocalGuard Antivirus - incremental scan cache.

Stores clean file verdicts keyed by (path, size, mtime, signature
version, engine version) so repeat scans skip files that have not
changed since their last clean result (spec section 34: "cache hashes
where safe", "skip unchanged files when configured").

Safety rules - correctness beats speed:

    - Only CLEAN verdicts are cached. Threats and suspicious files are
      always re-analysed, so an updated signature set can re-flag them.
    - Every entry is stamped with the signature database version;
      installing a signature update invalidates the whole cache, so a
      newly learned hash is checked against previously-clean files.
    - Any stat mismatch (size, mtime) misses; there is no partial
      matching. Files that cannot be stated are simply not cached.
    - The cache never decides a file is clean - it only says "this
      exact file was clean at engine version X". Deletion from the
      cache is always safe (worst case: the file is re-analysed).

Storage is a small SQLite database in the per-user data directory,
accessed through the same Database handle as the rest of the app so
writes stay serialised with the scan history (WAL, one connection).
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Dict, Optional, Tuple

from database.database import Database
from utils import get_logger

logger = get_logger("scan_cache")

# Bump when analysis behaviour changes in a way that could change
# verdicts for identical input (heuristic weights, PE rules, ...).
ENGINE_VERSION = "2"

_CACHE_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS scan_cache ("
    "    path            TEXT    NOT NULL,"
    "    size            INTEGER NOT NULL,"
    "    mtime_ns        INTEGER NOT NULL,"
    "    sig_version     TEXT    NOT NULL,"
    "    engine_version  TEXT    NOT NULL,"
    "    verdict         TEXT    NOT NULL,"
    "    cached_at       TEXT    NOT NULL DEFAULT (datetime('now')),"
    "    PRIMARY KEY (path, sig_version, engine_version)"
    ")"
)


class ScanCache:
    """Persistent clean-verdict cache backing incremental scans."""

    def __init__(self, database: Database, sig_version: str = "0") -> None:
        """``sig_version`` is the signature DB version to stamp entries
        with; changing it (via a signature update) drops all entries."""
        self._db = database
        self._sig_version = str(sig_version)
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        self._ensure_table()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _ensure_table(self) -> None:
        """Create the cache table (no-op after the first run)."""
        with self._lock:
            try:
                self._db.execute(_CACHE_SCHEMA)
            except Exception:  # noqa: BLE001 - cache must never break scans
                logger.warning("Could not create scan_cache table",
                               exc_info=True)

    def set_signature_version(self, sig_version: str) -> None:
        """Switch stamp version; clears ALL entries.

        Use for explicit full invalidation (signature update applied).
        """
        self._sig_version = str(sig_version)
        self.clear()

    def retarget_signature_version(self, sig_version: str) -> None:
        """Switch stamp version, dropping only *other* versions' rows.

        Used when picking up the current signature version: rows already
        stamped with the target version (e.g. written moments ago by a
        scan that started before the version was read) are kept.
        """
        sig_version = str(sig_version)
        if sig_version == self._sig_version:
            return
        previous = self._sig_version
        self._sig_version = sig_version
        with self._lock:
            try:
                self._db.execute(
                    "DELETE FROM scan_cache WHERE sig_version <> ?",
                    (sig_version,))
            except Exception:  # noqa: BLE001
                logger.debug("Cache retarget delete failed", exc_info=True)
        if previous not in ("0", ""):
            logger.info("Scan cache retargeted to signature version %s",
                        sig_version)

    # ------------------------------------------------------------------
    # Lookup / store
    # ------------------------------------------------------------------

    def lookup(self, path: Path, size: int, mtime_ns: int) -> bool:
        """True when this exact file version is a cached CLEAN.

        Non-clean verdicts are never stored, so a hit means clean.
        """
        key = (str(path), size, mtime_ns,
               self._sig_version, ENGINE_VERSION)
        with self._lock:
            try:
                row = self._db.query_one(
                    "SELECT 1 FROM scan_cache WHERE path = ? AND size = ? "
                    "AND mtime_ns = ? AND sig_version = ? "
                    "AND engine_version = ?",
                    key,
                )
            except Exception:  # noqa: BLE001
                return False
        if row is not None:
            self.hits += 1
            return True
        self.misses += 1
        return False

    def store_clean(self, path: Path, size: int, mtime_ns: int) -> None:
        """Record a clean verdict for this exact file version."""
        with self._lock:
            try:
                self._db.execute(
                    "INSERT OR REPLACE INTO scan_cache "
                    "(path, size, mtime_ns, sig_version, engine_version, verdict) "
                    "VALUES (?, ?, ?, ?, ?, 'clean')",
                    (str(path), size, mtime_ns,
                     self._sig_version, ENGINE_VERSION),
                )
            except Exception:  # noqa: BLE001 - cache is best effort
                logger.debug("Could not cache verdict for %s", path,
                             exc_info=True)

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def clear(self) -> int:
        """Drop every cached verdict; returns rows removed."""
        with self._lock:
            try:
                row = self._db.query_one("SELECT COUNT(*) AS n FROM scan_cache")
                count = int(row["n"]) if row else 0
                self._db.execute("DELETE FROM scan_cache")
                return count
            except Exception:  # noqa: BLE001
                return 0

    def prune_missing(self, known_paths: Optional[set] = None) -> int:
        """Remove entries whose files no longer exist (housekeeping).

        Called opportunistically after full scans to keep the table
        bounded. Paths are verified on disk one by one; unreadable
        entries are dropped (they will simply be re-analysed).
        """
        removed = 0
        with self._lock:
            try:
                rows = self._db.query(
                    "SELECT path FROM scan_cache WHERE sig_version = ? "
                    "AND engine_version = ?",
                    (self._sig_version, ENGINE_VERSION),
                )
                for row in rows:
                    if not Path(row["path"]).is_file():
                        self._db.execute(
                            "DELETE FROM scan_cache WHERE path = ?",
                            (row["path"],))
                        removed += 1
            except Exception:  # noqa: BLE001
                logger.debug("Cache prune failed", exc_info=True)
        return removed

    def stats(self) -> Dict[str, object]:
        """Cache size + hit/miss counters for the UI."""
        with self._lock:
            try:
                row = self._db.query_one("SELECT COUNT(*) AS n FROM scan_cache")
                entries = int(row["n"]) if row else 0
            except Exception:  # noqa: BLE001
                entries = 0
        return {
            "entries": entries,
            "hits": self.hits,
            "misses": self.misses,
            "sig_version": self._sig_version,
            "engine_version": ENGINE_VERSION,
        }
