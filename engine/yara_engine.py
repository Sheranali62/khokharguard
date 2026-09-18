"""LocalGuard Antivirus - optional YARA engine.

Loads YARA rules from signatures/yara/ when yara-python is installed.
If the module is unavailable or a rule fails validation, LocalGuard
continues functioning without YARA (spec section 18). YARA is never a
mandatory dependency.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from utils import get_logger, paths

logger = get_logger("yara")

try:  # optional dependency
    import yara  # type: ignore[import-not-found]

    YARA_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on environment
    yara = None  # type: ignore[assignment]
    YARA_AVAILABLE = False


class YaraMatch:
    """One YARA rule hit on one file."""

    def __init__(self, rule: str, severity: str, category: str,
                 description: str) -> None:
        self.rule = rule
        self.severity = severity
        self.category = category
        self.description = description


def _to_matches(matches) -> List[YaraMatch]:
    """Convert raw yara-python matches into :class:`YaraMatch` items."""
    results: List[YaraMatch] = []
    for match in matches:
        meta = match.meta or {}
        results.append(
            YaraMatch(
                rule=match.rule,
                severity=str(meta.get("severity", "high")),
                category=str(meta.get("category", "malware")),
                description=str(meta.get("description", "")),
            )
        )
    return results


class YaraEngine:
    """Optional YARA rule scanning with graceful fallback."""

    def __init__(self, rules_dir: Optional[Path] = None) -> None:
        self._rules_dir = Path(rules_dir) if rules_dir else paths.yara_rules_dir()
        self._rules = None
        self._compiled = False
        if YARA_AVAILABLE:
            self.reload()

    @property
    def available(self) -> bool:
        """True when yara-python imported successfully."""
        return YARA_AVAILABLE

    def reload(self) -> int:
        """(Re)compile all .yar/.yara files; return number of rules."""
        self._rules = None
        self._compiled = False
        if not YARA_AVAILABLE:
            logger.info("YARA not installed - rule scanning disabled")
            return 0

        rule_files = sorted(self._rules_dir.glob("*.yar")) + sorted(
            self._rules_dir.glob("*.yara")
        )
        if not rule_files:
            logger.info("No YARA rule files found in %s", self._rules_dir)
            return 0

        sources: Dict[str, str] = {}
        for path in rule_files:
            try:
                sources[path.stem] = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                logger.warning("Could not read YARA rule %s: %s", path, exc)

        try:
            self._rules = yara.compile(sources=sources)  # type: ignore[union-attr]
            self._compiled = True
            logger.info("YARA rules compiled: %d files", len(sources))
            return len(sources)
        except yara.Error as exc:  # type: ignore[union-attr]
            logger.error("YARA compilation failed: %s", exc)
            return 0

    def validate_rules(self) -> List[str]:
        """Return list of rule files that fail validation."""
        broken: List[str] = []
        if not YARA_AVAILABLE:
            return broken
        for path in sorted(self._rules_dir.glob("*.y*")):
            try:
                yara.compile(filepath=str(path))  # type: ignore[union-attr]
            except yara.Error as exc:  # type: ignore[union-attr]
                logger.warning("YARA rule invalid %s: %s", path, exc)
                broken.append(path.name)
        return broken

    def scan_file(self, path: Path) -> Optional[List[YaraMatch]]:
        """Scan one file; None when YARA is unavailable/failed."""
        if not YARA_AVAILABLE or not self._compiled or self._rules is None:
            return None
        try:
            matches = self._rules.match(str(path), timeout=30)
        except yara.Error as exc:  # type: ignore[union-attr]
            logger.debug("YARA scan error on %s: %s", path, exc)
            return None
        except yara.TimeoutError:  # type: ignore[union-attr]
            logger.warning("YARA timeout on %s", path)
            return None
        return _to_matches(matches)

    def scan_data(self, data: bytes) -> Optional[List[YaraMatch]]:
        """Scan an in-memory buffer; same contract as :meth:`scan_file`.

        Used for archive members and anywhere content is already in
        memory - avoids writing temp files and any on-access scanner
        interference with the bytes being inspected.
        """
        if not YARA_AVAILABLE or not self._compiled or self._rules is None:
            return None
        try:
            matches = self._rules.match(data=data, timeout=30)
        except yara.TimeoutError:  # type: ignore[union-attr]
            logger.warning("YARA timeout on in-memory data")
            return None
        except yara.Error as exc:  # type: ignore[union-attr]
            logger.debug("YARA data scan error: %s", exc)
            return None
        return _to_matches(matches)
