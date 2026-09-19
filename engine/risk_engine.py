"""Khokhar & Son's Antivirus - risk engine.

Combines heuristic factors into a 0-100 risk score with severity
classes (spec section 16):

    0-19    CLEAN / LOW
    20-39   SUSPICIOUS
    40-69   HIGH RISK
    70-100  CRITICAL

Risk scores are internal technical indicators, NOT proof of malware.
A high score must never trigger automatic permanent deletion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Factor name -> (description template, weight)
FACTOR_WEIGHTS: Dict[str, int] = {
    "known_malicious_hash": 100,
    "eicar_test_file": 100,
    "yara_rule_match": 80,
    "executable_in_temp": 30,
    "executable_in_startup": 25,
    "double_extension": 25,
    "masquerading_document": 30,
    "hidden_executable": 15,
    "suspicious_script_content": 30,
    "autorun_inf_mechanism": 35,
    "suspicious_lnk_target": 35,
    "content_type_mismatch": 15,
    "high_entropy_pe_section": 10,
    "suspicious_pe_imports": 15,
    "writable_exec_section": 15,
    "unsigned_new_exe": 10,
    "tiny_or_odd_pe": 10,
    "malformed_archive_member": 10,
    "huge_archive_member": 10,
    "recent_modification": 5,
    "no_version_info": 5,
}

SEVERITY_THRESHOLDS = [
    (70, "critical"),
    (40, "high"),
    (20, "medium"),
    (0, "low"),
]

# Cap for purely heuristic accumulation (never auto-critical from
# heuristics alone unless explicitly forced).
HEURISTIC_CAP = 95


def severity_for_score(score: int) -> str:
    """Map a numeric score to its severity label."""
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "low"


class RiskEngine:
    """Accumulates weighted factors into a final risk assessment."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        """Clear all factors for a new assessment."""
        self._factors: List[Dict[str, object]] = []
        self._score = 0

    def add_factor(self, name: str, detail: str = "",
                   weight_override: Optional[int] = None) -> None:
        """Add a factor by name with optional weight override."""
        if name not in FACTOR_WEIGHTS:
            return
        weight = weight_override if weight_override is not None else FACTOR_WEIGHTS[name]
        self._factors.append({"factor": name, "detail": detail, "weight": weight})
        self._score = min(HEURISTIC_CAP, self._score + weight)

    def force_score(self, score: int, factor: str, detail: str = "") -> None:
        """Set the score directly (signature/YARA determinations)."""
        self._factors.append({"factor": factor, "detail": detail, "weight": score})
        self._score = max(self._score, min(100, score))

    @property
    def score(self) -> int:
        """Current accumulated score."""
        return self._score

    @property
    def severity(self) -> str:
        """Severity label for the current score."""
        return severity_for_score(self._score)

    @property
    def factors(self) -> List[Dict[str, object]]:
        """Applied factors with weights and details."""
        return list(self._factors)

    def factor_names(self) -> List[str]:
        """Names of all applied factors."""
        return [f["factor"] for f in self._factors]  # type: ignore[misc]

    def summary_lines(self) -> List[str]:
        """Human-readable factor breakdown for reports/UI."""
        lines = []
        for f in self._factors:
            detail = f": {f['detail']}" if f["detail"] else ""
            lines.append(f"+{f['weight']} {f['factor']}{detail}")
        return lines

    def evaluate(self) -> "RiskResult":
        """Finalise into a RiskResult."""
        return RiskResult(
            score=self._score,
            severity=self.severity,
            factors=self.factors,
        )


@dataclass
class RiskResult:
    """Immutable final risk assessment for one file."""

    score: int
    severity: str
    factors: List[Dict[str, object]] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        """True when score is in the CLEAN/LOW band."""
        return self.score < 20

    @property
    def is_suspicious(self) -> bool:
        """True when score reaches the SUSPICIOUS band."""
        return 20 <= self.score < 40

    @property
    def is_high(self) -> bool:
        """True when score reaches HIGH RISK band."""
        return 40 <= self.score < 70

    @property
    def is_critical(self) -> bool:
        """True when score is CRITICAL."""
        return self.score >= 70

    def describe(self) -> str:
        """One-line classification for UI display."""
        if self.is_critical:
            return "CRITICAL"
        if self.is_high:
            return "HIGH RISK"
        if self.is_suspicious:
            return "SUSPICIOUS"
        return "LOW RISK"
