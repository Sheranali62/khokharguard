"""LocalGuard Antivirus - file analyzer.

Orchestrates every analysis layer for one file (spec section 65):

    hash -> signature -> YARA -> heuristics -> PE -> archive -> risk

Produces a Detection with name, severity, confidence, method, reason,
and recommended action. Never executes the analysed file (spec 28).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from engine.archive_scanner import ArchiveScanner, is_archive
from engine.hash_engine import HashEngine
from engine.heuristic_engine import (
    analyze_autorun_inf,
    analyze_filename_risk,
    analyze_location_risk,
    analyze_lnk_structure,
    analyze_script_content,
    is_in_temp,
)
from engine.pe_analyzer import PEAnalyzer
from engine.risk_engine import RiskEngine, severity_for_score
from engine.signature_engine import SignatureEngine
from engine.yara_engine import YaraEngine
from utils import get_logger
from utils.file_utils import (
    ARCHIVE_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    SCRIPT_EXTENSIONS,
    SHORTCUT_EXTENSIONS,
    looks_like_pe,
    read_prefix,
)

logger = get_logger("file_analyzer")

SEVERITY_ORDER = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Extension set eligible for YARA scanning: executables plus the
# script/shortcut/autorun file types where starter rules detect
# malicious content patterns (scripts are text, so scanning them is
# cheap and high-value).
YARA_EXTENSIONS = SCRIPT_EXTENSIONS | SHORTCUT_EXTENSIONS

# Extensions LocalGuard performs deep analysis on.
DEEP_EXTENSIONS = (
    EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS | SHORTCUT_EXTENSIONS | ARCHIVE_EXTENSIONS
)

# Files that are always at least quickly analysed regardless of size cap
# (e.g. autorun.inf on USB drives).
ALWAYS_ANALYZE_NAMES = {"autorun.inf"}


@dataclass
class Detection:
    """Final detection verdict for one file (spec section 65)."""

    path: str
    detection_name: str = "Clean.File"
    severity: str = "clean"          # clean | low | medium | high | critical
    confidence: str = "low"          # low | medium | high
    detection_method: str = "none"   # signature | heuristic | yara | pe | none
    reason: str = ""
    recommended_action: str = "No action required."
    sha256: str = ""
    file_size: int = 0
    risk_score: int = 0
    file_type: str = "unknown"
    factors: List[dict] = field(default_factory=list)
    pe_summary: str = ""
    scan_duration: float = 0.0

    @property
    def is_threat(self) -> bool:
        """True when the file is known malware or test signature."""
        return self.detection_method == "signature" and self.severity in {"high", "critical"}

    @property
    def needs_review(self) -> bool:
        """True when the file is suspicious enough to show the user."""
        return self.severity in {"medium", "high", "critical"}


class FileAnalyzer:
    """Analyzes individual files through the full detection pipeline."""

    def __init__(
        self,
        signature_engine: SignatureEngine,
        hash_engine: Optional[HashEngine] = None,
        yara_engine: Optional[YaraEngine] = None,
        pe_analyzer: Optional[PEAnalyzer] = None,
        archive_scanner: Optional[ArchiveScanner] = None,
        max_file_size: int = 512 * 1024 * 1024,
        scan_archives: bool = True,
        hash_cache: bool = True,
    ) -> None:
        self.signatures = signature_engine
        self.hash_engine = hash_engine or HashEngine(cache_enabled=hash_cache)
        self.yara = yara_engine or YaraEngine()
        self.pe = pe_analyzer or PEAnalyzer()
        self.archives = archive_scanner or ArchiveScanner()
        self.max_file_size = max_file_size
        self.scan_archives_enabled = scan_archives

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_path(self, path: Path, on_removable_drive: bool = False) -> Detection:
        """Build a Detection for *path* (main entry point)."""
        started = time.monotonic()
        risk = RiskEngine()
        path = Path(path)

        try:
            stat = path.stat()
        except OSError as exc:
            return Detection(
                path=str(path), detection_name="Inaccessible.File",
                severity="low", confidence="high", detection_method="none",
                reason=f"file could not be read: {exc}",
                recommended_action="File was skipped.",
                scan_duration=time.monotonic() - started,
            )

        size = stat.st_size

        # --- Hash & signature (works for any file type) ---
        record = self.hash_engine.hash_record(
            path, max_bytes=self.max_file_size if size > self.max_file_size else None
        )
        sha256 = record.sha256 if record else ""
        file_type = record.type if record else "unknown"

        signature_hit = self.signatures.lookup(sha256) if sha256 else None

        # --- Deep analysis only for interesting types/names ---
        deep_worthy = (
            path.suffix.lower() in DEEP_EXTENSIONS
            or path.name.lower() in ALWAYS_ANALYZE_NAMES
            or signature_hit is not None
        )

        pe_summary = ""
        matches = None  # YARA matches (None when YARA unavailable/skipped)
        if signature_hit:
            risk.force_score(
                100 if signature_hit.severity in {"high", "critical"} else 60,
                "known_malicious_hash" if signature_hit.category != "test" else "eicar_test_file",
                f"{signature_hit.name} ({signature_hit.severity})",
            )

        if deep_worthy:
            # Filename + location heuristics (cheap, always).
            analyze_filename_risk(path, risk)
            analyze_location_risk(path, risk)

            # Content heuristics for scripts, shortcuts, autorun.
            if path.suffix.lower() in SCRIPT_EXTENSIONS:
                analyze_script_content(path, risk)
            if path.suffix.lower() == ".lnk":
                analyze_lnk_structure(path, risk)
            if path.name.lower() == "autorun.inf":
                analyze_autorun_inf(path, risk)

            # PE structural analysis.
            if (
                path.suffix.lower() in EXECUTABLE_EXTENSIONS
                and size <= self.max_file_size
                and (looks_like_pe(path) or path.suffix in {".exe", ".dll", ".sys"})
            ):
                pe_info = self.pe.analyze(path)
                pe_summary = _pe_indicator_summary(pe_info)
                _apply_pe_indicators(pe_info, path, risk)

            # YARA rules (optional layer). Scripts, shortcuts, and
            # autorun configurations are high-value YARA targets but
            # are not executables, so they are scanned explicitly.
            yara_eligible = (
                size <= self.max_file_size
                and (path.suffix.lower() in EXECUTABLE_EXTENSIONS
                     or path.suffix.lower() in YARA_EXTENSIONS)
            )
            if self.yara.available and yara_eligible:
                matches = self.yara.scan_file(path)
                if matches:
                    for match in matches:
                        risk.force_score(
                            100 if match.severity in {"high", "critical"} else 70,
                            "yara_rule_match",
                            f"YARA rule '{match.rule}' matched",
                        )

            # Archive inspection (bounded, never executes members).
            if self.scan_archives_enabled and is_archive(path) and size <= self.max_file_size:
                self.archives.scan_archive(
                    path, risk, lambda member, r: self._analyze_member(member, r)
                )

            # Content/extension mismatch check.
            mismatch = _type_mismatch_note(path)
            if mismatch:
                risk.add_factor("content_type_mismatch", mismatch)

        score = risk.score
        severity = "clean" if score == 0 else severity_for_score(score)
        name, method, reason, action, confidence = _verdict(
            path, risk, signature_hit, score, severity, matches
        )

        return Detection(
            path=str(path),
            detection_name=name,
            severity=severity,
            confidence=confidence,
            detection_method=method,
            reason=reason,
            recommended_action=action,
            sha256=sha256,
            file_size=size,
            risk_score=score,
            file_type=file_type,
            factors=risk.factors,
            pe_summary=pe_summary,
            scan_duration=time.monotonic() - started,
        )

    def _analyze_member(self, member_path: Path, risk: RiskEngine) -> None:
        """Analyse an archive member as a child of the parent file."""
        child = self.analyze_path(member_path)
        for factor in child.factors:
            detail = str(factor.get("detail", ""))
            name = str(factor.get("factor", ""))
            if name in {"known_malicious_hash", "eicar_test_file", "yara_rule_match"}:
                risk.force_score(int(factor.get("weight", 70)), name, f"archive member: {detail}")
            else:
                risk.add_factor(name, f"archive member: {detail}", int(factor.get("weight", 0)))


# ---------------------------------------------------------------------------
# Verdict helpers
# ---------------------------------------------------------------------------

def _verdict(path: Path, risk: RiskEngine, signature_hit, score: int,
             severity: str, yara_matches=None):
    """Derive (name, method, reason, action, confidence) from evidence.

    Precedence: exact hash signature (strongest evidence), then YARA
    content rules, then the heuristic score bands. YARA detections get
    their own method and a ``YARA.<RuleName>`` detection name so the
    provenance is visible in the UI and reports (spec section 65).
    """
    if signature_hit:
        reason = signature_hit.description or (
            f"SHA-256 matches known signature '{signature_hit.name}'."
        )
        action = "Quarantine for review."
        confidence = "high"
        return signature_hit.name, "signature", reason, action, confidence

    if yara_matches:
        rule = yara_matches[0]
        strong = rule.severity in {"high", "critical"}
        reason = rule.description or f"YARA rule '{rule.rule}' matched."
        action = ("Quarantine for review." if strong
                  else "Review before allowing.")
        confidence = "high" if strong else "medium"
        return f"YARA.{rule.rule}", "yara", reason, action, confidence

    if score >= 70:
        return ("Suspicious.HighRisk", "heuristic",
                _reason_from(risk, path), "Quarantine for review.", "medium")
    if score >= 40:
        return ("Suspicious.Executable", "heuristic",
                _reason_from(risk, path), "Quarantine for review.", "medium")
    if score >= 20:
        return ("Suspicious.NeedsReview", "heuristic",
                _reason_from(risk, path), "Review before allowing.", "low")
    return ("Clean.File", "none", "No significant risk indicators.",
            "No action required.", "high")


def _reason_from(risk: RiskEngine, path: Path) -> str:
    """Human-readable reason sentence from accumulated factors."""
    lines = risk.summary_lines()
    if not lines:
        return "Heuristic indicators present."
    head = "; ".join(lines[:3])
    more = f" (+{len(lines) - 3} more)" if len(lines) > 3 else ""
    return f"Heuristic indicators: {head}{more}."


def _type_mismatch_note(path: Path) -> Optional[str]:
    """Extension/header mismatch detection (renamed executables)."""
    from engine.hash_engine import type_matches_content

    return type_matches_content(path)


def _apply_pe_indicators(pe_info, path: Path, risk: RiskEngine) -> None:
    """Feed PE indicators into the risk engine as weak heuristics."""
    indicators = pe_info.indicators()
    if indicators["high_entropy_sections"]:
        risk.add_factor(
            "high_entropy_pe_section",
            f"high-entropy sections: {', '.join(indicators['high_entropy_sections'][:2])}",
        )
    if indicators["writable_exec_sections"]:
        risk.add_factor(
            "writable_exec_section",
            f"sections writable+executable: {', '.join(indicators['writable_exec_sections'][:2])}",
        )
    if indicators["suspicious_imports"]:
        risk.add_factor(
            "suspicious_pe_imports",
            f"notable imports: {', '.join(indicators['suspicious_imports'][:3])}",
        )
    if indicators["unsigned"] and is_in_temp(path):
        risk.add_factor("unsigned_new_exe", "unsigned executable in temp location")
    if indicators["no_version_info"]:
        risk.add_factor("no_version_info", "PE lacks version information")


def _pe_indicator_summary(pe_info) -> str:
    """Short PE paragraph for UI technical details."""
    from engine.pe_analyzer import summarize_pe_info

    return summarize_pe_info(pe_info)
