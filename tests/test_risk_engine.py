"""Tests for risk scoring and severity bands (spec section 16)."""

from __future__ import annotations

import pytest

from engine.risk_engine import FACTOR_WEIGHTS, RiskEngine, severity_for_score


def test_empty_risk_is_low():
    """No factors -> clean/low."""
    risk = RiskEngine()
    result = risk.evaluate()
    assert result.score == 0
    assert result.severity == "low"
    assert result.is_clean


def test_suspicious_band():
    """Scores 20-39 map to SUSPICIOUS."""
    risk = RiskEngine()
    risk.add_factor("double_extension")          # 25
    result = risk.evaluate()
    assert 20 <= result.score < 40
    assert result.is_suspicious
    assert severity_for_score(result.score) == "medium"


def test_high_band():
    """Scores 40-69 map to HIGH RISK."""
    risk = RiskEngine()
    risk.add_factor("executable_in_temp")   # 30
    risk.add_factor("double_extension")     # 25
    result = risk.evaluate()
    assert 40 <= result.score < 70
    assert result.is_high


def test_critical_band():
    """Scores >= 70 map to CRITICAL."""
    risk = RiskEngine()
    risk.add_factor("executable_in_temp")        # 30
    risk.add_factor("double_extension")          # 25
    risk.add_factor("suspicious_script_content") # 30
    result = risk.evaluate()
    assert result.score >= 70
    assert result.is_critical


def test_heuristic_cap():
    """Heuristic accumulation is capped below 100."""
    risk = RiskEngine()
    for _ in range(20):
        risk.add_factor("executable_in_temp")
    result = risk.evaluate()
    assert result.score <= 95


def test_unknown_factor_ignored():
    """Unknown factor names are silently skipped."""
    risk = RiskEngine()
    risk.add_factor("not_a_real_factor")
    assert risk.score == 0


def test_force_score_signature():
    """Signature matches force the score directly."""
    risk = RiskEngine()
    risk.force_score(100, "known_malicious_hash", "Test.Malware")
    result = risk.evaluate()
    assert result.score == 100
    assert result.is_critical


def test_factor_details_preserved():
    """Details and weights are kept for UI display."""
    risk = RiskEngine()
    risk.add_factor("double_extension", "invoice.pdf.exe")
    lines = risk.summary_lines()
    assert any("invoice.pdf.exe" in line for line in lines)


def test_all_weights_positive():
    """All defined factor weights are positive integers."""
    for name, weight in FACTOR_WEIGHTS.items():
        assert weight > 0, f"factor {name} must have positive weight"
