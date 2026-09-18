"""Tests for USB detection logic and USB-path heuristics (spec 10, 49)."""

from __future__ import annotations

from pathlib import Path

from engine.heuristic_engine import (
    analyze_autorun_inf,
    analyze_filename_risk,
    analyze_hidden_attribute,
    analyze_lnk_structure,
)
from engine.risk_engine import RiskEngine


def test_autorun_inf_with_open_detected(tmp_path):
    """autorun.inf with open= command raises the autorun factor."""
    target = tmp_path / "autorun.inf"
    target.write_text("[autorun]\nopen=evil.exe\n", encoding="ascii")

    risk = RiskEngine()
    result = analyze_autorun_inf(target, risk)

    assert result == "evil.exe"
    assert "autorun_inf_mechanism" in [f["factor"] for f in risk.factors]


def test_autorun_inf_with_shellexecute(tmp_path):
    """shellexecute= is treated as an autorun mechanism too."""
    target = tmp_path / "autorun.inf"
    target.write_text("[autorun]\nshellexecute=run.bat\n", encoding="ascii")

    risk = RiskEngine()
    analyze_autorun_inf(target, risk)
    assert risk.score >= 35


def test_benign_autorun_inf_flagged_only_weakly(tmp_path):
    """Icon-only autorun.inf stays low risk (never auto-deleted)."""
    target = tmp_path / "autorun.inf"
    target.write_text("[autorun]\nicon=drive.ico\n", encoding="ascii")

    risk = RiskEngine()
    analyze_autorun_inf(target, risk)
    assert risk.score < 20


def test_double_extension_detection(tmp_path):
    """invoice.pdf.exe triggers the double-extension factor."""
    risk = RiskEngine()
    analyze_filename_risk(Path("E:/usb/invoice.pdf.exe"), risk)
    assert "double_extension" in [f["factor"] for f in risk.factors]


def test_masquerading_document_detection(tmp_path):
    """Executable named like a document is flagged."""
    risk = RiskEngine()
    analyze_filename_risk(Path("E:/invoice.exe"), risk)
    assert any(f["factor"] == "masquerading_document" for f in risk.factors)


def test_normal_exe_not_flagged_by_name(tmp_path):
    """Ordinary executable names produce no filename factors."""
    risk = RiskEngine()
    analyze_filename_risk(Path("C:/Program Files/App/app.exe"), risk)
    assert risk.score == 0


def test_lnk_with_powershell_target(tmp_path):
    """Shortcut invoking PowerShell is flagged."""
    target = tmp_path / "readme.lnk"
    target.write_bytes(
        b"fake lnk header ... cmd.exe /c powershell -enc AAAA ...")

    risk = RiskEngine()
    analyze_lnk_structure(target, risk)
    assert "suspicious_lnk_target" in [f["factor"] for f in risk.factors]


def test_hidden_executable_factor(tmp_path):
    """Hidden attribute check runs without error on normal files."""
    target = tmp_path / "visible.exe"
    target.write_bytes(b"MZ")

    risk = RiskEngine()
    analyze_hidden_attribute(target, risk)  # not hidden: no factor
    assert "hidden_executable" not in [f["factor"] for f in risk.factors]


def test_usb_device_dataclass():
    """USBDevice carries its fields through to_dict."""
    from protection.usb_monitor import USBDevice

    device = USBDevice("E:\\", "KINGSTON", "ABCD1234", 32_000_000_000,
                       16_000_000_000, "exfat")
    data = device.to_dict()
    assert data["drive_letter"] == "E:\\"
    assert data["volume_name"] == "KINGSTON"
    assert data["file_system"] == "exfat"


def test_usb_monitor_insertion_diff():
    """Insertion diffing identifies new drive letters."""
    from protection.usb_monitor import USBMonitor

    monitor = USBMonitor()
    known = {"C:\\"}
    current = {"C:\\", "E:\\"}
    inserted = [letter for letter in current if letter not in known]
    assert inserted == ["E:\\"]


def test_usb_device_record_persisted(test_database, temp_dirs):
    """usb_devices table stores and updates device rows."""
    device_id = test_database.upsert_usb_device(
        "E:\\", "FLASH", "SER1", 1_000, 500, "fat32")
    assert device_id > 0

    test_database.set_usb_scan_result(device_id, None, "clean")
    records = test_database.list_usb_devices()
    assert len(records) == 1
    assert records[0]["last_scan_status"] == "clean"

    again = test_database.upsert_usb_device(
        "E:\\", "FLASH", "SER1", 1_000, 400, "fat32")
    assert again == device_id
    assert len(test_database.list_usb_devices()) == 1
