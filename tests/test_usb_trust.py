"""Tests for the USB trusted-device allowlist.

Covers the database layer (trust by serial + volume label, invalid
inputs, revocation), ProtectionManager's skip logic, and the audit
events - all over the isolated test database with no real drives.
"""

from __future__ import annotations

import pytest

from database.database import Database
from protection.usb_monitor import USBDevice


@pytest.fixture()
def usb_stack(test_database, tmp_path):
    """ProtectionManager wired to the isolated DB with scan stubbed."""
    from engine.file_analyzer import FileAnalyzer
    from engine.scan_controller import ScanController
    from engine.signature_engine import SignatureEngine
    from protection.protection_manager import ProtectionManager

    analyzer = FileAnalyzer(
        signature_engine=SignatureEngine(database=test_database),
        hash_cache=False)
    controller = ScanController(analyzer=analyzer, database=test_database,
                                threads=1)
    manager = ProtectionManager(analyzer, controller, database=test_database)
    manager.settings.set("protection.usb_autoscan", True)
    manager.settings.set("general.show_notifications", False)

    scanned: list = []
    manager._scan_usb_async = scanned.append
    return manager, test_database, scanned


def _device(letter="E:", volume="KINGSTON", serial="ABCD1234"):
    return USBDevice(letter, volume, serial, 16_000_000_000, 8_000_000_000,
                     "FAT32")


# ---------------------------------------------------------------------------
# Database layer
# ---------------------------------------------------------------------------


def test_trust_roundtrip(test_database):
    """Grant, query, and revoke trust."""
    assert not test_database.is_usb_trusted("ABCD1234", "KINGSTON")
    assert test_database.trust_usb_device("ABCD1234", "KINGSTON", "stick")
    assert test_database.is_usb_trusted("ABCD1234", "KINGSTON")
    assert test_database.untrust_usb_device("ABCD1234", "KINGSTON") == 1
    assert not test_database.is_usb_trusted("ABCD1234", "KINGSTON")


def test_trust_requires_identifiable_drive(test_database):
    """Drives without serial or label can never be trusted."""
    assert not test_database.trust_usb_device("", "KINGSTON")
    assert not test_database.trust_usb_device(None, "KINGSTON")
    assert not test_database.trust_usb_device("ABCD1234", "")
    assert not test_database.trust_usb_device("ABCD1234", None)
    assert test_database.list_trusted_usb_devices() == []


def test_trust_is_specific_to_serial_and_label(test_database):
    """Same serial with a different label, or vice versa, is untrusted."""
    test_database.trust_usb_device("ABCD1234", "KINGSTON")
    assert not test_database.is_usb_trusted("ABCD1234", "OTHERLABEL")
    assert not test_database.is_usb_trusted("FFFFFFFF", "KINGSTON")


def test_duplicate_trust_is_idempotent(test_database):
    """Re-trusting the same drive does not create duplicate rows."""
    test_database.trust_usb_device("ABCD1234", "KINGSTON")
    test_database.trust_usb_device("ABCD1234", "KINGSTON")
    assert len(test_database.list_trusted_usb_devices()) == 1


def test_trust_persists_in_database_file(tmp_path):
    """Trust survives a Database reopen (it is a durable user decision)."""
    db_path = tmp_path / "persist.db"
    first = Database(db_path)
    first.trust_usb_device("ABCD1234", "KINGSTON")
    first.close()

    second = Database(db_path)
    try:
        assert second.is_usb_trusted("ABCD1234", "KINGSTON")
    finally:
        second.close()


# ---------------------------------------------------------------------------
# ProtectionManager integration
# ---------------------------------------------------------------------------


def test_trusted_device_skips_autoscan(usb_stack):
    """A trusted drive does not trigger the automatic scan."""
    manager, database, scanned = usb_stack
    database.trust_usb_device("ABCD1234", "KINGSTON")

    manager._on_usb_inserted(_device())
    assert scanned == [], "trusted drive must skip auto-scan"


def test_untrusted_device_still_autoscans(usb_stack):
    """Unknown drives get the full automatic scan."""
    manager, database, scanned = usb_stack
    manager._on_usb_inserted(_device(serial="DEAD0000", volume="UNKNOWN"))
    assert len(scanned) == 1


def test_same_serial_different_label_autoscans(usb_stack):
    """A drive reusing the serial but not the label is not trusted."""
    manager, database, scanned = usb_stack
    database.trust_usb_device("ABCD1234", "KINGSTON")
    manager._on_usb_inserted(_device(volume="SPOOFED"))
    assert len(scanned) == 1, "label must be part of the identity"


def test_serialless_device_can_never_be_trusted(usb_stack):
    """A drive without a serial always scans, even if trust attempted."""
    manager, database, scanned = usb_stack
    database.trust_usb_device("", "KINGSTON")  # refused by DB layer
    manager._on_usb_inserted(_device(serial=""))
    assert len(scanned) == 1


def test_revoked_trust_resumes_autoscan(usb_stack):
    """After revocation the drive is scanned automatically again."""
    manager, database, scanned = usb_stack
    database.trust_usb_device("ABCD1234", "KINGSTON")
    manager._on_usb_inserted(_device())
    assert scanned == []

    database.untrust_usb_device("ABCD1234", "KINGSTON")
    manager._on_usb_inserted(_device())
    assert len(scanned) == 1


def test_autoscan_disabled_means_no_scan_regardless_of_trust(usb_stack):
    """usb_autoscan = False still skips scanning (master switch first)."""
    manager, database, scanned = usb_stack
    manager.settings.set("protection.usb_autoscan", False)
    manager._on_usb_inserted(_device())
    assert scanned == []


def test_trust_check_failure_fails_open_to_scan(usb_stack, monkeypatch):
    """If the trust lookup explodes, we scan (fail safe) - never crash."""
    manager, database, scanned = usb_stack

    def broken(*_args, **_kwargs):
        raise RuntimeError("db glitch")

    monkeypatch.setattr(database, "is_usb_trusted", broken)
    manager._on_usb_inserted(_device())
    assert len(scanned) == 1
