"""Tests for the quarantine system (spec sections 20, 21, 49)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from quarantine.quarantine_manager import QuarantineError, QuarantineManager
from utils.file_utils import sha256_of_file


@pytest.fixture()
def quarantine_manager(temp_dirs, test_database):
    """QuarantineManager bound to temp quarantine storage."""
    return QuarantineManager()


def test_quarantine_moves_and_renames(quarantine_manager, tmp_path):
    """Quarantine moves the file into the vault with a .quar name."""
    target = tmp_path / "malware.exe"
    payload = b"fake malware body"
    target.write_bytes(payload)

    result = quarantine_manager.quarantine_file(
        target, "Test.Malware", severity="high")

    vault = Path(result["quarantine_path"])
    assert not target.exists()
    assert vault.exists()
    assert vault.suffix == ".quar"
    assert vault.parent == Path(result["quarantine_path"]).parent


def test_quarantine_record_fields(quarantine_manager, tmp_path):
    """Records store the spec-required metadata."""
    target = tmp_path / "threat.dll"
    target.write_bytes(b"dll bytes")

    result = quarantine_manager.quarantine_file(
        target, "Trojan.Test", severity="critical", sha256=hashlib.sha256(b"dll bytes").hexdigest())

    record = quarantine_manager.db.get(result["quarantine_id"])
    assert record is not None
    assert record["detection_name"] == "Trojan.Test"
    assert record["severity"] == "critical"
    assert record["status"] == "QUARANTINED"
    assert record["sha256"] == hashlib.sha256(b"dll bytes").hexdigest()
    assert record["original_path"] == str(tmp_path / "threat.dll")
    assert record["file_size"] == len(b"dll bytes")


def test_quarantine_missing_file_raises(quarantine_manager, tmp_path):
    """Missing files raise QuarantineError."""
    with pytest.raises(QuarantineError):
        quarantine_manager.quarantine_file(
            tmp_path / "ghost.exe", "X")


def test_restore_roundtrip(quarantine_manager, tmp_path):
    """Quarantine then restore returns the exact original bytes."""
    target = tmp_path / "restore_me.exe"
    payload = b"original executable content"
    target.write_bytes(payload)

    result = quarantine_manager.quarantine_file(target, "Suspicious.File")
    assert not target.exists()

    restored = quarantine_manager.restore(
        result["quarantine_id"], user_confirmed=True)

    assert restored == target
    assert target.exists()
    assert target.read_bytes() == payload
    record = quarantine_manager.db.get(result["quarantine_id"])
    assert record["status"] == "RESTORED"


def test_restore_requires_confirmation(quarantine_manager, tmp_path):
    """Restore refuses without explicit user confirmation."""
    target = tmp_path / "a.exe"
    target.write_bytes(b"x")
    result = quarantine_manager.quarantine_file(target, "X")

    with pytest.raises(QuarantineError):
        quarantine_manager.restore(result["quarantine_id"],
                                   user_confirmed=False)


def test_delete_requires_confirmation(quarantine_manager, tmp_path):
    """Permanent deletion refuses without explicit confirmation."""
    target = tmp_path / "b.exe"
    target.write_bytes(b"x")
    result = quarantine_manager.quarantine_file(target, "X")

    with pytest.raises(QuarantineError):
        quarantine_manager.delete_permanently(result["quarantine_id"],
                                              user_confirmed=False)


def test_delete_permanently(quarantine_manager, tmp_path):
    """Confirmed deletion removes the vault file and marks DELETED."""
    target = tmp_path / "c.exe"
    target.write_bytes(b"x")
    result = quarantine_manager.quarantine_file(target, "X")
    vault = Path(result["quarantine_path"])
    assert vault.exists()

    quarantine_manager.delete_permanently(result["quarantine_id"],
                                          user_confirmed=True)
    assert not vault.exists()
    record = quarantine_manager.db.get(result["quarantine_id"])
    assert record["status"] == "DELETED"


def test_double_quarantine_of_same_file(quarantine_manager, tmp_path):
    """Re-quarantining after restore works (new record)."""
    target = tmp_path / "d.exe"
    target.write_bytes(b"x")
    first = quarantine_manager.quarantine_file(target, "X")
    quarantine_manager.restore(first["quarantine_id"], user_confirmed=True)
    second = quarantine_manager.quarantine_file(target, "X")
    assert second["quarantine_id"] != first["quarantine_id"]


def test_quarantine_database_listing(quarantine_manager, tmp_path):
    """list_active only shows QUARANTINED records."""
    target = tmp_path / "e.exe"
    target.write_bytes(b"x")
    result = quarantine_manager.quarantine_file(target, "X")
    quarantine_manager.delete_permanently(result["quarantine_id"],
                                          user_confirmed=True)

    ids = [r["quarantine_id"] for r in quarantine_manager.db.list_active()]
    assert result["quarantine_id"] not in ids
