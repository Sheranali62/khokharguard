"""LocalGuard Antivirus - path resolution utilities.

Resolves filesystem locations for data, configuration, signatures,
quarantine, logs, and reports. Supports running from source and from a
PyInstaller-frozen executable. Uses environment variables and Windows
APIs rather than hardcoded usernames or drive letters.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "LocalGuard"
APP_DIR_NAME = "LocalGuard"


def is_frozen() -> bool:
    """Return True when running from a PyInstaller bundle."""
    return getattr(sys, "frozen", False)


def bundled_data_dir() -> Path:
    """Directory containing read-only bundled data (signatures, schema).

    In a PyInstaller one-file build this is the temp extraction dir
    (``sys._MEIPASS``); from source it is the project root.
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass and Path(meipass).is_dir():
        return Path(meipass)
    return project_root()


def project_root() -> Path:
    """Project root when running from source."""
    return Path(__file__).resolve().parent.parent


def executable_dir() -> Path:
    """Directory of the running executable (or main.py from source)."""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return project_root()


def app_data_dir() -> Path:
    """Writable per-user application data directory.

    Windows: ``%LOCALAPPDATA%\\LocalGuard`` with a fallback to the
    user profile when the variable is missing (e.g. odd environments).
    """
    local_app_data = os.environ.get("LOCALAPPDATA")
    base = Path(local_app_data) if local_app_data else (Path.home() / "AppData" / "Local")
    path = base / APP_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_dir() -> Path:
    """Directory holding settings.json when running from source."""
    if is_frozen():
        return app_data_dir() / "config"
    return project_root() / "config"


def database_path() -> Path:
    """Path of the main SQLite database file."""
    if is_frozen():
        return app_data_dir() / "localguard.db"
    return project_root() / "database" / "localguard.db"


def schema_path() -> Path:
    """Path of schema.sql (bundled read-only resource)."""
    return bundled_data_dir() / "database" / "schema.sql"


def signatures_dir() -> Path:
    """Writable signatures directory (updates land here)."""
    if is_frozen():
        path = app_data_dir() / "signatures"
        path.mkdir(parents=True, exist_ok=True)
        # Seed bundled signatures on first run
        bundled = bundled_data_dir() / "signatures" / "hashes.json"
        target = path / "hashes.json"
        if bundled.is_file() and not target.exists():
            try:
                target.write_bytes(bundled.read_bytes())
            except OSError:
                pass
        return path
    return project_root() / "signatures"


def hashes_signature_path() -> Path:
    """Path of the hash signature database file."""
    return signatures_dir() / "hashes.json"


def yara_rules_dir() -> Path:
    """Writable YARA rules directory."""
    path = signatures_dir() / "yara"
    path.mkdir(parents=True, exist_ok=True)
    bundled = bundled_data_dir() / "signatures" / "yara"
    if bundled.is_dir():
        for rule in bundled.glob("*.yar"):
            target = path / rule.name
            if not target.exists():
                try:
                    target.write_bytes(rule.read_bytes())
                except OSError:
                    pass
    return path


def quarantine_dir() -> Path:
    """Secure quarantine storage directory."""
    path = app_data_dir() / "quarantine"
    path.mkdir(parents=True, exist_ok=True)
    return path


def logs_dir() -> Path:
    """Writable logs directory."""
    if is_frozen():
        path = app_data_dir() / "logs"
    else:
        path = project_root() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def log_file_path() -> Path:
    """Path of the main log file: logs/localguard.log."""
    return logs_dir() / "localguard.log"


def reports_dir() -> Path:
    """Writable reports directory."""
    if is_frozen():
        path = app_data_dir() / "reports"
    else:
        path = project_root() / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_config_path() -> Path:
    """Path of bundled default configuration."""
    return bundled_data_dir() / "config" / "default_config.json"


def settings_path() -> Path:
    """Path of the user-editable settings file."""
    return config_dir() / "settings.json"


def version() -> str:
    """Application version string."""
    try:
        return (bundled_data_dir() / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return "0.0.0"
