"""Pytest fixtures shared across the LocalGuard test suite.

Sandboxing guarantees (spec section 49 - "test that corrupted files
don't crash the scanner" must never mean "corrupt the developer's
checkout"):

    - Every test is fully sandboxed. All writable application
      locations (database, settings, signatures, quarantine vault,
      logs, reports, per-user app data) are redirected into a
      per-test temporary directory by the autouse
      ``isolate_host_state`` fixture.
    - Singletons (shared Settings, shared Database) are reset around
      every test so no test can observe or pollute another's state,
      and so no singleton can outlive a redirect.
    - Toast notifications cannot spawn PowerShell during tests: the
      session-scoped guard swaps ``utils.notify``'s subprocess access
      for a proxy that blocks Popen (and only Popen) with an error.
    - A session-scoped guard snapshots protected repository files
      (signatures/hashes.json, config/settings.json, the source-tree
      database, logs/, reports/) and fails the run if anything in the
      suite modified them.

What is intentionally still real: modules may read bundled read-only
resources (default_config.json, schema.sql) from the repo - reading is
required for meaningful tests and never mutates anything. The
quarantine ACL tightening (icacls) operates only on files the test
itself created inside its temp vault.
"""

from __future__ import annotations

import subprocess  # noqa: S404 - used only to build the blocking proxy
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.database import Database  # noqa: E402
from utils.settings import Settings  # noqa: E402


# ---------------------------------------------------------------------------
# Session guard 1: repository files must never be modified
# ---------------------------------------------------------------------------

_PROTECTED_REPO_PATHS = (
    PROJECT_ROOT / "signatures" / "hashes.json",
    PROJECT_ROOT / "config" / "settings.json",
    PROJECT_ROOT / "database" / "localguard.db",
    PROJECT_ROOT / "logs",
    PROJECT_ROOT / "reports",
)


def _snapshot_state() -> Dict[Path, Any]:
    """mtime (or existence) fingerprint of each protected path."""
    state: Dict[Path, Any] = {}
    for target in _PROTECTED_REPO_PATHS:
        try:
            state[target] = target.stat().st_mtime_ns
        except OSError:
            state[target] = None  # does not exist (yet)
    return state


@pytest.fixture(scope="session", autouse=True)
def repo_write_guard():
    """Fail the whole session if any test modified repository files."""
    before = _snapshot_state()
    yield
    after = _snapshot_state()
    changed = [
        str(path) for path, mtime in after.items() if mtime != before[path]
    ]
    assert not changed, (
        "TEST SANDBOX VIOLATION - tests modified repository files: "
        + ", ".join(changed)
    )


# ---------------------------------------------------------------------------
# Session guard 2: no process spawning from the notification layer
# ---------------------------------------------------------------------------

class _BlockedSubprocess:
    """Proxy around :mod:`subprocess` that blocks Popen for one module.

    Only ``utils.notify`` may be affected; every other attribute is
    delegated to the real module so unrelated code keeps working.
    """

    def __init__(self, real: Any) -> None:
        self._real = real

    def Popen(self, *args: Any, **kwargs: Any) -> None:  # noqa: N802
        raise AssertionError(
            "TEST SANDBOX VIOLATION - utils.notify attempted to spawn a "
            "process during tests (PowerShell toast notification)"
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


@pytest.fixture(scope="session", autouse=True)
def block_notify_spawning():
    """Make ``utils.notify`` unable to spawn PowerShell for the session."""
    import utils.notify as notify_module

    original = notify_module.subprocess
    notify_module.subprocess = _BlockedSubprocess(subprocess)
    yield
    notify_module.subprocess = original


# ---------------------------------------------------------------------------
# Per-test sandbox: redirect every writable location into tmp
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolate_host_state(tmp_path, monkeypatch) -> Dict[str, Path]:
    """Redirect all writable application directories into *tmp_path*.

    Runs before every test (autouse) so that no test - and no module
    the test exercises - can write into the repository or the real
    per-user application data directory.
    """
    logs = tmp_path / "logs"
    reports = tmp_path / "reports"
    quarantine = tmp_path / "quarantine"
    signatures = tmp_path / "signatures"
    yara_rules = signatures / "yara"
    database = tmp_path / "database"
    appdata = tmp_path / "appdata"
    appdata_config = appdata / "config"
    for directory in (logs, reports, quarantine, signatures, yara_rules,
                      database, appdata, appdata_config):
        directory.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr("utils.paths.app_data_dir", lambda: appdata)
    monkeypatch.setattr("utils.paths.logs_dir", lambda: logs)
    monkeypatch.setattr("utils.paths.log_file_path",
                        lambda: logs / "localguard.log")
    monkeypatch.setattr("utils.paths.reports_dir", lambda: reports)
    monkeypatch.setattr("utils.paths.quarantine_dir", lambda: quarantine)
    monkeypatch.setattr("utils.paths.signatures_dir", lambda: signatures)
    monkeypatch.setattr("utils.paths.hashes_signature_path",
                        lambda: signatures / "hashes.json")
    monkeypatch.setattr("utils.paths.yara_rules_dir", lambda: yara_rules)
    monkeypatch.setattr("utils.paths.database_path",
                        lambda: database / "localguard.db")
    monkeypatch.setattr("utils.paths.settings_path",
                        lambda: appdata_config / "settings.json")

    # Reset singletons while the redirect is active so anything created
    # during the test binds to the sandboxed paths.
    import database.database as database_module
    import utils.settings as settings_module

    settings_module._shared = None
    database_module.reset_shared()

    sandbox = {
        "tmp": tmp_path,
        "logs": logs,
        "reports": reports,
        "quarantine": quarantine,
        "signatures": signatures,
        "database": database,
        "appdata": appdata,
    }
    yield sandbox

    # Drop singletons again before patches unwind, so no stale object
    # can carry a sandboxed path into the next test.
    settings_module._shared = None
    database_module.reset_shared()


# ---------------------------------------------------------------------------
# Domain fixtures (all build on the sandbox)
# ---------------------------------------------------------------------------

@pytest.fixture()
def temp_dirs(isolate_host_state) -> Dict[str, Path]:
    """Back-compat alias for the sandbox directory mapping."""
    return isolate_host_state


@pytest.fixture()
def test_database(tmp_path, monkeypatch):
    """Isolated Database instance over a temp file."""
    db_path = tmp_path / "test_localguard.db"
    monkeypatch.setattr("utils.paths.database_path", lambda: db_path)
    from database.database import reset_shared

    reset_shared()
    database = Database(db_path)
    yield database
    database.close()
    reset_shared()


@pytest.fixture()
def test_settings(tmp_path, monkeypatch):
    """Isolated Settings instance installed as the shared singleton.

    Installing (not just creating) matters: production code reads
    settings through ``get_settings()`` (e.g. the notification layer),
    which returns the module-level singleton. Without installation, a
    singleton created by an earlier test's notify call could serve
    stale in-memory state to later tests - an ordering-dependent race
    seen on CI. Restored to None on teardown so the next sandbox
    rebuilds it against its own paths.
    """
    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr("utils.paths.settings_path", lambda: settings_path)
    import utils.settings as settings_module

    settings_module._shared = None  # force re-creation
    settings = Settings(settings_path)
    settings_module._shared = settings
    yield settings
    settings_module._shared = None


@pytest.fixture()
def signature_engine(test_database, tmp_path, monkeypatch):
    """SignatureEngine wired to the isolated database and a temp
    signature file (never touches the repo's real hashes.json)."""
    from engine.signature_engine import SignatureEngine

    monkeypatch.setattr(
        "utils.paths.hashes_signature_path",
        lambda: tmp_path / "hashes.json")

    return SignatureEngine(database=test_database)


@pytest.fixture()
def analyzer(signature_engine):
    """FileAnalyzer with caching disabled for determinism."""
    from engine.file_analyzer import FileAnalyzer

    return FileAnalyzer(signature_engine=signature_engine, hash_cache=False,
                        scan_archives=True)
