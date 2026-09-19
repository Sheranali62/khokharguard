"""Tests for the background protection service: IPC protocol, headless
core lifecycle, and control-layer discovery.

All tests bind to loopback ephemeral ports and use sandboxed temp
directories (tests/conftest.py); no real Windows service is touched.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from typing import Any, Dict

import pytest

from services.windows_service import (
    IPC_METHODS,
    ProtectionServiceCore,
    ServiceIPCClient,
    ServiceIPCError,
    ServiceIPCServer,
    read_token_file,
    remove_token_file,
    token_file_path,
    write_token_file,
)


def _free_port() -> int:
    """Grab a free loopback port for a server instance."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture()
def ipc_server():
    """A running IPC server on an ephemeral port with echo handlers."""
    server = ServiceIPCServer(
        {
            "status": lambda params: {"ok": True, "method": "status"},
            "pause": lambda params: {"ok": True, "paused": True},
            "resume": lambda params: {"ok": True, "paused": False},
            "apply_settings": lambda params: {"ok": True},
            "shutdown": lambda params: {"ok": True},
        },
        token="test-token-123",
    )
    assert server.start()
    yield server
    server.stop()


@pytest.fixture()
def client(ipc_server):
    """Client wired to the fixture server's token and port."""
    return ServiceIPCClient(port=ipc_server.port, token=ipc_server.token)


# ---------------------------------------------------------------------------
# IPC protocol
# ---------------------------------------------------------------------------


def test_method_allowlist_is_fixed():
    """The IPC surface is a fixed allow-list - no arbitrary dispatch."""
    assert IPC_METHODS == ("status", "pause", "resume",
                           "apply_settings", "shutdown",
                           "recent_findings", "get_history",
                           "quarantine_restore", "quarantine_delete")


def test_roundtrip_authenticated_call(client):
    """A valid call reaches the handler and returns its result."""
    response = client.call("status")
    assert response == {"ok": True, "method": "status"}


def test_wrong_token_rejected(ipc_server):
    """A request with a bad token is refused."""
    attacker = ServiceIPCClient(port=ipc_server.port,
                                token="not-the-right-token")
    response = attacker.call("status")
    assert response == {"error": "unauthorized"}


def test_missing_token_rejected(ipc_server):
    """A tokenless request is refused."""
    attacker = ServiceIPCClient(port=ipc_server.port, token="")
    assert attacker.call("status") == {"error": "unauthorized"}


def test_unknown_method_rejected(client):
    """Methods outside the allow-list are refused."""
    response = client.call("delete_everything")
    assert response == {"error": "unknown method"}


def test_malformed_payload_returns_error(ipc_server):
    """Garbage bytes get a clean JSON error, never a crash."""
    response = json.loads(
        ipc_server.handle_payload(b"\x00\x01 not json \n"))
    assert response == {"error": "bad json"}
    # Non-dict JSON is also refused.
    response = json.loads(ipc_server.handle_payload(b"[1,2,3]\n"))
    assert response == {"error": "bad json"}


def test_non_dict_params_rejected(client):
    """A non-object params value is refused before dispatch."""
    # call() always sends an object, so craft the payload manually.
    import json as jsonlib

    payload = jsonlib.dumps({
        "token": client.token, "method": "status", "params": [1, 2],
    }).encode() + b"\n"

    import socket as sock_mod

    with sock_mod.create_connection((client.host, client.port),
                                    timeout=5) as sock:
        sock.sendall(payload)
        buffer = b""
        while b"\n" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer += chunk
    assert jsonlib.loads(buffer.decode()) == {"error": "bad params"}


def test_handler_exception_reported_not_crashing(ipc_server):
    """A raising handler produces an error response; server survives."""

    def boom(params: Dict[str, Any]) -> Dict[str, Any]:
        """Always fails."""
        raise RuntimeError("handler exploded")

    ipc_server.handlers["status"] = boom
    client = ServiceIPCClient(port=ipc_server.port,
                              token=ipc_server.token)
    assert "handler exploded" in client.call("status")["error"]
    # Server still healthy for a good handler.
    ipc_server.handlers["status"] = lambda p: {"ok": True}
    assert client.call("status") == {"ok": True}


def test_concurrent_calls_are_independent(ipc_server):
    """Parallel clients each get their own correct response."""
    client = ServiceIPCClient(port=ipc_server.port,
                              token=ipc_server.token)
    results: list = []
    errors: list = []

    def worker(index: int) -> None:
        """One concurrent caller."""
        try:
            for _ in range(5):
                response = client.call("status", timeout=10)
                assert response.get("ok") is True
            results.append(index)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    assert len(results) == 6


def test_oversized_request_capped(ipc_server):
    """A request beyond the size cap is refused with a clear error."""
    import socket as sock_mod

    junk = b'{"token": "' + b"A" * (80 * 1024) + b'"}\n'
    with sock_mod.create_connection((ipc_server.host, ipc_server.port),
                                    timeout=5) as sock:
        sock.sendall(junk)
        buffer = b""
        while b"\n" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer += chunk
    assert b"request too large" in buffer


def test_oversized_payload_via_handle(ipc_server):
    """handle_payload itself enforces nothing (socket layer caps), but
    huge valid JSON still round-trips or errors cleanly."""
    response = json.loads(
        ipc_server.handle_payload(json.dumps({
            "token": ipc_server.token, "method": "status",
            "params": {"blob": "x" * 1000},
        }).encode() + b"\n"))
    assert response.get("ok") is True


def test_start_fails_when_port_taken(ipc_server):
    """A second server on an occupied port reports failure cleanly."""
    import socket as sock_mod

    # Occupy a specific port with a plain socket.
    blocker = sock_mod.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]

    server = ServiceIPCServer({}, token="t", port=port)
    try:
        assert server.start() is False
        assert server.running is False
    finally:
        blocker.close()


# ---------------------------------------------------------------------------
# Token file discovery
# ---------------------------------------------------------------------------


def test_token_file_roundtrip(tmp_path, monkeypatch):
    """write/read/remove of the discovery file."""
    import services.windows_service as ws

    target = tmp_path / "service_token.json"
    monkeypatch.setattr(ws, "token_file_path", lambda: target)
    monkeypatch.setattr(ws.paths.app_data_dir, "__self__",
                        ws.paths.app_data_dir) if False else None

    write_token_file("tok", 12345, 999)
    info = read_token_file()
    assert info == {"token": "tok", "port": 12345, "pid": 999,
                    "host": "127.0.0.1"}
    remove_token_file()
    assert read_token_file() is None


def test_token_file_missing_returns_none(tmp_path, monkeypatch):
    """A missing discovery file reads as None."""
    import services.windows_service as ws

    monkeypatch.setattr(ws, "token_file_path",
                        lambda: tmp_path / "absent.json")
    assert read_token_file() is None


def test_token_file_corrupt_returns_none(tmp_path, monkeypatch):
    """A corrupt discovery file reads as None (never raises)."""
    import services.windows_service as ws

    target = tmp_path / "bad.json"
    target.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(ws, "token_file_path", lambda: target)
    assert read_token_file() is None


# ---------------------------------------------------------------------------
# Headless protection core
# ---------------------------------------------------------------------------


@pytest.fixture()
def service_core():
    """A ProtectionServiceCore on an ephemeral port, with monitoring
    disabled so the test is fast and side-effect free.

    Ephemeral port: reusing the fixed default across tests collides
    with Windows TIME_WAIT on quick successive binds.
    """
    from utils.settings import get_settings

    settings = get_settings()
    settings.set("protection.realtime_enabled", False)
    settings.set("protection.usb_autoscan", False)

    core = ProtectionServiceCore(port=0)
    core.start()
    yield core
    core.stop()


def test_core_start_publishes_token_and_status(service_core):
    """A running core publishes its token file and answers status."""
    info = read_token_file()
    assert info is not None
    assert info["port"] == service_core.ipc.port

    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    status = client.call("status")
    assert status["service"] == "running"
    assert status["version"]
    assert status["paused"] is False


def test_core_pause_resume_via_ipc(service_core):
    """Pause/resume round-trip through the IPC surface."""
    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    assert client.call("pause")["paused"] is True
    assert client.call("status")["paused"] is True
    assert client.call("resume")["paused"] is False


def test_core_shutdown_via_ipc(service_core):
    """The shutdown command stops the core cleanly."""
    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    assert client.call("shutdown") == {"ok": True}
    # run_forever-style loop exit is cooperative; the stop event is set.
    assert service_core._stop_event.is_set()
    # Token file removed on stop.
    service_core.stop()
    assert read_token_file() is None


def test_core_stop_is_idempotent(service_core):
    """Stopping twice does not raise."""
    service_core.stop()
    service_core.stop()
    assert service_core.protection is None


def test_core_records_service_events(service_core):
    """Start/stop land in the security event log."""
    database = service_core.database  # stop() clears the attribute
    events = database.list_events(limit=10)
    kinds = [e["event_type"] for e in events]
    assert "service_started" in kinds
    service_core.stop()
    events = database.list_events(limit=10)
    assert "service_stopped" in [e["event_type"] for e in events]


def test_core_refuses_second_instance(service_core):
    """A second core on the same port fails cleanly (port in use)."""
    from utils.settings import get_settings

    get_settings().set("protection.realtime_enabled", False)
    get_settings().set("protection.usb_autoscan", False)

    second = ProtectionServiceCore(port=service_core.ipc.port)
    with pytest.raises(ServiceIPCError):
        second.start()
    second.stop()  # must be safe even though start failed


# ---------------------------------------------------------------------------
# Control layer (services.service_control)
# ---------------------------------------------------------------------------


def test_discovery_reaches_live_core(service_core, monkeypatch):
    """is_service_protection_active() finds a live core via IPC."""
    from services import service_control

    monkeypatch.setattr(service_control, "service_running",
                        lambda: False)  # no real SCM service
    assert service_control.is_service_protection_active() is True


def test_discovery_false_without_token(monkeypatch):
    """No token file means no background protection."""
    import services.windows_service as ws
    from services import service_control

    monkeypatch.setattr(ws, "read_token_file", lambda: None)
    monkeypatch.setattr(service_control, "service_running",
                        lambda: False)
    assert service_control.is_service_protection_active() is False


def test_discovery_false_with_stale_token(monkeypatch, tmp_path):
    """A token file pointing at a dead port reads as inactive."""
    import services.windows_service as ws
    from services import service_control

    monkeypatch.setattr(ws, "read_token_file",
                        lambda: {"token": "x", "port": 1, "pid": 1,
                                 "host": "127.0.0.1"})
    monkeypatch.setattr(service_control, "service_running", lambda: False)
    assert service_control.is_service_protection_active() is False


def test_send_command_wraps_errors(monkeypatch):
    """IPC failures surface as ServiceControlError."""
    from services import service_control
    import services.windows_service as ws

    monkeypatch.setattr(ws, "read_token_file",
                        lambda: {"token": "x", "port": 1, "pid": 1,
                                 "host": "127.0.0.1"})
    with pytest.raises(service_control.ServiceControlError):
        service_control.send_command("status")


def test_service_lifecycle_errors_on_non_windows(monkeypatch):
    """Lifecycle helpers refuse to run off-Windows (simulated)."""
    from services import service_control

    monkeypatch.setattr(service_control.sys, "platform", "win32")
    # On a real Windows box these contact the SCM; simulate absence.
    monkeypatch.setattr(service_control, "pywin32_available",
                        lambda: False)
    with pytest.raises(service_control.ServiceControlError):
        service_control.install_service()


def test_stale_token_cleanup(monkeypatch, tmp_path):
    """cleanup_stale_token_file removes a file with a dead pid."""
    import services.windows_service as ws
    from services import service_control

    removed: list = []
    monkeypatch.setattr(ws, "read_token_file",
                        lambda: {"token": "x", "port": 1,
                                 "pid": 2 ** 28,  # implausibly dead
                                 "host": "127.0.0.1"})
    monkeypatch.setattr(ws, "remove_token_file",
                        lambda: removed.append(1))
    service_control.cleanup_stale_token_file()
    assert removed


# ---------------------------------------------------------------------------
# Findings streaming (service -> GUI) and remote history
# ---------------------------------------------------------------------------


def _fake_detection(**overrides: Any):
    """A Detection instance without running any analysis code."""
    from dataclasses import replace

    from engine.file_analyzer import Detection

    base = Detection(
        path=r"C:\Users\me\Downloads\sample.exe",
        detection_name="YARA.LocalGuard_Script_Download_Cradle",
        severity="high",
        confidence="high",
        detection_method="yara",
        reason="YARA rule matched",
        recommended_action="Quarantine for review.",
        sha256="ab" * 32,
        file_size=1234,
        risk_score=100,
    )
    return replace(base, **overrides) if overrides else base


def test_recent_findings_streams_and_sequences(service_core):
    """_on_threat records sequenced findings retrievable by watermark."""
    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    service_core._on_threat(_fake_detection())
    service_core._on_threat(_fake_detection(
        path=r"C:\Users\me\Downloads\other.exe"))

    response = client.call("recent_findings", {"since_seq": 0})
    findings = response["findings"]
    assert len(findings) == 2
    seqs = [f["seq"] for f in findings]
    assert seqs == sorted(seqs) and len(set(seqs)) == 2
    assert findings[0]["detection"]["detection_method"] == "yara"
    assert response["last_seq"] == seqs[-1]

    # Watermark: only newer findings come back.
    response2 = client.call("recent_findings", {"since_seq": seqs[-1]})
    assert response2["findings"] == []
    assert response2["last_seq"] == seqs[-1]

    service_core._on_threat(_fake_detection(path=fr"C:\x\new.exe"))
    response3 = client.call("recent_findings", {"since_seq": seqs[-1]})
    assert len(response3["findings"]) == 1


def test_recent_findings_buffer_is_bounded(service_core):
    """The buffer keeps only the most recent findings."""
    for index in range(150):
        service_core._on_threat(
            _fake_detection(path=fr"C:\x\{index}.exe"))
    assert len(service_core._findings) == 100
    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    response = client.call("recent_findings", {"since_seq": 0})
    assert len(response["findings"]) == 100
    assert response["last_seq"] == 150


def test_findings_poll_suppresses_service_notifications(service_core, monkeypatch):
    """While a GUI polls, the service does not also pop a notification."""
    import utils.notify as notify_module

    sent: list = []
    monkeypatch.setattr(notify_module, "notify",
                        lambda *a, **k: sent.append(a))
    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    client.call("recent_findings", {"since_seq": 0})  # GUI poll
    service_core._on_threat(_fake_detection())
    assert sent == []  # suppressed: GUI is consuming

    # Simulate a long-closed GUI (poll window expired).
    service_core._last_gui_poll -= 30.0
    service_core._on_threat(_fake_detection(path=fr"C:\x\late.exe"))
    assert len(sent) == 1


def test_findings_persist_to_service_database(service_core):
    """Threats raised at the service still land in its database."""
    service_core._on_threat(_fake_detection())
    threats = service_core.database.list_threats()
    assert len(threats) == 1
    assert threats[0]["detection_name"].startswith("YARA.")
    assert threats[0]["source"] == "realtime"


def test_get_history_returns_scans_and_threats(service_core):
    """get_history exposes the service database read-only over IPC."""
    from utils import paths

    service_core.database.scan_start("quick", [r"C:\x"])
    scan = service_core.database.list_scans(1)[0]
    service_core.database.scan_finish(
        scan["scan_id"], "completed", files_scanned=10, threats=2,
        suspicious=1, quarantined=0, skipped=0, errors=0,
        duration_secs=1.5)
    service_core._on_threat(_fake_detection())

    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    response = client.call("get_history", {"scans_limit": 10,
                                           "threats_limit": 10})
    assert len(response["scans"]) == 1
    assert response["scans"][0]["files_scanned"] == 10
    assert len(response["threats"]) == 1
    assert response["database"] == str(paths.database_path())


def test_get_history_limit_is_capped(service_core):
    """Abusive limits are clamped; bad types fall back to defaults."""
    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    ok = client.call("get_history", {"scans_limit": 10 ** 9,
                                     "threats_limit": "banana"})
    assert ok["scans"] == [] and ok["threats"] == []


# ---------------------------------------------------------------------------
# GUI-side merge of service history (no Tk window required)
# ---------------------------------------------------------------------------


def _bare_app(test_database):
    """A LocalGuardApp instance without running Tk.__init__.

    Only the attributes needed by the history-merge methods are set;
    this keeps UI-free coverage of the merge logic.
    """
    from ui.app import LocalGuardApp

    app = LocalGuardApp.__new__(LocalGuardApp)
    app.database = test_database
    app.background_protection = True
    app._remote_history_cache = None
    return app


def test_list_scans_merges_service_rows(test_database, monkeypatch):
    """Service scan rows appear merged, marked, and sorted by date."""
    from services import service_control

    test_database.scan_start("quick", [r"C:\local"])
    # Remote timestamp must always sort newer than the local row. The
    # DB writes UTC, so derive from utc_timestamp() rather than the
    # local clock (a fixed offset would break in other timezones).
    from datetime import datetime as _dt, timedelta as _td
    from database.database import utc_timestamp

    soon = (_dt.strptime(utc_timestamp(), "%Y-%m-%d %H:%M:%S")
            + _td(hours=1)).strftime("%Y-%m-%d %H:%M")
    remote = {
        "scans": [
            {"scan_id": 7, "scan_type": "usb", "start_time": soon,
             "end_time": soon, "files_scanned": 55,
             "threats_found": 1, "suspicious_found": 0, "status": "completed"},
        ],
        "threats": [],
    }
    monkeypatch.setattr(service_control, "send_command",
                        lambda method, params=None: remote)
    app = _bare_app(test_database)
    rows = app.list_scans()
    assert [r.get("origin") for r in rows] == ["service", None]
    svc = rows[0]
    assert svc["scan_id"] == "svc-7"
    assert svc["files_scanned"] == 55


def test_threat_counts_merge_service_rows(test_database, monkeypatch):
    """Service threat statuses are added to the local counts."""
    from services import service_control

    remote = {"scans": [], "threats": [
        {"status": "open"}, {"status": "open"}, {"status": "quarantined"},
    ]}
    monkeypatch.setattr(service_control, "send_command",
                        lambda method, params=None: remote)
    app = _bare_app(test_database)
    counts = app.threat_counts()
    assert counts["open"] == 2
    assert counts["quarantined"] == 1
    assert counts["total"] == 3


def test_history_merge_degrades_gracefully(test_database, monkeypatch):
    """When the service stops answering, local data still comes through."""
    from services import service_control

    def boom(method, params=None):
        raise service_control.ServiceControlError("gone")

    monkeypatch.setattr(service_control, "send_command", boom)
    test_database.scan_start("full", [r"C:\local"])
    app = _bare_app(test_database)
    assert len(app.list_scans()) == 1
    assert app.threat_counts()["total"] == 0


def test_history_cache_respects_ttl(test_database, monkeypatch):
    """Repeated refreshes reuse the cached snapshot for 30 seconds."""
    from services import service_control

    calls: list = []
    monkeypatch.setattr(
        service_control, "send_command",
        lambda method, params=None: calls.append(1) or
        {"scans": [], "threats": []})
    app = _bare_app(test_database)
    app.list_scans()
    app.list_scans()
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# Quarantine + exclusions merge (service scope shown in the GUI)
# ---------------------------------------------------------------------------


def _bare_app_with_history(test_database, monkeypatch, snapshot):
    """A bare app whose remote-history fetch returns *snapshot*."""
    from services import service_control
    from ui.app import LocalGuardApp

    monkeypatch.setattr(service_control, "send_command",
                        lambda method, params=None: snapshot)
    app = LocalGuardApp.__new__(LocalGuardApp)
    app.database = test_database
    app.background_protection = True
    app._remote_history_cache = None
    return app


def test_get_history_includes_quarantine_and_exclusions(service_core):
    """The IPC snapshot carries active quarantine + exclusion rows."""
    service_core.database.add_quarantine_record({
        "original_path": r"C:\evil.exe",
        "quarantine_path": r"C:\vault\evil.quar",
        "sha256": "cd" * 32,
        "detection_name": "Test.Malware",
        "severity": "high",
        "file_size": 42,
    })
    service_core.database.add_exclusion("folder", r"D:\trusted")

    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    response = client.call("get_history", {})
    assert len(response["quarantined"]) == 1
    # Service-local vault paths never leave the service process.
    assert "quarantine_path" not in response["quarantined"][0]
    assert "metadata" not in response["quarantined"][0]
    assert response["quarantined"][0]["detection_name"] == "Test.Malware"
    assert response["exclusions"][0]["value"] == r"D:\trusted"


def test_quarantine_view_merges_service_rows(test_database, monkeypatch):
    """Service quarantine rows appear marked as service origin."""
    test_database.add_quarantine_record({
        "original_path": r"C:\local.exe",
        "detection_name": "Local.Threat",
    })
    snapshot = {"scans": [], "threats": [], "exclusions": [],
                "quarantined": [
                    {"quarantine_id": 9, "original_path": r"C:\svc.exe",
                     "detection_name": "Service.Threat",
                     "severity": "high"}]}
    app = _bare_app_with_history(test_database, monkeypatch, snapshot)
    rows = app.list_quarantine_records()
    names = [r["detection_name"] for r in rows]
    assert "Local.Threat" in names and "Service.Threat" in names
    svc = next(r for r in rows if r["detection_name"] == "Service.Threat")
    assert svc["origin"] == "service"
    local = next(r for r in rows if r["detection_name"] == "Local.Threat")
    assert "origin" not in local


def test_quarantine_count_includes_service_rows(test_database, monkeypatch):
    """The dashboard count covers both scopes."""
    test_database.add_quarantine_record({
        "original_path": r"C:\local.exe",
        "detection_name": "Local.Threat",
    })
    snapshot = {"scans": [], "threats": [],
                "quarantined": [{"quarantine_id": 1}, {"quarantine_id": 2}],
                "exclusions": []}
    app = _bare_app_with_history(test_database, monkeypatch, snapshot)
    assert app.quarantine_count() == 3


def test_exclusions_merge_marks_service_scope(test_database, monkeypatch):
    """Service-only exclusions are marked; duplicates are de-duplicated."""
    test_database.add_exclusion("folder", r"D:\shared")
    snapshot = {"scans": [], "threats": [], "quarantined": [],
                "exclusions": [
                    {"exclusion_id": 1, "exclusion_type": "folder",
                     "value": r"D:\shared"},
                    {"exclusion_id": 2, "exclusion_type": "hash",
                     "value": "ab" * 32},
                ]}
    app = _bare_app_with_history(test_database, monkeypatch, snapshot)
    rows = app.list_exclusions_merged()
    scopes = {(r["value"], r.get("origin", "local")) for r in rows}
    assert (r"D:\shared", "local") in scopes       # local wins, no dup
    assert (("ab" * 32), "service") in scopes      # service-only marked
    assert len([r for r in rows if r["value"] == r"D:\shared"]) == 1


def test_exclusions_view_degrades_without_service(test_database):
    """No service: merged view is exactly the local set."""
    from ui.app import LocalGuardApp

    test_database.add_exclusion("extension", ".log")
    app = LocalGuardApp.__new__(LocalGuardApp)
    app.database = test_database
    app.background_protection = False
    assert [r["value"] for r in app.list_exclusions_merged()] == [".log"]


# ---------------------------------------------------------------------------
# Quarantine actions over IPC (GUI-confirmed restore/delete)
# ---------------------------------------------------------------------------


def test_quarantine_restore_requires_confirmation(service_core):
    """A request without user_confirmed must not touch the vault."""
    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    response = client.call("quarantine_restore",
                           {"quarantine_id": 1, "user_confirmed": False})
    assert "error" in response
    assert "confirmation" in response["error"].lower()


def test_quarantine_action_rejects_bad_id(service_core):
    """Non-integer IDs are refused with a clean error, never a crash."""
    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    response = client.call("quarantine_delete", {"quarantine_id": "x",
                                                 "user_confirmed": True})
    assert "error" in response
    assert "integer" in response["error"].lower()


def test_quarantine_action_unknown_id_is_clean_error(service_core):
    """An unknown record id surfaces as an error response."""
    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    response = client.call("quarantine_restore",
                           {"quarantine_id": 424242, "user_confirmed": True})
    assert "error" in response
    assert "not found" in response["error"].lower()


def test_quarantine_restore_via_ipc(service_core, tmp_path):
    """Full loop: quarantine a file, restore it over authenticated IPC."""
    original = tmp_path / "report.txt"
    original.write_text("harmless report body", encoding="utf-8")

    manager = service_core._quarantine_manager()
    record = manager.quarantine_file(
        original, "Test.Threat", detection_type="signature",
        severity="high")
    assert not original.exists()  # quarantined away

    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    response = client.call("quarantine_restore", {
        "quarantine_id": record["quarantine_id"], "user_confirmed": True,
    })
    assert response.get("ok") is True
    assert original.exists()
    assert original.read_text(encoding="utf-8") == "harmless report body"
    stored = service_core.database.get_quarantine_record(
        record["quarantine_id"])
    assert stored["status"] == "RESTORED"


def test_quarantine_delete_via_ipc(service_core, tmp_path):
    """Full loop: quarantine a file, permanently delete it over IPC."""
    original = tmp_path / "evil.bin"
    original.write_bytes(b"MZ fake payload for delete test")

    manager = service_core._quarantine_manager()
    record = manager.quarantine_file(original, "Test.Deleted")
    assert not original.exists()

    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    response = client.call("quarantine_delete", {
        "quarantine_id": record["quarantine_id"], "user_confirmed": True,
    })
    assert response.get("ok") is True
    assert not original.exists()
    stored = service_core.database.get_quarantine_record(
        record["quarantine_id"])
    assert stored["status"] == "DELETED"


def test_quarantine_action_writes_security_event(service_core, tmp_path):
    """Actions leave a visible audit trail in the security event log."""
    original = tmp_path / "audited.txt"
    original.write_text("audit me", encoding="utf-8")
    record = service_core._quarantine_manager().quarantine_file(
        original, "Test.Audit")

    client = ServiceIPCClient(port=service_core.ipc.port,
                              token=service_core.ipc.token)
    client.call("quarantine_delete",
                {"quarantine_id": record["quarantine_id"],
                 "user_confirmed": True})
    events = service_core.database.list_events(limit=10)
    assert any(e.get("event_type") in {"threat_deleted", "quarantine_deleted"}
               for e in events)


# ---------------------------------------------------------------------------
# GUI-side service quarantine actions (no Tk window required)
# ---------------------------------------------------------------------------


class _FakeIPCClient:
    """Captures quarantine action calls instead of using a socket."""

    calls: List[tuple] = []
    response: Dict[str, Any] = {"ok": True}
    raise_error: bool = False

    @classmethod
    def from_discovery(cls):
        if cls.raise_error:
            raise RuntimeError("background service is not running")
        return cls()

    def call(self, method, params=None, timeout=5.0):
        _FakeIPCClient.calls.append((method, dict(params or {})))
        return dict(_FakeIPCClient.response)


def test_app_service_quarantine_action_routes_over_ipc(
        test_database, monkeypatch):
    """The GUI method sends the authenticated, confirmed IPC command."""
    from services import windows_service as ws_module

    app = _bare_app(test_database)
    sent_messages: List[tuple] = []
    monkeypatch.setattr(app, "ui_call", lambda func: func())
    monkeypatch.setattr(app, "run_background",
                        lambda worker, text: worker())
    monkeypatch.setattr(app, "_message",
                        lambda text, level="info": sent_messages.append(
                            ("msg", text, level)))
    monkeypatch.setattr(app, "refresh_merged_views",
                        lambda: sent_messages.append(("refresh",)))
    monkeypatch.setattr(ws_module, "ServiceIPCClient", _FakeIPCClient)

    _FakeIPCClient.calls = []
    _FakeIPCClient.response = {"ok": True}
    app.service_quarantine_action(7, "restore")

    assert _FakeIPCClient.calls == [(
        "quarantine_restore",
        {"quarantine_id": 7, "user_confirmed": True})]
    kinds = [entry[0] for entry in sent_messages]
    assert "msg" in kinds and "refresh" in kinds
    success = [e for e in sent_messages if e[0] == "msg"]
    assert any("restored" in e[1] for e in success)


def test_app_service_quarantine_action_reports_errors(
        test_database, monkeypatch):
    """Failures reach the user as error messages, never as crashes."""
    from services import windows_service as ws_module

    app = _bare_app(test_database)
    sent_messages: List[tuple] = []
    monkeypatch.setattr(app, "ui_call", lambda func: func())
    monkeypatch.setattr(app, "run_background",
                        lambda worker, text: worker())
    monkeypatch.setattr(app, "_message",
                        lambda text, level="info": sent_messages.append(
                            (text, level)))

    monkeypatch.setattr(ws_module, "ServiceIPCClient", _FakeIPCClient)
    _FakeIPCClient.calls = []
    _FakeIPCClient.response = {"error": "Quarantine record 9 not found"}
    app.service_quarantine_action(9, "delete")
    assert any(level == "error" and "not found" in text
               for text, level in sent_messages)

    sent_messages.clear()
    _FakeIPCClient.raise_error = True
    app.service_quarantine_action(9, "restore")
    _FakeIPCClient.raise_error = False
    assert any(level == "error" and "not running" in text
               for text, level in sent_messages)
