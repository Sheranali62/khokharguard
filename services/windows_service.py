"""LocalGuard Antivirus - background protection service core.

Implements the spec section 45 model with a clear split:

    - :class:`ProtectionServiceCore` hosts the protection stack
      (real-time monitor, USB monitor, database, notifications) in a
      process that has NO GUI - the console session or a Windows
      service process.
    - :class:`ServiceIPCServer` exposes a small, authenticated
      localhost JSON command surface (status / pause / resume /
      apply-settings / shutdown). The GUI talks to it through
      :class:`ServiceIPCClient` / :mod:`services.service_control`.

Security properties (spec sections 28, 45):

    - The server binds to 127.0.0.1 only; it is never reachable from
      the network.
    - Every request must carry the session token; the comparison is
      constant-time. The token is generated per service start and
      stored with 0600-style restriction in the per-user app data
      directory, so only the same Windows user can control it.
    - The command set is a fixed allow-list: there is no arbitrary
      command execution, no file paths accepted over IPC, no SQL
      built from IPC input.
    - Request size is capped and malformed input never crashes the
      server.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import socket
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from utils import get_logger

logger = get_logger("windows_service")

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 47615  # unregistered port, local loopback only
_MAX_REQUEST_BYTES = 64 * 1024
_MAX_STREAMED_FINDINGS = 100
_MAX_HISTORY_LIMIT = 200

# Fixed IPC method allow-list (spec section 58: no arbitrary execution).
IPC_METHODS = ("status", "pause", "resume", "apply_settings", "shutdown",
               "recent_findings", "get_history")


class ServiceIPCError(Exception):
    """Raised when the IPC channel cannot be established."""


# ---------------------------------------------------------------------------
# Token / discovery file
# ---------------------------------------------------------------------------


def token_file_path() -> Path:
    """Path of the service discovery file (token + port)."""
    from utils import paths

    return paths.app_data_dir() / "service_token.json"


def write_token_file(token: str, port: int, pid: int) -> None:
    """Persist the connection info for GUI clients.

    The file lives in the per-user app data directory, which on Windows
    is ACL-protected to the user profile; we additionally restrict it
    best-effort on POSIX.
    """
    path = token_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({
        "token": token,
        "port": int(port),
        "pid": int(pid),
        "host": _DEFAULT_HOST,
    })
    path.write_text(payload, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows ACLs already scope this to the user profile


def read_token_file() -> Optional[Dict[str, Any]]:
    """Read the connection info written by a running service."""
    try:
        data = json.loads(token_file_path().read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("token"), str):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return None


def remove_token_file() -> None:
    """Delete the discovery file (service shutdown)."""
    try:
        token_file_path().unlink(missing_ok=True)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# IPC server (service side)
# ---------------------------------------------------------------------------


class ServiceIPCServer:
    """Authenticated localhost JSON command server.

    One connection = one request = one response (newline-delimited
    JSON), mirroring :class:`ServiceIPCClient.call`. A dedicated
    daemon thread accepts connections; each request is handled on its
    own short-lived thread so a slow client cannot stall the service.
    """

    def __init__(self, handlers: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]],
                 token: Optional[str] = None,
                 host: str = _DEFAULT_HOST,
                 port: int = _DEFAULT_PORT) -> None:
        self.handlers = dict(handlers)
        self.token = token or secrets.token_hex(32)
        self.host = host
        self.port = port
        self._server_sock: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Bind and start accepting; False when the port is taken."""
        if self._server_sock is not None:
            return True
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if sys.platform == "win32":
                # Windows SO_REUSEADDR permits a second bind to the same
                # port (hijack risk); SO_EXCLUSIVEADDRUSE prevents it.
                self._server_sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            self._server_sock.bind((self.host, self.port))
            # Port 0 lets the OS pick a free port (tests, co-resident
            # instances); publish the actual bound port.
            self.port = int(self._server_sock.getsockname()[1])
            self._server_sock.listen(4)
            self._server_sock.settimeout(0.5)
        except OSError as exc:
            logger.error("IPC server bind failed on %s:%d: %s",
                         self.host, self.port, exc)
            self._server_sock = None
            return False

        self._stop_event.clear()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True, name="localguard-ipc-accept")
        self._accept_thread.start()
        logger.info("IPC server listening on %s:%d", self.host, self.port)
        return True

    def stop(self) -> None:
        """Stop the server and release the port (idempotent)."""
        self._stop_event.set()
        sock = self._server_sock
        self._server_sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._accept_thread is not None and \
                self._accept_thread is not threading.current_thread():
            self._accept_thread.join(timeout=3)
        self._accept_thread = None
        logger.info("IPC server stopped")

    @property
    def running(self) -> bool:
        """True while the accept loop is live."""
        return self._server_sock is not None and not self._stop_event.is_set()

    # ------------------------------------------------------------------
    # Request handling
    # ------------------------------------------------------------------

    def _accept_loop(self) -> None:
        """Accept client connections until stopped."""
        while not self._stop_event.is_set():
            server = self._server_sock
            if server is None:
                break
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if addr[0] not in ("127.0.0.1", "::1"):
                # Defence in depth: loopback bind should guarantee this.
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            threading.Thread(
                target=self._serve_client, args=(conn,), daemon=True,
                name="localguard-ipc-req").start()

    def _serve_client(self, conn: socket.socket) -> None:
        """Handle one request/response exchange on *conn*.

        Oversized requests are drained to the request terminator before
        responding so the client can still read the error instead of
        receiving a TCP reset (Windows resets connections that are
        closed with unread data in flight).
        """
        try:
            with conn:
                buffer = b""
                oversized = False
                while b"\n" not in buffer:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk
                    if len(buffer) > _MAX_REQUEST_BYTES and not oversized:
                        oversized = True
                if oversized:
                    response = (json.dumps({"error": "request too large"})
                                .encode("utf-8") + b"\n")
                else:
                    response = self.handle_payload(buffer)
                conn.sendall(response)
        except OSError:
            logger.debug("IPC client connection error", exc_info=True)

    def handle_payload(self, payload: bytes) -> bytes:
        """Process one request payload; always returns a JSON line."""
        try:
            request = json.loads(payload.decode("utf-8"))
            if not isinstance(request, dict):
                raise ValueError("request must be a JSON object")
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return json.dumps({"error": "bad json"}).encode("utf-8") + b"\n"

        supplied = request.get("token")
        if not isinstance(supplied, str) or \
                not hmac.compare_digest(supplied, self.token):
            return json.dumps({"error": "unauthorized"}).encode("utf-8") + b"\n"

        method = request.get("method")
        if method not in IPC_METHODS:
            return json.dumps({"error": "unknown method"}).encode("utf-8") + b"\n"

        params = request.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return json.dumps({"error": "bad params"}).encode("utf-8") + b"\n"

        handler = self.handlers.get(str(method))
        if handler is None:
            return json.dumps({"error": "unavailable"}).encode("utf-8") + b"\n"
        try:
            result = handler(params)
        except Exception as exc:  # noqa: BLE001 - report, never crash
            logger.exception("IPC handler failed for %s", method)
            return json.dumps({"error": str(exc)}).encode("utf-8") + b"\n"
        return json.dumps(result).encode("utf-8") + b"\n"


# ---------------------------------------------------------------------------
# IPC client (GUI / CLI side)
# ---------------------------------------------------------------------------


class ServiceIPCClient:
    """Authenticated localhost IPC client for the running service."""

    def __init__(self, host: str = _DEFAULT_HOST, port: int = _DEFAULT_PORT,
                 token: Optional[str] = None) -> None:
        self.host = host
        self.port = port
        self.token = token or secrets.token_hex(32)
        self._lock = threading.Lock()

    @classmethod
    def from_discovery(cls) -> Optional["ServiceIPCClient"]:
        """Build a client from the service's token file, if present."""
        info = read_token_file()
        if info is None:
            return None
        return cls(
            host=str(info.get("host", _DEFAULT_HOST)),
            port=int(info.get("port", _DEFAULT_PORT)),
            token=str(info.get("token", "")),
        )

    def call(self, method: str, params: Optional[Dict[str, Any]] = None,
             timeout: float = 5.0) -> Dict[str, Any]:
        """Make one authenticated JSON-RPC style call."""
        payload = json.dumps({
            "token": self.token, "method": method, "params": params or {},
        }).encode("utf-8")

        with self._lock:
            try:
                with socket.create_connection(
                        (self.host, self.port), timeout=timeout) as sock:
                    sock.sendall(payload + b"\n")
                    buffer = b""
                    while b"\n" not in buffer:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        buffer += chunk
            except OSError as exc:
                raise ServiceIPCError(f"IPC connection failed: {exc}") from exc

        if not buffer:
            raise ServiceIPCError("Empty IPC response")
        try:
            return json.loads(buffer.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ServiceIPCError(f"Invalid IPC response: {exc}") from exc


# ---------------------------------------------------------------------------
# Headless protection core
# ---------------------------------------------------------------------------


class ProtectionServiceCore:
    """Runs the protection stack without a GUI.

    Owns the shared services (database, analyzer, ProtectionManager)
    plus the IPC server, and persists a small state file so the GUI
    can see the service across process restarts. Findings are stored
    in the shared database exactly like scan findings; the GUI picks
    them up on refresh.
    """

    def __init__(self, port: int = _DEFAULT_PORT) -> None:
        self.port = port
        self.database = None
        self.analyzer = None
        self.protection = None
        self.ipc: Optional[ServiceIPCServer] = None
        self._stop_event = threading.Event()
        # Streaming state: monotonically increasing sequence numbers so
        # the GUI can poll for *new* findings since its last watermark.
        self._findings_seq = 0
        self._findings: deque = deque(maxlen=_MAX_STREAMED_FINDINGS)
        self._findings_lock = threading.Lock()
        # Monotonic timestamp of the last GUI findings poll: while a GUI
        # is actively consuming, the service suppresses its own popup
        # notifications because the GUI raises them on receipt (no
        # double alerts). Stale (GUI closed) -> service alerts again.
        self._last_gui_poll = 0.0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Initialise services and begin protecting (blocking owner)."""
        from engine.file_analyzer import FileAnalyzer
        from engine.scan_controller import ScanController
        from engine.signature_engine import SignatureEngine
        from engine.yara_engine import YaraEngine
        from database.database import get_database
        from protection.protection_manager import ProtectionManager
        from utils.logger import setup_logging

        setup_logging()
        logger.info("Protection service core starting")

        self.database = get_database()
        self.analyzer = FileAnalyzer(
            signature_engine=SignatureEngine(database=self.database),
            yara_engine=YaraEngine(),
        )
        # A real controller so background USB auto-scans persist like
        # GUI-initiated ones; the service never drives it directly.
        scan_controller = ScanController(
            analyzer=self.analyzer, database=self.database, threads=2)
        self.protection = ProtectionManager(self.analyzer, scan_controller)
        self.protection.on_threat = self._on_threat

        self.ipc = ServiceIPCServer({
            "status": lambda params: self.status(),
            "pause": lambda params: self.pause(),
            "resume": lambda params: self.resume(),
            "apply_settings": lambda params: self.apply_settings(),
            "shutdown": lambda params: self.request_shutdown(),
            "recent_findings": self.recent_findings,
            "get_history": self.get_history,
        })
        if self.ipc.start():
            write_token_file(self.ipc.token, self.ipc.port, os.getpid())
        else:
            # Port busy: another instance is already protecting. Do not
            # fight over the monitoring duty.
            logger.error("IPC port busy - is another instance running?")
            raise ServiceIPCError("IPC port already in use")

        self._write_state({"status": "running"})
        self.database.add_event("service_started",
                                "Background protection service started")
        self.protection.start()
        logger.info("Protection service core running")

    def stop(self) -> None:
        """Stop protection, IPC, and clean up (idempotent)."""
        self._stop_event.set()
        if self.ipc is not None:
            self.ipc.stop()
            self.ipc = None
        remove_token_file()
        if self.protection is not None:
            try:
                self.protection.stop()
            except Exception:  # noqa: BLE001
                logger.exception("Protection stop failed")
            self.protection = None
        if self.database is not None:
            try:
                self.database.add_event("service_stopped",
                                        "Background protection service stopped")
                self.database.close()
            except Exception:  # noqa: BLE001
                pass
            self.database = None
        self._write_state({"status": "stopped"})
        logger.info("Protection service core stopped")

    # ------------------------------------------------------------------
    # Commands (IPC-reachable surface - fixed, safe operations only)
    # ------------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        """Service + protection status snapshot for the GUI."""
        protection_status: Dict[str, Any] = {}
        if self.protection is not None:
            protection_status = self.protection.status()
        return {
            "service": "running",
            "pid": os.getpid(),
            "version": _version(),
            "paused": bool(self.protection.paused) if self.protection else False,
            "protection": protection_status,
        }

    def pause(self) -> Dict[str, Any]:
        """Pause protection (GUI/tray parity)."""
        if self.protection is not None:
            self.protection.pause_protection()
            self.database.add_event("protection_disabled",
                                    "Protection paused via service IPC",
                                    severity="warning")
        return {"ok": True, "paused": True}

    def resume(self) -> Dict[str, Any]:
        """Resume protection (GUI/tray parity)."""
        if self.protection is not None:
            self.protection.resume_protection()
            self.database.add_event("protection_enabled",
                                    "Protection resumed via service IPC")
        return {"ok": True, "paused": False}

    def apply_settings(self) -> Dict[str, Any]:
        """Reload settings and restart monitors (GUI parity)."""
        if self.protection is not None:
            self.protection.stop()
            self.protection.start()
        return {"ok": True}

    def request_shutdown(self) -> Dict[str, Any]:
        """Ask the service loop to exit cleanly."""
        self._stop_event.set()
        return {"ok": True}

    def recent_findings(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Findings recorded since the caller's last watermark.

        ``params``: ``{"since_seq": int}`` (defaults to 0 = everything
        still buffered). Returns ``{"findings": [...], "last_seq": n}``
        where each finding carries its sequence number plus the
        detection fields the GUI needs to reproduce a local finding.
        """
        try:
            since = int(params.get("since_seq", 0))
        except (TypeError, ValueError):
            since = 0
        self._last_gui_poll = time.monotonic()
        with self._findings_lock:
            findings = [
                dict(entry) for entry in self._findings
                if entry.get("seq", 0) > since
            ]
            last_seq = self._findings_seq
        return {"findings": findings, "last_seq": last_seq}

    def get_history(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Read-only history snapshot from the service's database.

        Bridges the SCM-hosted case where the service runs under its
        own account and therefore its own data directory: the GUI pulls
        these rows and merges them into its views. ``params`` accepts
        ``scans_limit`` / ``threats_limit`` (capped to a small maximum;
        this is a fixed SQL read, never IPC-controlled SQL).
        """
        def _limit(key: str) -> int:
            try:
                return max(1, min(int(params.get(key, 50)), _MAX_HISTORY_LIMIT))
            except (TypeError, ValueError):
                return 50

        scans: List[Dict[str, Any]] = []
        threats: List[Dict[str, Any]] = []
        if self.database is not None:
            scans = [dict(row) for row in self.database.list_scans(
                limit=_limit("scans_limit"))]
            threats = [dict(row) for row in self.database.list_threats(
                limit=_limit("threats_limit"))]
        try:
            from utils import paths

            db_path = str(paths.database_path())
        except Exception:  # noqa: BLE001
            db_path = ""
        return {
            "scans": scans,
            "threats": threats,
            "database": db_path,
            "pid": os.getpid(),
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _on_threat(self, detection) -> None:
        """Persist + stream + notify for background findings (GUI-less path)."""
        from dataclasses import asdict
        from pathlib import Path

        from utils.notify import notify

        # 1. Stream to any connected GUI (bounded buffer, sequence kept).
        try:
            with self._findings_lock:
                self._findings_seq += 1
                self._findings.append({
                    "seq": self._findings_seq,
                    "detection": asdict(detection),
                })
        except Exception:  # noqa: BLE001
            logger.exception("Could not stream service detection")
        # 2. Persist in the service database for the merged history view.
        try:
            self.database.add_threat({
                "file_path": detection.path,
                "sha256": detection.sha256,
                "file_size": detection.file_size,
                "detection_name": detection.detection_name,
                "detection_type": detection.detection_method,
                "severity": detection.severity,
                "confidence": detection.confidence,
                "risk_score": detection.risk_score,
                "reason": detection.reason,
                "recommended_action": detection.recommended_action,
                "source": "realtime",
            })
        except Exception:  # noqa: BLE001
            logger.exception("Could not persist service detection")
        # 3. Notify only when no GUI is consuming findings - otherwise
        # the GUI raises the alert on receipt and this would double it.
        gui_consuming = (time.monotonic() - self._last_gui_poll) < 15.0
        if not gui_consuming:
            try:
                notify("threat_detected", "LocalGuard - Threat Detected",
                       f"{detection.detection_name}: "
                       f"{Path(detection.path).name}")
            except Exception:  # noqa: BLE001
                logger.debug("Service notification failed", exc_info=True)

    def _write_state(self, extra: Dict[str, Any]) -> None:
        """Persist a small state file for cross-process visibility."""
        from utils import paths

        try:
            state = {"pid": os.getpid(), "version": _version(), **extra}
            paths.app_data_dir().joinpath("service_state.json").write_text(
                json.dumps(state), encoding="utf-8")
        except OSError:
            logger.debug("Could not write service state file", exc_info=True)

    def run_forever(self) -> None:
        """Block until shutdown is requested (service loop)."""
        self.start()
        try:
            while not self._stop_event.wait(1.0):
                pass
        finally:
            self.stop()


def _version() -> str:
    """Application version (best effort)."""
    try:
        from utils import paths

        return paths.version()
    except Exception:  # noqa: BLE001
        return "unknown"


def run_service_core(port: int = _DEFAULT_PORT) -> int:
    """Entry point for the background core (blocks until shutdown)."""
    core = ProtectionServiceCore(port=port)
    try:
        core.run_forever()
        return 0
    except ServiceIPCError as exc:
        logger.error("Service core did not start: %s", exc)
        return 2
    except Exception:  # noqa: BLE001
        logger.exception("Service core crashed")
        return 1
