"""LocalGuard Antivirus - Windows service lifecycle wrapper.

Wraps :class:`~services.windows_service.ProtectionServiceCore` in a
pywin32 ``win32serviceutil.ServiceFramework`` so protection survives
GUI exit and can start with Windows (spec section 45).

Design constraints (spec sections 28, 45, 46):

    - The service is installed via the standard, visible pywin32
      service mechanism - no stealth persistence (spec section 46).
      The user (or installer) installs it deliberately and can remove
      it at any time; it shows in services.msc like any other service.
    - Clean start/stop with SCM status reporting.
    - The command surface is the fixed CLI verbs in ``main.py``
      (``service install / uninstall / start / stop / run``) - no
      arbitrary command execution.

Everything degrades when pywin32 is absent or on non-Windows hosts:
queries return False and lifecycle operations raise
:class:`ServiceControlError` with a clear message.
"""

from __future__ import annotations

import sys
from typing import Optional

from utils import get_logger

logger = get_logger("service_control")

SERVICE_NAME = "LocalGuardService"
SERVICE_DISPLAY_NAME = "LocalGuard Antivirus Protection Service"
SERVICE_DESCRIPTION = (
    "Keeps LocalGuard real-time and USB-drive protection running even "
    "when the LocalGuard window is closed. Manage it from the "
    "LocalGuard Settings page or services.msc."
)


class ServiceControlError(Exception):
    """Raised when a service lifecycle operation cannot be completed."""


def pywin32_available() -> bool:
    """True when the pywin32 service stack imports cleanly."""
    try:
        import servicemanager  # noqa: F401
        import win32event  # noqa: F401
        import win32service  # noqa: F401
        import win32serviceutil  # noqa: F401
    except ImportError:
        return False
    return True


# ---------------------------------------------------------------------------
# SCM service class (only defined when the pywin32 stack is importable)
# ---------------------------------------------------------------------------

if sys.platform == "win32" and pywin32_available():  # pragma: no cover

    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class LocalGuardWinService(win32serviceutil.ServiceFramework):  # type: ignore[misc]
        """SCM-visible Windows service hosting the protection core."""

        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args) -> None:
            super().__init__(args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.core = None

        def SvcStop(self) -> None:  # noqa: N802 - pywin32 API
            """SCM stop request: report stopping and unblock the loop."""
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)

        def SvcDoRun(self) -> None:  # noqa: N802 - pywin32 API
            """Service main: run the protection core until stopped."""
            try:
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, ""),
                )
            except Exception:  # noqa: BLE001
                pass
            try:
                from services.windows_service import ProtectionServiceCore

                self.core = ProtectionServiceCore()
                self.core.start()
                win32event.WaitForSingleObject(self._stop_event, 0xFFFFFFFF)
            except Exception:  # noqa: BLE001 - the SCM must see failure
                logger.exception("Service main loop failed")
                servicemanager.LogErrorMsg(
                    "LocalGuard protection service failed; see "
                    "LocalGuard logs.")
                self.SvcStop()
            finally:
                if self.core is not None:
                    self.core.stop()

else:

    LocalGuardWinService = None  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Lifecycle helpers
# ---------------------------------------------------------------------------


def _require_windows() -> None:
    """Guard for non-Windows platforms."""
    if sys.platform != "win32":
        raise ServiceControlError("Windows services require Windows")


def service_installed() -> bool:
    """True when the LocalGuard service exists (any state)."""
    if sys.platform != "win32":
        return False
    try:
        import win32service
        import win32serviceutil

        win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        return True
    except ImportError:
        return _query_via_sc() is not None
    except Exception:  # noqa: BLE001 - service simply not installed
        return False


def service_running() -> bool:
    """True when the LocalGuard service exists and is RUNNING."""
    if sys.platform != "win32":
        return False
    state = _query_service_state()
    return state is not None and state == "RUNNING"


def _query_service_state() -> Optional[str]:
    """Current SCM state name (RUNNING / STOPPED / ...) or None."""
    if sys.platform != "win32":
        return None
    try:
        import win32service
        import win32serviceutil

        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        current = status[1] if isinstance(status, tuple) else status
        states = {
            win32service.SERVICE_START_PENDING: "START_PENDING",
            win32service.SERVICE_RUNNING: "RUNNING",
            win32service.SERVICE_STOP_PENDING: "STOP_PENDING",
            win32service.SERVICE_STOPPED: "STOPPED",
            win32service.SERVICE_PAUSE_PENDING: "PAUSE_PENDING",
            win32service.SERVICE_PAUSED: "PAUSED",
            win32service.SERVICE_CONTINUE_PENDING: "CONTINUE_PENDING",
        }
        return states.get(int(current), "UNKNOWN")
    except ImportError:
        return _query_via_sc()
    except Exception:  # noqa: BLE001 - not installed / access denied
        return None


def _query_via_sc() -> Optional[str]:
    """Fallback query parsing the ``sc query`` output (no pywin32)."""
    import os
    import subprocess  # noqa: S404 - fixed argument list, never shell
    from pathlib import Path

    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    sc = Path(system_root) / "System32" / "sc.exe"
    if not sc.is_file():
        return None
    try:
        result = subprocess.run(  # noqa: S603
            [str(sc), "query", SERVICE_NAME],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("STATE"):
            # e.g. "STATE              : 4 RUNNING"
            parts = line.split()
            return parts[-1] if parts else None
    return None


def install_service() -> None:
    """Install the service (requires elevation; UAC decides, silently
    failing here would be wrong - the caller surfaces the error)."""
    _require_windows()
    if not pywin32_available():
        raise ServiceControlError(
            "pywin32 is required to install the service "
            "(pip install pywin32)")
    import win32serviceutil

    # Frozen exe hosts itself (pywin32 dispatcher built into main.py);
    # source installs register the current interpreter + main.py.
    if getattr(sys, "frozen", False):
        win32serviceutil.InstallService(
            f"{SERVICE_NAME}Service",
            SERVICE_NAME,
            SERVICE_DISPLAY_NAME,
            exeName=sys.executable,
            exeArgs="service run",
            description=SERVICE_DESCRIPTION,
            startType=win32serviceutil.SERVICE_AUTO_START,
        )
    else:
        class_string = (
            "services.service_control.LocalGuardWinService")
        win32serviceutil.InstallService(
            class_string,
            SERVICE_NAME,
            SERVICE_DISPLAY_NAME,
            description=SERVICE_DESCRIPTION,
            startType=win32serviceutil.SERVICE_AUTO_START,
        )
    logger.info("Service %s installed", SERVICE_NAME)


def uninstall_service() -> None:
    """Remove the service (requires elevation)."""
    _require_windows()
    if not service_installed():
        return
    try:
        import win32serviceutil

        win32serviceutil.RemoveService(SERVICE_NAME)
    except ImportError:
        raise ServiceControlError(
            "pywin32 is required to uninstall the service") from None
    logger.info("Service %s removed", SERVICE_NAME)


def start_service(timeout: int = 30) -> None:
    """Start the service and wait until RUNNING."""
    _require_windows()
    if not service_installed():
        raise ServiceControlError(
            "The LocalGuard service is not installed")
    try:
        import win32serviceutil

        win32serviceutil.StartService(SERVICE_NAME)
    except ImportError:
        raise ServiceControlError(
            "pywin32 is required to start the service") from None
    if not wait_for_state(True, timeout=timeout):
        raise ServiceControlError("The service did not reach RUNNING")


def stop_service(timeout: int = 30) -> None:
    """Stop the service and wait until STOPPED."""
    _require_windows()
    if not service_installed():
        return
    try:
        import win32serviceutil

        win32serviceutil.StopService(SERVICE_NAME)
    except ImportError:
        raise ServiceControlError(
            "pywin32 is required to stop the service") from None
    wait_for_state(False, timeout=timeout)


def wait_for_state(desired_running: bool, timeout: int = 30) -> bool:
    """Poll until the service reaches the desired running state."""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if service_running() == desired_running:
            return True
        time.sleep(0.5)
    return False


def set_service_description(description: str) -> None:
    """Update the service description via sc (best effort)."""
    _require_windows()
    try:
        import os
        import subprocess  # noqa: S404 - fixed argument list
        from pathlib import Path

        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        sc = Path(system_root) / "System32" / "sc.exe"
        subprocess.run(  # noqa: S603
            [str(sc), "description", SERVICE_NAME, description],
            capture_output=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        logger.debug("Description update skipped", exc_info=True)


# ---------------------------------------------------------------------------
# GUI-facing helpers
# ---------------------------------------------------------------------------


def is_service_protection_active() -> bool:
    """True when a reachable background core is protecting this
    account's data.

    Verified via an authenticated IPC status ping against the token
    file in *this user's* app data directory - not merely because a
    Windows service exists. This is deliberate: the SCM-hosted service
    runs under its own account with its own data directory in 1.0, so
    it cannot report into the user session; the GUI must keep
    in-session monitoring in that case instead of deferring and
    leaving the user unprotected (documented limitation).
    """
    try:
        from services.windows_service import (
            ServiceIPCClient,
            read_token_file,
        )

        info = read_token_file()
        if info is None:
            return False
        client = ServiceIPCClient(
            host=str(info.get("host", "127.0.0.1")),
            port=int(info.get("port", 47615)),
            token=str(info.get("token", "")))
        response = client.call("status", timeout=2.0)
        return response.get("service") == "running"
    except Exception:  # noqa: BLE001 - stale token file etc.
        return False


def send_command(method: str, params: Optional[dict] = None) -> dict:
    """Send one IPC command to the background protection provider."""
    from services.windows_service import (
        ServiceIPCClient,
        read_token_file,
    )

    info = read_token_file()
    if info is None:
        raise ServiceControlError("No running LocalGuard service found")
    client = ServiceIPCClient(
        host=str(info.get("host", "127.0.0.1")),
        port=int(info.get("port", 47615)),
        token=str(info.get("token", "")))
    try:
        return client.call(method, params)
    except Exception as exc:
        raise ServiceControlError(str(exc)) from exc


def cleanup_stale_token_file() -> None:
    """Remove a token file whose owning process is gone."""
    import os

    from services.windows_service import read_token_file, remove_token_file

    info = read_token_file()
    if info is None:
        return
    pid = info.get("pid")
    if not isinstance(pid, int):
        remove_token_file()
        return
    try:
        import psutil

        if not psutil.pid_exists(pid):
            remove_token_file()
            logger.info("Removed stale service token file (pid %s)", pid)
    except ImportError:
        # os.kill(pid, 0) raises OSError (ESRCH) when the pid is gone
        # on POSIX; on Windows it uses a different mechanism, so treat
        # any OSError with no live pid as stale.
        try:
            os.kill(pid, 0)
        except OSError:
            remove_token_file()
