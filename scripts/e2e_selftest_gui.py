#!/usr/bin/env python3
"""End-to-end GUI click-through of the About page EICAR self-test.

Launches the real LocalGuard Tkinter GUI with every writable location
redirected into a temp directory, navigates to the About page, clicks
the Run Detection Self-Test button, and answers the real native
dialogs (confirm + verdict) from a helper thread that presses Enter on
the foreground window. Screenshots of each step are saved as UX
evidence.

This is a development/verification tool - it requires an interactive
desktop session and briefly shows the real application window.

Run:  .venv/Scripts/python.exe scripts/e2e_selftest_gui.py
"""

from __future__ import annotations

import ctypes
import json
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# Redirect every writable location into a temp dir BEFORE app imports
# (same redirect strategy as tests/conftest.py - this run must not
# touch the developer's real database, settings, or signature files).
# ---------------------------------------------------------------------------
BASE = Path(tempfile.mkdtemp(prefix="lg_gui_e2e_"))

import utils.paths as paths  # noqa: E402

_appdata = BASE / "appdata"
_logs = BASE / "logs"
_reports = BASE / "reports"
_quarantine = BASE / "quarantine"
_signatures = BASE / "signatures"
_database = BASE / "database"
for directory in (_appdata / "config", _logs, _reports, _quarantine,
                  _signatures / "yara", _database):
    directory.mkdir(parents=True, exist_ok=True)

paths.app_data_dir = lambda: _appdata
paths.logs_dir = lambda: _logs
paths.log_file_path = lambda: _logs / "localguard.log"
paths.reports_dir = lambda: _reports
paths.quarantine_dir = lambda: _quarantine
paths.signatures_dir = lambda: _signatures
paths.hashes_signature_path = lambda: _signatures / "hashes.json"
paths.yara_rules_dir = lambda: _signatures / "yara"
paths.database_path = lambda: _database / "localguard.db"
paths.settings_path = lambda: _appdata / "config" / "settings.json"

# Complete first run beforehand so the wizard does not interfere with
# the self-test click-through being verified here.
import utils.settings as settings_module  # noqa: E402

settings_module._shared = None
_settings = settings_module.Settings(paths.settings_path())
_settings.set("general.first_run_completed", True)

import database.database as database_module  # noqa: E402

database_module.reset_shared()

SHOTS = BASE / "shots"
SHOTS.mkdir(exist_ok=True)

user32 = ctypes.windll.user32
WM_KEYDOWN, WM_KEYUP, VK_RETURN = 0x0100, 0x0101, 0x0D

_status = {"steps": [], "dialogs": [], "final": "incomplete"}


def _grab(name: str) -> None:
    """Save one screenshot of the current screen."""
    try:
        from PIL import ImageGrab

        ImageGrab.grab().save(SHOTS / f"{name}.png")
        _status["steps"].append(f"screenshot:{name}")
    except Exception as exc:  # noqa: BLE001 - evidence is best-effort
        _status["steps"].append(f"screenshot-failed:{name}:{exc}")


def _press_enter() -> None:
    """Send one Enter keypress to the foreground window."""
    user32.keybd_event(VK_RETURN, 0, 0, 0)
    time.sleep(0.06)
    user32.keybd_event(VK_RETURN, 0, WM_KEYUP, 0)


def dialog_handler(done: threading.Event, stop: threading.Event) -> None:
    """Answer the self-test dialogs with Enter as they appear."""
    plan = [
        ("Detection Self-Test", "03_confirm_dialog"),
        ("Self-Test Passed", "04_result_dialog"),
        ("Self-Test Skipped", "04_result_dialog"),
        ("Self-Test Problem", "04_result_dialog"),
    ]
    handled: set = set()
    deadline = time.time() + 90
    while time.time() < deadline and not stop.is_set():
        for title, shot in plan:
            if title in handled:
                continue
            if user32.FindWindowW(None, title):
                time.sleep(0.5)  # let the dialog finish painting
                _grab(shot)
                user32.SetForegroundWindow(user32.FindWindowW(None, title))
                time.sleep(0.3)
                _press_enter()
                handled.add(title)
                _status["dialogs"].append(title)
                print(f"[e2e] answered dialog: {title}", flush=True)
        if {"Detection Self-Test"} <= handled and any(
                t in handled for t in ("Self-Test Passed", "Self-Test Skipped",
                                       "Self-Test Problem")):
            done.set()
            return
        time.sleep(0.25)
    done.set()  # timeout: let the main thread report the failure


def main() -> int:
    """Run the click-through and report the outcome."""
    import tkinter as tk

    from ui.app import LocalGuardApp

    root = tk.Tk()
    app = LocalGuardApp(root)

    done = threading.Event()
    stop = threading.Event()
    handler = threading.Thread(target=dialog_handler, args=(done, stop),
                               daemon=True, name="lg-e2e-dialogs")
    handler.start()

    def step_dashboard() -> None:
        """Screenshot the dashboard and navigate to About."""
        _grab("01_dashboard")
        app.show_page("about")

    def step_about() -> None:
        """Screenshot About and click the self-test button."""
        _grab("02_about")
        button = getattr(app.pages["about"], "_self_test_button", None)
        if button is None:
            _status["final"] = "self-test button not found"
            root.destroy()
            return
        print("[e2e] clicking Run Detection Self-Test", flush=True)
        button.invoke()  # programmatic click -> confirm dialog

    def poll_done() -> None:
        """Wait for the dialogs to be answered, then close cleanly."""
        if done.is_set():
            _grab("05_after_close")
            stop.set()
            _status["final"] = (
                "complete" if _status["dialogs"] else "no-dialogs-seen")
            print(f"[e2e] dialogs handled: {_status['dialogs']}", flush=True)
            app._on_close()
        else:
            root.after(400, poll_done)

    def watchdog() -> None:
        """Hard exit if the flow stalls."""
        if not done.is_set():
            _status["final"] = "timeout"
            stop.set()
            print("[e2e] TIMEOUT waiting for dialogs", flush=True)
            try:
                root.destroy()
            except Exception:  # noqa: BLE001
                pass

    root.after(2500, step_dashboard)
    root.after(3200, step_about)
    root.after(400, poll_done)
    root.after(100000, watchdog)
    root.mainloop()

    (BASE / "e2e_status.json").write_text(
        json.dumps(_status, indent=2), encoding="utf-8")
    print(f"[e2e] screenshots: {SHOTS}", flush=True)
    print(f"[e2e] final: {_status['final']}", flush=True)
    return 0 if _status["final"] == "complete" else 1


if __name__ == "__main__":
    sys.exit(main())
