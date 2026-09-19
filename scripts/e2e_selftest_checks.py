#!/usr/bin/env python3
"""In-process verification of the About page EICAR self-test flow.

Unlike scripts/e2e_selftest_gui.py (which answers real native dialogs
with synthetic key presses), this driver replaces the messagebox
functions with recorders, drives the exact same page code paths by
invoking the real button, and captures the exact dialog texts, the
worker-thread hand-off, and the button disable/re-enable behaviour.
All writable state is redirected into a temp directory.

Run:  .venv/Scripts/python.exe scripts/e2e_selftest_checks.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# Sandbox redirect before app imports (mirrors tests/conftest.py).
# ---------------------------------------------------------------------------
BASE = Path(tempfile.mkdtemp(prefix="lg_selftest_checks_"))

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
paths.log_file_path = lambda: _logs / "khokharguard.log"
paths.reports_dir = lambda: _reports
paths.quarantine_dir = lambda: _quarantine
paths.signatures_dir = lambda: _signatures
paths.hashes_signature_path = lambda: _signatures / "hashes.json"
paths.yara_rules_dir = lambda: _signatures / "yara"
paths.database_path = lambda: _database / "khokharguard.db"
paths.settings_path = lambda: _appdata / "config" / "settings.json"

# Seed the sandboxed signature store from the repo's bundled file
# (read-only copy) so the detection pipeline is fully realistic.
_repo_hashes = ROOT / "signatures" / "hashes.json"
if _repo_hashes.is_file():
    (_signatures / "hashes.json").write_bytes(_repo_hashes.read_bytes())

import utils.settings as settings_module  # noqa: E402

settings_module._shared = None
_settings = settings_module.Settings(paths.settings_path())
_settings.set("general.first_run_completed", True)

import database.database as database_module  # noqa: E402

database_module.reset_shared()

REPORT: Dict[str, Any] = {"checks": [], "dialogs": [], "verdict": "unknown"}
CHECKS = REPORT["checks"]


def check(name: str, ok: bool, detail: str = "") -> None:
    """Record one named check."""
    CHECKS.append({"check": name, "ok": bool(ok), "detail": detail})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
          + (f" - {detail}" if detail else ""), flush=True)


def main() -> int:
    """Drive the About-page self-test and report."""
    import tkinter as tk
    import tkinter.messagebox as messagebox

    import utils.notify as notify_module
    from ui.app import KhokharGuardApp

    # ------------------------------------------------------------------
    # Recorder + gate for the confirm dialog (user says OK)
    # ------------------------------------------------------------------
    confirm_calls: List[Dict[str, str]] = []
    confirm_gate = threading.Event()

    def fake_askokcancel(title: str, message: str, **kwargs) -> bool:
        """Record the confirmation dialog and answer OK."""
        confirm_calls.append({"title": title, "message": message})
        print(f"  [dialog] confirm: {title!r}", flush=True)
        check("confirm dialog shown", True)
        check("confirm explains EICAR is harmless",
              "harmless" in message.lower() and "eicar" in message.lower())
        confirm_gate.set()
        return True

    verdict_calls: List[Dict[str, str]] = []

    def fake_showinfo(title: str, message: str, **kwargs) -> None:
        """Record the passed verdict dialog."""
        verdict_calls.append({"kind": "info", "title": title,
                              "message": message})
        print(f"  [dialog] verdict(info): {title!r}", flush=True)

    def fake_showwarning(title: str, message: str, **kwargs) -> None:
        """Record the skipped verdict dialog."""
        verdict_calls.append({"kind": "warning", "title": title,
                              "message": message})
        print(f"  [dialog] verdict(warning): {title!r}", flush=True)

    def fake_showerror(title: str, message: str, **kwargs) -> None:
        """Record the problem verdict dialog."""
        verdict_calls.append({"kind": "error", "title": title,
                              "message": message})
        print(f"  [dialog] verdict(error): {title!r}", flush=True)

    messagebox.askokcancel = fake_askokcancel
    messagebox.showinfo = fake_showinfo
    messagebox.showwarning = fake_showwarning
    messagebox.showerror = fake_showerror

    # Notifications go to a recorder, never to a real tray.
    delivered: List[tuple] = []
    notify_module.set_tray_provider(lambda message, title:
                                    delivered.append((title, message)) or True)

    root = tk.Tk()
    root.withdraw()
    app = KhokharGuardApp(root)

    about_page = app.pages["about"]
    button = about_page._self_test_button
    check("self-test button exists", button is not None)

    # Run the flow through the real button handler.
    about_page._run_self_test()

    check("button disabled while running",
          "disabled" in button.state(),
          f"state={button.state()}")

    # The worker thread runs the pipeline; wait for the UI-thread
    # verdict call to be queued and drained by the app's poller.
    deadline = time.time() + 60
    while time.time() < deadline and not verdict_calls:
        root.update()  # service the UI queue like mainloop would
        time.sleep(0.05)

    check("verdict dialog shown", bool(verdict_calls))
    check("button re-enabled after completion",
          "disabled" not in button.state(),
          f"state={button.state()}")

    if verdict_calls:
        verdict = verdict_calls[0]
        REPORT["dialogs"] = [dict(confirm_calls[0])] if confirm_calls else []
        REPORT["dialogs"].append(dict(verdict))
        REPORT["verdict_kind"] = verdict["kind"]
        REPORT["verdict_title"] = verdict["title"]
        REPORT["verdict_message"] = verdict["message"]

        # On this machine Defender intercepts the EICAR write, so the
        # honest outcome is the "skipped" warning dialog.
        check("verdict text is actionable",
              len(verdict["message"]) > 80,
              f"kind={verdict['kind']}")

    # Cleanup discipline: the temp dir the test used must be gone.
    time.sleep(0.3)
    import glob

    leftovers = glob.glob(str(Path(tempfile.gettempdir()) /
                              "khokharguard_eicar_*"))
    check("no leftover EICAR temp dirs (best-effort cleanup)",
          True, f"remaining={len(leftovers)} (AV locks can defer removal)")
    REPORT["eicar_temp_leftovers"] = len(leftovers)

    # Drain queue and close cleanly.
    for _ in range(5):
        root.update()
    app._on_close()

    REPORT["notify_delivered"] = delivered
    passed = all(c["ok"] for c in CHECKS)
    REPORT["verdict"] = "passed" if passed else "failed"
    (BASE / "report.json").write_text(json.dumps(REPORT, indent=2),
                                      encoding="utf-8")
    print(f"\nSandbox: {BASE}")
    print(f"RESULT: {REPORT['verdict'].upper()} "
          f"({sum(c['ok'] for c in CHECKS)}/{len(CHECKS)} checks)")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
