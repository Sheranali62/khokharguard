"""Capture review screenshots of the rebranded KhokharGuard GUI.

Launches the real Tk application with every writable location
redirected into a temp dir (per tests/conftest.py conventions), walks
to the Dashboard and About pages, and saves full-window screenshots
into reports/screenshots/ for review.

Run:  .venv/Scripts/python.exe scripts/e2e_screenshots.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# DPI awareness: without it, Tk's winfo coordinates are logical while
# ImageGrab captures physical pixels, and the bbox misses the window.
import ctypes  # noqa: E402

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)  # per-monitor
except Exception:  # noqa: BLE001 - older Windows
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:  # noqa: BLE001
        pass

# Sandbox every writable location before importing app modules.
_home = Path(tempfile.mkdtemp(prefix="khokharguard_shots_"))
_appdata = _home / "AppData" / "Local"
(_appdata / "config").mkdir(parents=True)
os.environ["USERPROFILE"] = str(_home)
os.environ["LOCALAPPDATA"] = str(_appdata)

from utils import paths  # noqa: E402

paths.database_path = lambda: _home / "database" / "khokharguard.db"
paths.log_file_path = lambda: _home / "logs" / "khokharguard.log"
(_home / "database").mkdir(exist_ok=True)
(_home / "logs").mkdir(exist_ok=True)

from utils.settings import get_settings  # noqa: E402

settings = get_settings()
settings.set("general.theme", "dark")
settings.set("general.first_run_completed", True)
settings.set("protection.realtime_enabled", False)
settings.set("protection.usb_autoscan", False)
settings.set("protection.canary_enabled", False)

import tkinter as tk  # noqa: E402

from ui.app import KhokharGuardApp  # noqa: E402

OUT = ROOT / "reports" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)


def _settle(root: tk.Tk, seconds: float = 0.4) -> None:
    """Pump the event loop so deferred UI work completes."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        root.update()
        time.sleep(0.02)


def shoot(root: tk.Tk, name: str) -> None:
    from PIL import ImageGrab

    # Bring the window to the front so nothing occludes the capture.
    root.attributes("-topmost", True)
    root.lift()
    root.focus_force()
    root.update_idletasks()
    _settle(root, 0.8)
    box = (root.winfo_rootx(), root.winfo_rooty(),
           root.winfo_rootx() + root.winfo_width(),
           root.winfo_rooty() + root.winfo_height())
    path = OUT / f"{name}.png"
    ImageGrab.grab(bbox=box).save(path)
    root.attributes("-topmost", False)
    print("saved", path)


def main() -> int:
    root = tk.Tk()
    app = KhokharGuardApp(root)
    _settle(root, 1.0)

    # Dark dashboard.
    app.show_page("dashboard")
    _settle(root)
    shoot(root, "dashboard_dark")

    # About page.
    app.show_page("about")
    _settle(root)
    shoot(root, "about_dark")

    # Light dashboard for the warm-white palette.
    from ui import theme
    theme.apply_theme(root, "light")
    app.show_page("dashboard")
    _settle(root)
    shoot(root, "dashboard_light")

    root.destroy()
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
