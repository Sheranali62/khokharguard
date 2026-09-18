"""LocalGuard Antivirus - first-run welcome dialog.

Shown on first launch (spec section 59): introduces components and
asks for USB auto-scan, real-time protection, and start-with-Windows
with clear explanations. Every choice is changeable in Settings.
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING

import tkinter.ttk as ttk

from ui.theme import colors
from ui.widgets import Card

if TYPE_CHECKING:  # pragma: no cover
    from ui.app import LocalGuardApp


class FirstRunDialog(tk.Toplevel):
    """Welcome + protection options dialog."""

    def __init__(self, app: "LocalGuardApp") -> None:
        super().__init__(app.root)
        self.app = app
        self.title("Welcome to LocalGuard")
        self.geometry("560x520")
        self.transient(app.root)
        self.grab_set()

        card = Card(self, padding=20)
        card.pack(fill="both", expand=True)

        tk.Label(card, text="\U0001F6E1", font=("Segoe UI Emoji", 40),
                 bg=card_style_bg(), fg=colors()["accent"]).pack(pady=(8, 4))

        ttk.Label(card, text="Welcome to LocalGuard",
                  style="H2.TLabel",
                  font=("Segoe UI", 18, "bold")).pack()
        ttk.Label(card,
                  text="Local-first antivirus protection for Windows",
                  style="CardDim.TLabel").pack(pady=(0, 10))

        components = "\n".join([
            "\u2713  Local Scanner (quick / full / custom)",
            "\u2713  USB Scanner",
            "\u2713  Quarantine with restore",
            "\u2713  Real-Time Monitoring",
        ])
        ttk.Label(card, text=components, style="Card.TLabel",
                  justify="left").pack(anchor="w", pady=(0, 12))

        self.usb_var = tk.BooleanVar(value=True)
        self.rt_var = tk.BooleanVar(value=True)
        self.startup_var = tk.BooleanVar(value=False)

        self._option(
            card, "Enable USB Auto Scan", self.usb_var,
            "Scan removable drives automatically when inserted.",
        )
        self._option(
            card, "Enable Real-Time Protection", self.rt_var,
            "Watch Downloads, Desktop and Temp for new suspicious files.",
        )
        self._option(
            card, "Start with Windows", self.startup_var,
            "Registers LocalGuard in the visible HKCU Run key. "
            "Changeable anytime in Settings.",
        )

        ttk.Label(card,
                  text="No antivirus can guarantee detection of every "
                       "threat. LocalGuard complements Windows Security.",
                  style="CardDim.TLabel", wraplength=480,
                  justify="center").pack(pady=(12, 10))

        btn_row = ttk.Frame(card, style="Card.TFrame")
        btn_row.pack(fill="x", pady=(0, 8))
        ttk.Button(btn_row, text="Get Started", style="Accent.TButton",
                   command=self._finish).pack(side="right")

    def _option(self, master: tk.Widget, label: str, var: tk.BooleanVar,
                description: str) -> None:
        """One clearly-explained option checkbox."""
        row = ttk.Frame(master, style="Card.TFrame")
        row.pack(fill="x", pady=6)
        check = ttk.Checkbutton(row, text=label, variable=var,
                                style="Card.TCheckbutton")
        check.pack(anchor="w")
        ttk.Label(row, text="     " + description,
                  style="CardDim.TLabel",
                  wraplength=460, justify="left").pack(anchor="w")

    def _finish(self) -> None:
        """Apply choices and close."""
        settings = self.app.settings
        settings.set("protection.usb_autoscan", bool(self.usb_var.get()))
        settings.set("protection.realtime_enabled", bool(self.rt_var.get()))
        settings.set("general.start_with_windows", bool(self.startup_var.get()))
        settings.set("general.first_run_completed", True)

        if self.startup_var.get():
            from services.startup_service import enable_start_with_windows

            enable_start_with_windows()

        self.app.apply_protection_settings()
        self.destroy()


def card_style_bg() -> str:
    """Card background for raw tk labels."""
    return colors()["bg_card"]
