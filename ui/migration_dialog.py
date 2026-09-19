"""Khokhar & Son's Antivirus - legacy migration summary dialog.

Shown once after a successful pre-rebrand import (utils/migration.py):
summarises what was brought over and offers a shortcut to review the
imported quarantine records plus the full upgrade guide
(docs/UPGRADING.md, bundled in frozen builds). Pure presentation - the
migration itself already ran in main.py before the GUI was constructed.
"""

from __future__ import annotations

import sys
import tkinter as tk
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional

import tkinter.ttk as ttk

from ui.theme import colors
from ui.widgets import Card, add_tooltip

#: Repo-relative location of the upgrade guide (bundled by the spec).
GUIDE_REL = Path("docs") / "UPGRADING.md"
#: Online fallback when the local copy is unavailable.
GUIDE_URL = (
    "https://github.com/Sheranali62/khokharguard/blob/main/docs/UPGRADING.md"
)


def guide_path() -> Optional[Path]:
    """Return the local upgrade guide, or None when only the web copy exists."""
    roots = []
    meipass = getattr(sys, "_MEIPASS", None)  # PyInstaller bundle root
    if meipass:
        roots.append(Path(meipass))
    roots.append(Path(__file__).resolve().parent.parent)  # source checkout
    for root in roots:
        candidate = root / GUIDE_REL
        if candidate.is_file():
            return candidate
    return None


def open_guide() -> None:
    """Open the upgrade guide - local file when present, GitHub otherwise."""
    local = guide_path()
    webbrowser.open(local.as_uri() if local is not None else GUIDE_URL)


def _card_bg() -> str:
    """Resolved card background color for plain tk widgets."""
    from ui.first_run import card_style_bg

    return card_style_bg()

if TYPE_CHECKING:  # pragma: no cover
    from ui.app import KhokharGuardApp


class MigrationSummaryDialog(tk.Toplevel):
    """One-time summary of the imported legacy LocalGuard data."""

    def __init__(self, app: "KhokharGuardApp",
                 summary: Dict[str, Any]) -> None:
        super().__init__(app.root)
        self.app = app
        self.title("Data import complete")
        self.geometry("480x470")
        self.transient(app.root)
        self.grab_set()

        card = Card(self, padding=20)
        card.pack(fill="both", expand=True)

        tk.Label(card, text="\u2705", font=("Segoe UI Emoji", 34),
                 bg=_card_bg(), fg=colors()["success"]).pack(pady=(8, 4))

        ttk.Label(card, text="Your previous data was imported",
                  style="H2.TLabel",
                  font=("Segoe UI", 15, "bold")).pack()

        ttk.Label(
            card,
            text="KhokharGuard found data from the earlier LocalGuard "
                 "version and imported it. Nothing was deleted - the old "
                 "folder is untouched and can be removed manually later.",
            style="CardDim.TLabel", wraplength=400,
            justify="left").pack(pady=(6, 12))

        # --- Summary rows -------------------------------------------------
        rows = [
            ("Scan history entries", str(summary.get("history_rows", 0))),
            ("Security events", str(summary.get("events", 0))),
            ("Quarantine records", str(summary.get("quarantine_records", 0))),
            ("Files copied", str(len(summary.get("copied", [])))),
        ]
        skipped = summary.get("skipped", [])
        if skipped:
            rows.append(("Already present (skipped)", str(len(skipped))))
        rows_frame = ttk.Frame(card, style="Card.TFrame")
        rows_frame.pack(fill="x", pady=(0, 12))
        for label, value in rows:
            row = ttk.Frame(rows_frame, style="Card.TFrame")
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=label, style="CardDim.TLabel").pack(side="left")
            ttk.Label(row, text=value, style="Card.TLabel",
                      font=("Segoe UI", 10, "bold")).pack(side="right")

        # --- Quarantine shortcut ------------------------------------------
        quarantine_records = summary.get("quarantine_records", 0)
        if quarantine_records:
            review = ttk.Button(
                card, text="Review imported quarantined items",
                style="Accent.TButton",
                command=self._review_quarantine)
            review.pack(fill="x", pady=(0, 6))
            add_tooltip(review,
                        "Opens the Quarantine page where you can inspect, "
                        "restore, or delete the imported records")

        # --- Full upgrade guide -------------------------------------------
        guide_btn = ttk.Button(
            card, text="Open full upgrade guide", command=open_guide)
        guide_btn.pack(fill="x", pady=(2, 0))
        add_tooltip(
            guide_btn,
            "Opens docs/UPGRADING.md: the complete 1.0.0 to 1.1.0 upgrade "
            "path, what was imported, and rollback instructions")

        ttk.Button(card, text="Close",
                   command=self.destroy).pack(fill="x", pady=(4, 0))

    def _review_quarantine(self) -> None:
        """Jump to the Quarantine page and close this dialog."""
        self.destroy()
        self.app.show_page("quarantine")
