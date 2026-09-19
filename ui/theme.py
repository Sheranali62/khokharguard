"""Khokhar & Son's Antivirus - UI theme.

Dark and light ttk theme configuration using a consistent palette
(spec section 6). No animations; accessible contrast; keyboard focus
visible on all interactive widgets.
"""

from __future__ import annotations

import tkinter as tk
from typing import Dict

PALETTES: Dict[str, Dict[str, str]] = {
    "dark": {
        "bg": "#1e1f24",
        "bg_alt": "#26272e",
        "bg_card": "#26272e",
        "bg_input": "#2c2d35",
        "fg": "#e8e9ed",
        "fg_dim": "#9a9caa",
        "accent": "#D4AF37",
        "accent_hover": "#E3C566",
        "accent_fg": "#0B0B0B",
        "success": "#22c55e",
        "warning": "#f59e0b",
        "danger": "#ef4444",
        "danger_hover": "#dc2626",
        "border": "#3a3b44",
        "select": "#334155",
        "row_even": "#26272e",
        "row_odd": "#2b2c34",
    },
    "light": {
        "bg": "#F7F5F0",
        "bg_alt": "#EFEBE1",
        "bg_card": "#FFFDF8",
        "bg_input": "#FFFFFF",
        "fg": "#1a1c22",
        "fg_dim": "#5f6470",
        "accent": "#B8962E",
        "accent_hover": "#A4841F",
        "accent_fg": "#ffffff",
        "success": "#16a34a",
        "warning": "#d97706",
        "danger": "#dc2626",
        "danger_hover": "#b91c1c",
        "border": "#DAD4C4",
        "select": "#F1E7C8",
        "row_even": "#ffffff",
        "row_odd": "#f6f7f9",
    },
}

_current: Dict[str, str] = dict(PALETTES["dark"])


def colors() -> Dict[str, str]:
    """Active palette."""
    return _current


def palette_name() -> str:
    """Current palette name ('dark' | 'light')."""
    return "dark" if _current is PALETTES["dark"] else "light"


def apply_theme(root: tk.Widget, name: str) -> None:
    """Apply the named palette to the Tk instance and ttk styles."""
    import tkinter.ttk as ttk

    palette = PALETTES.get(name, PALETTES["dark"])
    _current.clear()
    _current.update(palette)

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass  # keep default engine when clam is unavailable

    style.configure(".", background=palette["bg"], foreground=palette["fg"],
                    fieldbackground=palette["bg_input"],
                    bordercolor=palette["border"],
                    lightcolor=palette["bg_card"],
                    darkcolor=palette["bg_card"],
                    troughcolor=palette["bg_alt"],
                    focuscolor=palette["accent"],
                    selectbackground=palette["select"],
                    selectforeground=palette["fg"])

    style.configure("TFrame", background=palette["bg"])
    style.configure("Card.TFrame", background=palette["bg_card"],
                    relief="flat")
    style.configure("TLabel", background=palette["bg"], foreground=palette["fg"])
    style.configure("Card.TLabel", background=palette["bg_card"],
                    foreground=palette["fg"])
    style.configure("Dim.TLabel", background=palette["bg"],
                    foreground=palette["fg_dim"])
    style.configure("CardDim.TLabel", background=palette["bg_card"],
                    foreground=palette["fg_dim"])
    style.configure("Title.TLabel", background=palette["bg"],
                    foreground=palette["fg"],
                    font=("Segoe UI", 16, "bold"))
    style.configure("H2.TLabel", background=palette["bg_card"],
                    foreground=palette["fg"], font=("Segoe UI", 11, "bold"))
    style.configure("H3.TLabel", background=palette["bg_card"],
                    foreground=palette["fg"], font=("Segoe UI", 10, "bold"))
    style.configure("H1.TLabel", background=palette["bg"],
                    foreground=palette["fg"], font=("Segoe UI", 26, "bold"))

    style.configure("TButton", background=palette["bg_alt"],
                    foreground=palette["fg"], padding=(12, 6),
                    bordercolor=palette["border"], focuscolor=palette["accent"])
    style.map("TButton",
              background=[("active", palette["select"]),
                          ("pressed", palette["border"])],
              foreground=[("disabled", palette["fg_dim"])])

    style.configure("Accent.TButton", background=palette["accent"],
                    foreground=palette["accent_fg"], padding=(16, 8))
    style.map("Accent.TButton",
              background=[("active", palette["accent_hover"]),
                          ("pressed", palette["accent_hover"])],
              foreground=[("disabled", palette["accent_fg"])])

    style.configure("Danger.TButton", background=palette["danger"],
                    foreground="#ffffff", padding=(12, 6))
    style.map("Danger.TButton",
              background=[("active", palette["danger_hover"]),
                          ("pressed", palette["danger_hover"])])

    style.configure("Success.TButton", background=palette["success"],
                    foreground="#ffffff", padding=(12, 6))
    style.map("Success.TButton",
              background=[("active", palette["success"])])

    style.configure("TEntry", fieldbackground=palette["bg_input"],
                    foreground=palette["fg"], insertcolor=palette["fg"],
                    bordercolor=palette["border"])
    style.configure("TCombobox", fieldbackground=palette["bg_input"],
                    foreground=palette["fg"],
                    arrowcolor=palette["fg"])
    style.map("TCombobox",
              fieldbackground=[("readonly", palette["bg_input"])],
              selectbackground=[("readonly", palette["select"])])

    style.configure("Treeview", background=palette["bg_card"],
                    foreground=palette["fg"], fieldbackground=palette["bg_card"],
                    bordercolor=palette["border"], rowheight=26)
    style.map("Treeview",
              background=[("selected", palette["select"])],
              foreground=[("selected", palette["fg"])])
    style.configure("Treeview.Heading", background=palette["bg_alt"],
                    foreground=palette["fg"], padding=(6, 6))

    style.configure("TCheckbutton", background=palette["bg"],
                    foreground=palette["fg"], focuscolor=palette["accent"])
    style.map("TCheckbutton", background=[("active", palette["bg"])])
    style.configure("Card.TCheckbutton", background=palette["bg_card"],
                    foreground=palette["fg"])
    style.map("Card.TCheckbutton", background=[("active", palette["bg_card"])])

    style.configure("Horizontal.TProgressbar",
                    background=palette["accent"],
                    troughcolor=palette["bg_alt"],
                    bordercolor=palette["bg"], thickness=8)

    style.configure("TRadiobutton", background=palette["bg"],
                    foreground=palette["fg"], focuscolor=palette["accent"])
    style.map("TRadiobutton", background=[("active", palette["bg"])])

    style.configure("TLabelframe", background=palette["bg"],
                    foreground=palette["fg"], bordercolor=palette["border"])
    style.configure("TLabelframe.Label", background=palette["bg"],
                    foreground=palette["fg"])

    style.configure("TNotebook", background=palette["bg"],
                    bordercolor=palette["border"])
    style.configure("TNotebook.Tab", background=palette["bg_alt"],
                    foreground=palette["fg"], padding=(14, 6))
    style.map("TNotebook.Tab",
              background=[("selected", palette["accent"])],
              foreground=[("selected", palette["accent_fg"])])

    style.configure("TSeparator", background=palette["border"])

    style.configure("Vertical.TScrollbar", background=palette["bg_alt"],
                    troughcolor=palette["bg"], bordercolor=palette["bg"],
                    arrowcolor=palette["fg_dim"])
    style.configure("Horizontal.TScrollbar", background=palette["bg_alt"],
                    troughcolor=palette["bg"], bordercolor=palette["bg"],
                    arrowcolor=palette["fg_dim"])

    root.configure(bg=palette["bg"])


def severity_color(severity: str) -> str:
    """Map severity labels to palette colors."""
    return {
        "clean": _current["success"],
        "low": _current["success"],
        "medium": _current["warning"],
        "high": _current["danger"],
        "critical": _current["danger"],
    }.get(severity, _current["fg"])
