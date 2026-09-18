"""LocalGuard Antivirus - threat details dialog.

Shows the complete detection record per spec section 65: detection
name, severity, confidence, method, reason, hash, and factor
breakdown with recommended action.
"""

from __future__ import annotations

import tkinter as tk
from typing import Optional

import tkinter.ttk as ttk

from ui.theme import colors, severity_color
from ui.widgets import Card


def show_detection_details(parent: tk.Widget, detection, on_quarantine=None) -> None:
    """Open a modal dialog with full detection details."""
    palette = colors()
    dialog = tk.Toplevel(parent)
    dialog.title("Detection Details - LocalGuard")
    dialog.geometry("640x560")
    dialog.transient(parent.winfo_toplevel())
    dialog.grab_set()

    card = Card(dialog, padding=16)
    card.pack(fill="both", expand=True)

    header = ttk.Frame(card, style="Card.TFrame")
    header.pack(fill="x", pady=(0, 10))
    name_lbl = ttk.Label(header, text=detection.detection_name,
                         style="H2.TLabel",
                         font=("Segoe UI", 15, "bold"))
    name_lbl.pack(anchor="w")
    sev_lbl = ttk.Label(
        header, text=f"{detection.severity.upper()} - "
                     f"confidence: {detection.confidence.upper()}",
        style="Card.TLabel")
    sev_lbl.pack(anchor="w")
    try:
        sev_lbl.configure(foreground=severity_color(detection.severity))
    except tk.TclError:
        pass

    body = ttk.Frame(card, style="Card.TFrame")
    body.pack(fill="both", expand=True)

    rows = [
        ("File path", detection.path),
        ("SHA-256", detection.sha256 or "n/a"),
        ("File size", f"{detection.file_size:,} bytes"),
        ("File type", detection.file_type),
        ("Detection method", detection.detection_method),
        ("Risk score", f"{detection.risk_score} / 100"),
        ("Recommended action", detection.recommended_action),
    ]
    for label, value in rows:
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(fill="x", pady=1)
        ttk.Label(row, text=f"{label}:", style="CardDim.TLabel",
                  width=18, anchor="w").pack(side="left")
        val_lbl = ttk.Label(row, text=str(value), style="Card.TLabel",
                            wraplength=420, justify="left")
        val_lbl.pack(side="left", fill="x", expand=True)

    reason_box = tk.Text(body, height=4, wrap="word", relief="flat",
                         background=palette["bg_input"],
                         foreground=palette["fg"],
                         font=("Segoe UI", 9))
    reason_box.insert("1.0", detection.reason or "No additional reason recorded.")
    reason_box.configure(state="disabled")
    reason_box.pack(fill="x", pady=8)

    if detection.factors:
        ttk.Label(body, text="RISK FACTORS", style="H2.TLabel").pack(
            anchor="w", pady=(4, 4))
        factor_text = tk.Text(body, height=6, wrap="word", relief="flat",
                              background=palette["bg_input"],
                              foreground=palette["fg"],
                              font=("Consolas", 9))
        for factor in detection.factors:
            factor_text.insert(
                "end", f"+{factor.get('weight', '?'):>3}  "
                       f"{factor.get('factor', '?')}"
                       + (f" - {factor.get('detail')}" if factor.get("detail") else "")
                       + "\n")
        factor_text.configure(state="disabled")
        factor_text.pack(fill="both", expand=True)

    if getattr(detection, "pe_summary", ""):
        ttk.Label(body, text="PE ANALYSIS", style="H2.TLabel").pack(
            anchor="w", pady=(8, 4))
        pe_text = tk.Text(body, height=5, wrap="word", relief="flat",
                          background=palette["bg_input"],
                          foreground=palette["fg"], font=("Segoe UI", 9))
        pe_text.insert("1.0", detection.pe_summary)
        pe_text.configure(state="disabled")
        pe_text.pack(fill="both", expand=True)

    btn_row = ttk.Frame(card, style="Card.TFrame")
    btn_row.pack(fill="x", pady=(10, 0))

    if on_quarantine is not None:
        ttk.Button(btn_row, text="Quarantine This File",
                   style="Accent.TButton",
                   command=lambda: (dialog.destroy(), on_quarantine())
                   ).pack(side="left", padx=(0, 8))

    close_btn = ttk.Button(btn_row, text="Close", command=dialog.destroy)
    close_btn.pack(side="right")

    dialog.bind("<Escape>", lambda _e: dialog.destroy())
