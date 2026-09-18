"""LocalGuard Antivirus - reusable UI widgets.

Card container, tooltip helper, status banner, and labelled stat rows
shared by all pages (spec sections 5, 6).
"""

from __future__ import annotations

import tkinter as tk
from typing import Optional

import tkinter.ttk as ttk

from ui.theme import colors


class Card(ttk.Frame):
    """A flat card container with consistent padding."""

    def __init__(self, master: tk.Widget, padding: int = 14, **kwargs) -> None:
        super().__init__(master, style="Card.TFrame", padding=padding, **kwargs)


class Tooltip:
    """Simple hover tooltip (bounded, non-blocking)."""

    def __init__(self, widget: tk.Widget, text: str, delay_ms: int = 500) -> None:
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self._tip: Optional[tk.Toplevel] = None
        self._after_id: Optional[str] = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None) -> None:
        """Show tooltip after delay."""
        self._cancel()
        self._after_id = self.widget.after(self.delay_ms, self._show)

    def _cancel(self) -> None:
        """Cancel pending show."""
        if self._after_id is not None:
            self.widget.after_cancel(self._after_id)
            self._after_id = None

    def _show(self) -> None:
        """Display the tooltip window."""
        if self._tip is not None:
            return
        x = self.widget.winfo_rootx() + 12
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self._tip = tk.Toplevel(self.widget)
        self._tip.wm_overrideredirect(True)
        self._tip.wm_geometry(f"+{x}+{y}")
        palette = colors()
        label = tk.Label(
            self._tip, text=self.text, justify="left",
            background=palette["bg_alt"], foreground=palette["fg"],
            relief="solid", borderwidth=1,
            font=("Segoe UI", 9),
            wraplength=320,
        )
        label.pack(ipadx=6, ipady=4)

    def _hide(self, _event=None) -> None:
        """Hide the tooltip."""
        self._cancel()
        if self._tip is not None:
            self._tip.destroy()
            self._tip = None


def add_tooltip(widget: tk.Widget, text: str) -> Tooltip:
    """Attach a tooltip to a widget."""
    return Tooltip(widget, text)


class StatRow(ttk.Frame):
    """One 'label ..... value' row used on the dashboard."""

    def __init__(self, master: tk.Widget, label: str, value: str = "",
                 card: bool = True) -> None:
        super().__init__(master, style="Card.TFrame" if card else "TFrame")
        self.label = ttk.Label(self, text=label, style="CardDim.TLabel" if card else "Dim.TLabel")
        self.value_var = tk.StringVar(value=value)
        self.value = ttk.Label(self, textvariable=self.value_var,
                               style="Card.TLabel" if card else "TLabel")
        self.label.pack(side="left", anchor="w")
        self.value.pack(side="right", anchor="e")

    def set(self, value: str) -> None:
        """Update the value text."""
        self.value_var.set(value)


class StatusBanner(Card):
    """Large protection status banner with colored state text."""

    def __init__(self, master: tk.Widget) -> None:
        super().__init__(master, padding=20)
        palette = colors()
        self.icon = tk.Label(self, text="\U0001F6E1", font=("Segoe UI Emoji", 30),
                             bg=palette["bg_card"], fg=palette["success"])
        self.icon.pack(side="left", padx=(0, 16))
        text_frame = ttk.Frame(self, style="Card.TFrame")
        text_frame.pack(side="left", fill="x", expand=True)
        self.title_var = tk.StringVar(value="PROTECTED")
        self.title = ttk.Label(text_frame, textvariable=self.title_var,
                               style="H2.TLabel", font=("Segoe UI", 18, "bold"))
        self.title.pack(anchor="w")
        self.subtitle_var = tk.StringVar(value="All protection components active")
        self.subtitle = ttk.Label(text_frame, textvariable=self.subtitle_var,
                                  style="CardDim.TLabel")
        self.subtitle.pack(anchor="w")

    def set_state(self, state: str, subtitle: str, level: str = "success") -> None:
        """Update banner text and color."""
        palette = colors()
        self.title_var.set(state)
        self.subtitle_var.set(subtitle)
        color = {
            "success": palette["success"], "warning": palette["warning"],
            "danger": palette["danger"],
        }.get(level, palette["fg"])
        self.icon.configure(fg=color)
        self.title.configure(foreground=color)


class ScrollFrame(ttk.Frame):
    """Vertical scrollable frame container."""

    def __init__(self, master: tk.Widget) -> None:
        super().__init__(master)
        self.canvas = tk.Canvas(self, highlightthickness=0,
                                bg=colors()["bg"])
        scrollbar = ttk.Scrollbar(self, orient="vertical",
                                  command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas)
        self.inner.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas_window = self.canvas.create_window(
            (0, 0), window=self.inner, anchor="nw"
        )
        self.canvas.bind(
            "<Configure>",
            lambda e: self.canvas.itemconfig(self.canvas_window, width=e.width)
        )
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        # Mouse wheel scrolling (Windows convention)
        self.canvas.bind_all("<MouseWheel>", self._on_wheel, add="+")

    def _on_wheel(self, event) -> None:
        """Scroll on wheel delta."""
        try:
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        except tk.TclError:
            pass


def make_treeview(master: tk.Widget, columns, *,
                  heights: int = 12) -> ttk.Treeview:
    """Create a configured Treeview with scrollbars.

    ``columns`` maps column id -> (heading text, width, anchor).
    """
    frame = ttk.Frame(master)
    tree = ttk.Treeview(frame, columns=list(columns.keys()),
                        show="headings", height=heights)
    vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)
    tree._scrollframe = frame  # type: ignore[attr-defined]
    for col_id, (text, width, anchor) in columns.items():
        tree.heading(col_id, text=text)
        tree.column(col_id, width=width, anchor=anchor)
    return tree
