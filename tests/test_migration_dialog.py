"""Tests for the migration summary dialog and its upgrade-guide link.

Structural tests only (no screenshots): the dialog is built against a
minimal app stub exposing just what it uses (root + show_page). Skipped
automatically when no interactive display is available (headless CI).
All paths sandboxed per tests/conftest.py.
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import List

import pytest

tkinter = pytest.importorskip("tkinter")

from ui import migration_dialog as md  # noqa: E402


class _StubApp:
    """Just enough of KhokharGuardApp for the dialog."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.pages: List[str] = []

    def show_page(self, page_id: str) -> None:  # noqa: D102 - stub
        self.pages.append(page_id)


@pytest.fixture(scope="module")
def root_tk():
    """One Tk root for the module; skipped when Tk cannot initialise."""
    try:
        root = tk.Tk()
    except tk.TclError as exc:  # headless environment
        pytest.skip(f"Tk unavailable: {exc}")
    root.withdraw()
    yield root
    root.destroy()


def test_guide_path_found_in_source_tree() -> None:
    """The bundled/source upgrade guide resolves from the repo layout."""
    found = md.guide_path()
    assert found is not None
    assert found.name == "UPGRADING.md"
    assert found.is_file()


def test_open_guide_uses_local_file(monkeypatch) -> None:
    """When the local doc exists, it is opened (file URI), not the web."""
    opened: List[str] = []
    monkeypatch.setattr(md.webbrowser, "open", lambda u: opened.append(u))
    md.open_guide()
    assert len(opened) == 1
    assert opened[0].lower().startswith("file://")
    assert opened[0].lower().endswith("upgrading.md")


def test_open_guide_falls_back_to_web(monkeypatch) -> None:
    """Without a local copy the GitHub page is opened instead."""
    opened: List[str] = []
    monkeypatch.setattr(md.webbrowser, "open", lambda u: opened.append(u))
    monkeypatch.setattr(md, "guide_path", lambda: None)
    md.open_guide()
    assert opened == [md.GUIDE_URL]


def test_dialog_shows_summary_and_review_jumps_to_quarantine(root_tk) -> None:
    """Full summary: rows, quarantine shortcut, guide button, close."""
    app = _StubApp(root_tk)
    summary = {
        "history_rows": 3,
        "events": 7,
        "quarantine_records": 2,
        "copied": ["a", "b", "c", "d"],
        "skipped": ["already-here"],
    }
    dlg = md.MigrationSummaryDialog(app, summary)
    root_tk.update_idletasks()

    texts = []
    for child in dlg.winfo_children():
        texts.append(str(child))
    assert dlg.title() == "Data import complete"

    # Every button we promise exists.
    buttons = _button_texts(dlg)
    assert "Review imported quarantined items" in buttons
    assert "Open full upgrade guide" in buttons
    assert "Close" in buttons

    # The review shortcut navigates to the Quarantine page.
    for widget in _walk(dlg):
        if isinstance(widget, tk.ttk.Button) and \
                str(widget.cget("text")) == "Review imported quarantined items":
            widget.invoke()
            break
    assert app.pages == ["quarantine"]
    assert not dlg.winfo_exists()  # dialog closed itself


def test_dialog_without_quarantine_records_has_no_review_button(root_tk) -> None:
    """No imported quarantine records -> no review shortcut offered."""
    app = _StubApp(root_tk)
    dlg = md.MigrationSummaryDialog(
        app, {"history_rows": 0, "events": 0, "quarantine_records": 0,
              "copied": [], "skipped": []})
    root_tk.update_idletasks()
    buttons = _button_texts(dlg)
    assert "Review imported quarantined items" not in buttons
    assert "Open full upgrade guide" in buttons
    dlg.destroy()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _walk(widget):  # type: ignore[no-untyped-def]
    yield widget
    for child in widget.winfo_children():
        yield from _walk(child)


def _button_texts(widget) -> List[str]:  # type: ignore[no-untyped-def]
    import tkinter.ttk as ttk

    return [
        str(w.cget("text")) for w in _walk(widget)
        if isinstance(w, (ttk.Button, tk.Button))
    ]
