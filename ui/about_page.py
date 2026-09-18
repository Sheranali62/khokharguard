"""LocalGuard Antivirus - about page.

Version, engine information, and the mandatory transparency
disclaimer (spec section 54).
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING

import tkinter.ttk as ttk

from ui.theme import colors
from ui.widgets import Card, StatRow

if TYPE_CHECKING:  # pragma: no cover
    from ui.app import LocalGuardApp


class AboutPage(ttk.Frame):
    """About LocalGuard."""

    def __init__(self, master: tk.Widget, app: "LocalGuardApp") -> None:
        super().__init__(master)
        self.app = app
        self._build()

    def _build(self) -> None:
        """Construct the about page."""
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=16, pady=12)

        card = Card(container)
        card.pack(fill="both", expand=True)

        palette = tk.Label(
            card, text="\U0001F6E1", font=("Segoe UI Emoji", 44),
            bg=self._card_bg(), fg=colors()["accent"],
        )
        palette.pack(pady=(16, 4))

        ttk.Label(card, text="LOCALGUARD ANTIVIRUS",
                  style="H2.TLabel",
                  font=("Segoe UI", 20, "bold")).pack()
        ttk.Label(card, text=f"Version {self.app.version}",
                  style="CardDim.TLabel").pack(pady=(2, 12))

        ttk.Label(card, text="Local-first Windows malware protection",
                  style="Card.TLabel").pack()
        ttk.Label(card,
                  text="Scanning - Signatures - Heuristics - PE Analysis - "
                       "Quarantine - Reports",
                  style="CardDim.TLabel").pack(pady=(2, 14))

        info = ttk.Frame(card, style="Card.TFrame")
        info.pack(fill="x", padx=20)
        for label, value in (
            ("Application version", self.app.version),
            ("Security engine version", self.app.engine_version),
            ("Signature database", self.app.signature_version_label()),
            ("YARA support", self.app.yara_status_label()),
            ("Platform", self.app.platform_label()),
        ):
            row = StatRow(card, label, value)
            row.pack(fill="x", pady=2, padx=20)

        disclaimer = ttk.Label(
            card,
            text="\nNo antivirus can guarantee detection or removal of "
                 "every threat.\nLocalGuard is designed to complement "
                 "Windows Security and should be used together with a "
                 "properly maintained operating system.\n",
            style="CardDim.TLabel", wraplength=560, justify="center",
        )
        disclaimer.pack(pady=(16, 12))

        license_label = ttk.Label(
            card,
            text="MIT License - see LICENSE for details.\n"
                 "LocalGuard never uploads your files. Telemetry is off "
                 "by default.",
            style="CardDim.TLabel", wraplength=560, justify="center",
        )
        license_label.pack(pady=(0, 16))

        self._build_self_test_section(container)

    # ------------------------------------------------------------------
    # EICAR self-test (spec section 15)
    # ------------------------------------------------------------------

    def _build_self_test_section(self, container: tk.Widget) -> None:
        """Add the EICAR detection self-test card."""
        from ui.widgets import Tooltip

        card = Card(container)
        card.pack(fill="x", padx=16, pady=(0, 12))

        ttk.Label(card, text="DETECTION SELF-TEST (EICAR)",
                  style="H3.TLabel").pack(anchor="w", pady=(2, 4))
        ttk.Label(
            card,
            text="Run a safe test of LocalGuard's detection engine. The "
                 "EICAR test string is a harmless, industry-standard text "
                 "(eicar.org) used by all antivirus products to verify "
                 "detection - it is not malware and cannot harm your "
                 "computer. The test file is created in a temporary "
                 "folder, never executed, scanned, and deleted "
                 "immediately afterwards.",
            style="CardDim.TLabel", wraplength=640, justify="left",
        ).pack(anchor="w", pady=(0, 8))

        self._self_test_button = ttk.Button(
            card, text="  Run Detection Self-Test  ",
            command=self._run_self_test,
        )
        self._self_test_button.pack(anchor="w", pady=(0, 2))
        Tooltip(self._self_test_button,
                "Writes the harmless EICAR test string to a temp folder, "
                "scans it, and deletes it.")

    def _run_self_test(self) -> None:
        """Run the EICAR self-test in a worker thread (GUI never blocks)."""
        import tkinter.messagebox as messagebox

        confirm = messagebox.askokcancel(
            "Detection Self-Test",
            "Run the EICAR detection self-test?\n\n"
            "EICAR is a harmless industry-standard test string - not a "
            "virus. A test file will be created in a temporary folder, "
            "scanned, and deleted immediately.",
            parent=self,
        )
        if not confirm:
            return

        self._self_test_button.state(["disabled"])

        def worker() -> None:
            """Self-test off the UI thread."""
            from ui.eicar_selftest import run_eicar_self_test

            result = run_eicar_self_test()

            def show() -> None:
                """Show the verdict on the UI thread."""
                self._self_test_button.state(["!disabled"])
                if result["status"] == "detected":
                    messagebox.showinfo(
                        "Self-Test Passed", result["detail"], parent=self)
                elif result["status"] == "another_av_active":
                    # Another AV swallowed the test file. The detail
                    # explains why and how to demonstrate a full
                    # detection verdict; Yes opens Windows Security
                    # where exclusions can be added.
                    if messagebox.askyesno(
                        "Self-Test Skipped - Another Antivirus Active",
                        result["detail"],
                        parent=self,
                    ):
                        self.app.open_windows_security()
                elif result["status"] == "defender_intercepted":
                    messagebox.showwarning(
                        "Self-Test Skipped", result["detail"], parent=self)
                else:
                    messagebox.showerror(
                        "Self-Test Problem", result["detail"], parent=self)

            self.app.ui_call(show)

        self.app.run_background(worker, "Running EICAR self-test...")

    @staticmethod
    def _card_bg() -> str:
        """Card background color for raw tk widgets."""
        return colors()["bg_card"]
