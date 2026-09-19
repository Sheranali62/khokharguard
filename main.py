#!/usr/bin/env python3
"""Khokhar & Son's Antivirus - application entry point.

Launches the GUI by default and provides a safe, read-mostly CLI
(spec section 58):

    python main.py                    # launch GUI
    python main.py scan <path>        # scan a file/folder/drive
    python main.py quick-scan         # quick scan
    python main.py scan-usb <drv>     # scan a removable drive
    python main.py quarantine         # list quarantined items
    python main.py status             # protection status summary
    python main.py service <action>   # install/start/stop the service
    python main.py version            # print version

The CLI deliberately exposes no arbitrary command execution.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

# Ensure project root is importable when run from any CWD.
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils import paths  # noqa: E402
from utils.logger import setup_logging  # noqa: E402


def _build_cli_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="KhokharGuard",
        description="Khokhar & Son's Antivirus - local-first Windows malware "
                    "protection (complements Windows Security).",
    )
    parser.add_argument("--version", action="store_true",
                        help="print version and exit")

    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="scan a file, folder, or drive")
    scan_p.add_argument("path", help="path to scan")

    sub.add_parser("quick-scan", help="scan common infection locations")

    usb_p = sub.add_parser("scan-usb", help="scan a removable drive")
    usb_p.add_argument("drive", help="drive letter, e.g. E:\\ or E:")

    sub.add_parser("quarantine", help="list quarantined items")

    restore_p = sub.add_parser("restore", help="restore a quarantined item")
    restore_p.add_argument("id", type=int, help="quarantine record ID")

    sub.add_parser("status", help="show protection status")
    sub.add_parser("version", help="print version")

    service_p = sub.add_parser(
        "service", help="manage the background protection service")
    service_p.add_argument(
        "action",
        choices=["install", "uninstall", "start", "stop", "status", "run"],
        help="service lifecycle action")

    return parser


# ---------------------------------------------------------------------------
# CLI command implementations
# ---------------------------------------------------------------------------

def _cli_services():
    """Initialise shared engine services for CLI use."""
    from database.database import get_database
    from engine.file_analyzer import FileAnalyzer
    from engine.signature_engine import SignatureEngine
    from engine.yara_engine import YaraEngine

    database = get_database()
    signatures = SignatureEngine(database=database)
    analyzer = FileAnalyzer(signature_engine=signatures, yara_engine=YaraEngine())
    return database, analyzer


def _print_detections(detections) -> int:
    """Print detections; return count."""
    findings = [d for d in detections
                if d.severity in {"medium", "high", "critical"}]
    for detection in findings:
        print(f"\n[{detection.severity.upper()}] {detection.detection_name}")
        print(f"  File:      {detection.path}")
        print(f"  SHA-256:   {detection.sha256 or 'n/a'}")
        print(f"  Risk:      {detection.risk_score}/100 "
              f"(confidence: {detection.confidence})")
        print(f"  Method:    {detection.detection_method}")
        print(f"  Reason:    {detection.reason}")
        print(f"  Action:    {detection.recommended_action}")
    return len(findings)


def cli_scan(path: str) -> int:
    """Scan one path synchronously and print results."""
    target = Path(path)
    if not target.exists():
        print(f"Error: path does not exist: {target}")
        return 2

    from engine.scan_controller import ScanController

    database, analyzer = _cli_services()
    controller = ScanController(analyzer=analyzer, database=database, threads=4)
    controller.on_detection = lambda d: None

    print(f"Scanning {target} ...")
    controller.start([target],
                     scan_type="usb" if _is_removable(target) else "custom")
    controller.wait()

    stats = controller.stats
    if stats is None:
        print("Scan failed to start.")
        return 2

    print(f"\nScan complete ({controller.state and 'done'})")
    print(f"  Files scanned: {stats.files_scanned:,}")
    print(f"  Threats:       {stats.threats_found}")
    print(f"  Suspicious:    {stats.suspicious_found}")
    print(f"  Skipped:       {stats.skipped}")
    print(f"  Errors:        {stats.errors}")

    findings = 0
    for detection in stats.detections:
        findings += _print_detections([detection])
    if findings == 0:
        print("\nNo threats or suspicious files detected.")
    else:
        print(f"\n{findings} finding(s) recorded in the database. "
              "Review them in the GUI or quarantine page.")
    return 0 if findings == 0 else 1


def _is_removable(path: Path) -> bool:
    """True when path is a removable drive root."""
    from utils.windows_utils import get_removable_drives

    return any(
        str(path).upper().startswith(str(d["mountpoint"]).upper())
        for d in get_removable_drives()
    )


def _migrate_legacy_data() -> None:
    """One-time import of pre-rebrand LocalGuard data (main.py helper)."""
    try:
        from utils.migration import maybe_migrate

        maybe_migrate()
    except Exception:  # noqa: BLE001 - startup must never break on this
        logger.exception("Legacy data migration skipped after error")


def cli_quick_scan() -> int:
    """Quick scan of common infection locations."""
    _migrate_legacy_data()
    userprofile = Path.home()
    local = Path(__import__("os").environ.get(
        "LOCALAPPDATA", str(userprofile / "AppData" / "Local")))
    targets = [t for t in (
        userprofile / "Downloads", userprofile / "Desktop",
        local / "Temp",
    ) if t.is_dir()]
    if not targets:
        print("No quick-scan locations found.")
        return 2
    return cli_scan_multi(targets, scan_type="quick")


def cli_scan_multi(targets: List[Path], scan_type: str = "custom") -> int:
    """Scan multiple targets (shared by quick scan)."""
    from engine.scan_controller import ScanController

    database, analyzer = _cli_services()
    controller = ScanController(analyzer=analyzer, database=database, threads=4)
    print(f"Quick scan of {len(targets)} location(s) ...")
    controller.start(targets, scan_type=scan_type, deep_extensions_only=True)
    controller.wait()
    stats = controller.stats
    if stats is None:
        return 2
    print(f"Files scanned: {stats.files_scanned:,}  "
          f"Threats: {stats.threats_found}  "
          f"Suspicious: {stats.suspicious_found}  "
          f"Errors: {stats.errors}")
    findings = 0
    for detection in stats.detections:
        findings += _print_detections([detection])
    if findings == 0:
        print("No threats or suspicious files detected.")
    return 0 if findings == 0 else 1


def cli_quarantine_list() -> int:
    """List quarantined items."""
    database, _ = _cli_services()
    records = database.list_quarantine(active_only=True)
    if not records:
        print("Quarantine is empty.")
        return 0
    print(f"{len(records)} quarantined item(s):\n")
    for record in records:
        print(f"  ID {record['quarantine_id']}: {record['detection_name']}")
        print(f"    Original: {record['original_path']}")
        print(f"    Severity: {record['severity']}  "
              f"Date: {record['quarantine_date']}")
        print(f"    SHA-256:  {record['sha256']}")
    print("\nRestore via the GUI (Quarantine page) or: "
          "KhokharGuard restore <ID>")
    return 0


def cli_restore(quarantine_id: int) -> int:
    """Restore a quarantined item (explicit CLI action)."""
    from quarantine.quarantine_manager import QuarantineError, QuarantineManager

    try:
        path = QuarantineManager().restore(quarantine_id,
                                           user_confirmed=True)
        print(f"Restored to: {path}")
        return 0
    except QuarantineError as exc:
        print(f"Restore failed: {exc}")
        return 1


def cli_status() -> int:
    """Print protection status summary."""
    from utils.windows_utils import get_defender_status, is_admin
    from utils.settings import get_settings
    from database.database import get_database
    from engine.signature_engine import SignatureEngine

    settings = get_settings()
    database = get_database()
    signature_count = SignatureEngine(database=database).count
    defender = get_defender_status()

    print("KHOKHARGUARD STATUS")
    print("=" * 40)
    print(f"Version:                  {paths.version()}")
    print(f"Real-time protection:     "
          f"{'ON' if settings.get('protection.realtime_enabled') else 'OFF'}")
    print(f"USB auto-scan:            "
          f"{'ON' if settings.get('protection.usb_autoscan') else 'OFF'}")
    print(f"Administrator privileges: {'YES' if is_admin() else 'NO'}")
    if defender.get("available"):
        print(f"Windows Security:         connected "
              f"(real-time {'ON' if defender.get('realtime_enabled') else 'OFF'})")
    else:
        print("Windows Security:         status unavailable")
    print(f"Signature database:       {signature_count} signatures")
    print(f"Quarantined items:        {database.quarantine_count()}")
    counts = database.threat_counts()
    print(f"Open threats:             {counts.get('open', 0)}")
    print()
    print("KhokharGuard complements Windows Security; it does not replace it.")
    return 0


def cli_service(action: str) -> int:
    """Manage the background protection service lifecycle."""
    import sys as _sys

    from services.service_control import (
        ServiceControlError,
        install_service,
        service_installed,
        service_running,
        start_service,
        stop_service,
        uninstall_service,
    )

    try:
        if action == "install":
            install_service()
            print(f"Service installed ({service_installed()}).")
            print("Start it with: KhokharGuard service start")
            return 0
        if action == "uninstall":
            uninstall_service()
            print("Service removed.")
            return 0
        if action == "start":
            start_service()
            print("Service started.")
            return 0
        if action == "stop":
            stop_service()
            print("Service stopped.")
            return 0
        if action == "status":
            print(f"Installed: {service_installed()}")
            print(f"Running:   {service_running()}")
            return 0
        if action == "run":
            # Headless core for console-session use (no SCM needed):
            # keeps protecting until stopped via IPC ('shutdown') or
            # Ctrl+C. For the SCM-managed service use 'service start'.
            from services.windows_service import run_service_core

            try:
                return run_service_core()
            except KeyboardInterrupt:
                print("\nService core stopped.")
                return 0
    except ServiceControlError as exc:
        print(f"Service error: {exc}")
        return 1
    print(f"Unknown service action: {action}")
    return 2


def cli_main(argv: Optional[List[str]] = None) -> int:
    """CLI dispatch."""
    parser = _build_cli_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"Khokhar & Son's Antivirus {paths.version()}")
        return 0
    if args.command is None:
        parser.print_help()
        return 0

    setup_logging()

    if args.command == "scan":
        return cli_scan(args.path)
    if args.command == "quick-scan":
        return cli_quick_scan()
    if args.command == "scan-usb":
        drive = args.drive if args.drive.endswith(":\\") else args.drive + ":\\"
        return cli_scan(drive)
    if args.command == "quarantine":
        return cli_quarantine_list()
    if args.command == "restore":
        return cli_restore(args.id)
    if args.command == "status":
        return cli_status()
    if args.command == "service":
        return cli_service(args.action)
    if args.command == "version":
        print(f"Khokhar & Son's Antivirus {paths.version()}")
        return 0
    parser.print_help()
    return 0


def run_gui() -> int:
    """Launch the Tkinter GUI."""
    setup_logging()
    _migrate_legacy_data()

    import tkinter as tk

    from ui.app import KhokharGuardApp

    root = tk.Tk()
    try:
        app = KhokharGuardApp(root)
    except Exception:  # noqa: BLE001 - show fatal errors cleanly
        import logging
        import traceback

        logging.getLogger("khokharguard").critical(
            "GUI initialisation failed", exc_info=True)
        traceback.print_exc()
        return 1

    _show_migration_summary(app)
    root.mainloop()
    logger.info("Application exited")
    return 0


def _show_migration_summary(app) -> None:
    """Show the legacy-import summary once after a fresh migration."""
    try:
        from utils.migration import pending_notification

        summary = pending_notification()
    except Exception:  # noqa: BLE001 - never block startup on this
        return
    if not summary:
        return
    try:
        from ui.migration_dialog import MigrationSummaryDialog

        app.root.after(600, lambda: MigrationSummaryDialog(app, summary))
    except Exception:  # noqa: BLE001 - dialog is optional sugar
        logger.exception("Migration summary dialog failed")


def _service_host() -> int:
    """Handle SCM service hosting dispatch (frozen exe only).

    When the SCM starts the registered service it launches
    ``KhokharGuard.exe service run`` with a SCM process context. Only
    then may we hand control to pywin32's service manager; the same
    command typed by a user in a console must run the headless core
    directly (the dispatcher fails with error 1063 outside the SCM).
    """
    if sys.platform != "win32":
        return 1
    try:
        import servicemanager

        # Detect the SCM context: the SCM launches the service process
        # as a child of services.exe; a console launch has a shell or
        # explorer parent. psutil (already a core dependency) resolves
        # this portably.
        def _scm_launched() -> bool:
            """True when our parent process is services.exe."""
            try:
                import psutil

                parent = psutil.Process().parent()
                return bool(parent) and parent.name().lower() == "services.exe"
            except Exception:  # noqa: BLE001 - psutil missing or denied
                return False

        if not _scm_launched():
            # Console launch: run the headless core directly.
            return cli_main(["service", "run"])

        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(
            __import__("services.service_control",
                       fromlist=["KhokharGuardWinService"]).KhokharGuardWinService)
        servicemanager.StartServiceCtrlDispatcher()
        return 0
    except Exception as exc:  # noqa: BLE001 - SCM reports via event log
        print(f"Service hosting failed: {exc}", file=sys.stderr)
        return 1


def main() -> int:
    """Entry point: GUI unless CLI arguments are present."""
    argv = sys.argv[1:]
    if argv and argv[0] in {
        "scan", "quick-scan", "scan-usb", "quarantine", "restore",
        "status", "service", "version",
    } or (argv and argv[0] == "--version"):
        # SCM hosting: 'service run' launched by the service control
        # manager must dispatch to the registered service class rather
        # than run the console core.
        if argv and argv[0] == "service" and len(argv) > 1 \
                and argv[1] == "run" and getattr(sys, "frozen", False):
            return _service_host()
        return cli_main(argv)
    return run_gui()


if __name__ == "__main__":
    sys.exit(main())
