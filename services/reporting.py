"""Khokhar & Son's Antivirus - report generation.

Produces human-readable TXT reports and machine-readable CSV/JSON
exports for scan sessions (spec section 32). Reports contain only
scan facts and detection metadata - never file contents.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils import get_logger, paths
from utils.file_utils import format_duration, human_size

logger = get_logger("reporting")


def _scan_record(scan_id: int) -> Optional[Dict[str, Any]]:
    """Fetch the scan_history row for a scan."""
    from database.database import get_database

    return get_database().query_one(
        "SELECT * FROM scan_history WHERE scan_id = ?", (scan_id,)
    )


def _scan_results(scan_id: int) -> List[Dict[str, Any]]:
    """Fetch per-file results for a scan."""
    from database.database import get_database

    return get_database().results_for_scan(scan_id)


def generate_text_report(scan_id: int) -> str:
    """Build the human-readable security report."""
    scan = _scan_record(scan_id)
    if scan is None:
        return "No scan found for this ID."

    results = _scan_results(scan_id)
    lines = [
        "=" * 60,
        "KHOKHARGUARD SECURITY REPORT",
        "=" * 60,
        "",
        f"Scan:              {_scan_type_label(str(scan['scan_type']))}",
        f"Started:           {scan['start_time']}",
        f"Completed:         {scan['end_time'] or 'n/a'}",
        f"Status:            {scan['status']}",
        "",
        f"Files scanned:     {scan['files_scanned']:,}",
        f"Directories:       {scan['directories_scanned']:,}",
        f"Threats:           {scan['threats_found']}",
        f"Suspicious:        {scan['suspicious_found']}",
        f"Quarantined:       {scan['quarantined']}",
        f"Skipped:           {scan['skipped']}",
        f"Errors:            {scan['errors']}",
        f"Duration:          {format_duration(float(scan['duration_secs'] or 0))}",
        "",
    ]

    if results:
        lines.extend(["-" * 60, "DETECTED ITEMS", "-" * 60])
        for result in results:
            lines.extend([
                "",
                f"  File:       {result['file_path']}",
                f"  Detection:  {result['detection_name']}",
                f"  Severity:   {result['severity']} "
                f"(confidence: {result['confidence']})",
                f"  Method:     {result['detection_type']}",
                f"  Risk score: {result['risk_score']}",
                f"  SHA-256:    {result['sha256'] or 'n/a'}",
                f"  Size:       {human_size(result['file_size'])}",
                f"  Reason:     {result['reason']}",
                f"  Action:     {result['recommended_action']}",
            ])
    else:
        lines.extend(["", "No detected items for this scan."])

    lines.extend([
        "",
        "-" * 60,
        "DISCLAIMER",
        "-" * 60,
        "No antivirus can guarantee detection or removal of every threat.",
        "KhokharGuard is designed to complement Windows Security.",
        "",
    ])
    return "\n".join(lines)


def generate_csv_report(scan_id: int) -> str:
    """Build CSV export of per-file results."""
    results = _scan_results(scan_id)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "file_path", "sha256", "file_size", "detection_name",
        "detection_type", "severity", "confidence", "risk_score",
        "reason", "recommended_action", "action_taken",
    ])
    for result in results:
        writer.writerow([
            result["file_path"], result["sha256"], result["file_size"],
            result["detection_name"], result["detection_type"],
            result["severity"], result["confidence"], result["risk_score"],
            result["reason"], result["recommended_action"], result["action_taken"],
        ])
    return buffer.getvalue()


def generate_json_report(scan_id: int) -> str:
    """Build JSON export of the full scan record."""
    scan = _scan_record(scan_id)
    if scan is None:
        return json.dumps({"error": "scan not found"})
    scan["scan_targets"] = json.loads(scan.get("scan_targets") or "[]")
    scan["results"] = _scan_results(scan_id)
    return json.dumps(scan, indent=2, default=str)


def export_report(scan_id: int, fmt: str, output_path: Optional[Path] = None) -> Path:
    """Export a report in txt/csv/json format; returns written path."""
    fmt = fmt.lower().lstrip(".")
    if fmt not in {"txt", "csv", "json"}:
        raise ValueError(f"Unsupported report format: {fmt}")

    if output_path is None:
        output_path = paths.reports_dir() / f"khokharguard_report_{scan_id}.{fmt}"

    generators = {
        "txt": generate_text_report,
        "csv": generate_csv_report,
        "json": generate_json_report,
    }
    content = generators[fmt](scan_id)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    logger.info("Report exported: %s", output_path)
    return output_path


def _scan_type_label(scan_type: str) -> str:
    """Friendly scan type label."""
    return {
        "quick": "Quick Scan", "full": "Full System Scan",
        "custom": "Custom Scan", "usb": "USB Scan",
        "realtime": "Real-Time Detection",
    }.get(scan_type, scan_type.title())
