"""LocalGuard Antivirus - safe EICAR self-test service.

Implements the About page self-test using the standard EICAR test
string - a harmless industry-standard text used by every antivirus
vendor to verify detection is working (spec section 15; see
https://www.eicar.org).

Safety properties (spec section 28):

    - The test file is written into a private, restrictive temporary
      directory and is deleted in a ``finally`` block on every path.
    - The file is never executed, opened, or imported by LocalGuard.
    - Detection goes through the exact same pipeline used for real
      scans (hash -> signature lookup).
    - The test never touches the quarantine vault: it only reads the
      detection verdict.
    - Defender may remove the file before it can be read; that outcome
      is reported honestly as a skip, not a failure.

Note on Defender: on machines with Microsoft Defender active, Defender
itself may delete or block the EICAR file the moment it is written.
LocalGuard reports this transparently instead of treating it as a
LocalGuard failure.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict

from utils import get_logger
from utils.security_utils import safe_temp_dir

logger = get_logger("eicar_selftest")


def _environment_snapshot() -> Dict[str, Any]:
    """Best-effort snapshot of the active-AV environment.

    Reads Defender real-time state, whether LocalGuard's own process is
    excluded from Defender, and the current privilege level. Every
    field degrades to None when unavailable (non-Windows, access
    denied, Defender absent). Read-only: Defender settings are never
    modified (spec section 26).
    """
    snapshot: Dict[str, Any] = {
        "defender_active": None,
        "localguard_excluded": None,
        "is_admin": None,
    }
    try:
        from utils.windows_utils import get_defender_status, is_admin

        snapshot["is_admin"] = bool(is_admin())
        status = get_defender_status()
        if status.get("available"):
            snapshot["defender_active"] = bool(
                status.get("realtime_enabled"))
    except Exception:  # noqa: BLE001
        logger.debug("Defender status unavailable", exc_info=True)
    try:
        from utils.windows_utils import localguard_in_defender_exclusions

        snapshot["localguard_excluded"] = \
            localguard_in_defender_exclusions()
    except Exception:  # noqa: BLE001
        logger.debug("Defender exclusion check unavailable", exc_info=True)
    return snapshot


def _interference_hint(env: Dict[str, Any]) -> str:
    """Build the user guidance for another-AV interference.

    Tailored to what we could actually observe: which product is
    active, whether LocalGuard is already excluded, and whether the
    user could elevate.
    """
    lines = [
        "To demonstrate LocalGuard's own detection, the EICAR test file "
        "must survive on disk long enough to be scanned. You can:",
        "",
        "  1. Temporarily add an antivirus exclusion for the LocalGuard "
        "program folder:",
        "     Windows Security > Virus & threat protection > Manage "
        "settings > Exclusions > Add an exclusion > Folder.",
    ]
    if env.get("localguard_excluded") is False:
        lines.append(
            "     (LocalGuard's process is currently NOT in Defender's "
            "exclusion list.)")
    elif env.get("localguard_excluded"):
        lines.append(
            "     (LocalGuard's process IS already listed in Defender's "
            "exclusions - the interference may come from another "
            "security product.)")
    lines.extend([
        "",
        "  2. Or run this self-test on a machine where real-time "
        "protection is paused.",
        "",
        "Removing exclusions afterwards is recommended. If Windows "
        "asks for administrator permission for that step, that is "
        f"expected ({'you are' if env.get('is_admin') else 'you are not ' 
                      'currently'} running as Administrator).",
        "",
        "This is normal antivirus behaviour, not a LocalGuard defect: "
        "every antivirus product reacts to EICAR - that is precisely "
        "what it is for.",
    ])
    return "\n".join(lines)


def run_eicar_self_test() -> Dict[str, Any]:
    """Generate, scan, and clean up one EICAR test file.

    Returns a result dictionary::

        {
            "status": "detected" | "another_av_active" |
                      "defender_intercepted" | "failed",
            "message": str,            # user-facing summary
            "detail": str,             # longer explanation (dialog body)
            "detection_name": str,
            "severity": str,
            "sha256": str,
            "defender_active": bool | None,   # Defender real-time on?
            "localguard_excluded": bool | None,  # LG in AV exclusions?
        }

    The "another_av_active" status carries an actionable hint (how to
    exclude the test from the active antivirus) so a full detection
    verdict can be demonstrated when the user chooses.

    Never raises.
    """
    from engine.signature_engine import EICAR_SHA256, EICAR_STRING

    env = _environment_snapshot()
    temp = None
    try:
        temp = safe_temp_dir(prefix="localguard_eicar_")
        temp_path = Path(temp.name)

        test_file = temp_path / "eicar_test_file.txt"
        # ASCII-only per the EICAR standard: the string must be exactly
        # 68 ASCII characters with no trailing newline.
        test_file.write_text(EICAR_STRING, encoding="ascii", newline="")

        # Confirm the artifact survived write (Defender may remove it).
        try:
            on_disk = hashlib.sha256(test_file.read_bytes()).hexdigest()
        except OSError as exc:
            return {
                "status": "another_av_active",
                "message": ("Another antivirus removed the test file "
                            "before LocalGuard could scan it."),
                "detail": (
                    "The EICAR test string was written, but your active "
                    "antivirus ("
                    + ("Microsoft Defender"
                       if env.get("defender_active")
                       else "another security product")
                    + ") deleted or blocked it on write. That is the "
                    "product doing its job - EICAR exists to trigger "
                    "exactly this reaction - so this is expected "
                    "behaviour, not a LocalGuard failure.\n\n"
                    + _interference_hint(env)
                    + "\n\n"
                    f"Technical detail: {exc}"
                ),
                "detection_name": "",
                "severity": "",
                "sha256": "",
                **env,
            }

        if on_disk != EICAR_SHA256:
            return {
                "status": "another_av_active",
                "message": ("The test file on disk no longer matches the "
                            "EICAR string - another antivirus altered it."),
                "detail": (
                    "Your active antivirus modified or replaced the EICAR "
                    "test file between writing and reading it. "
                    "LocalGuard's pipeline only sees the bytes on disk, "
                    "so its own signature check cannot run here.\n\n"
                    + _interference_hint(env)
                    + "\n\n"
                    "Expected SHA-256: " + EICAR_SHA256 + "\n"
                    "Actual SHA-256:   " + on_disk
                ),
                "detection_name": "",
                "severity": "",
                "sha256": "",
                **env,
            }

        # --- Detection through the real analysis pipeline -------------
        from engine.file_analyzer import FileAnalyzer
        from engine.signature_engine import SignatureEngine

        signature_engine = SignatureEngine()
        analyzer = FileAnalyzer(
            signature_engine=signature_engine,
            hash_cache=False,
            scan_archives=False,
        )
        detection = analyzer.analyze_path(test_file)

        detected = (
            detection.detection_method == "signature"
            and detection.detection_name == "EICAR.Test.File"
            and detection.is_threat
        )

        if detected:
            status = "detected"
            message = (f"Detected as {detection.detection_name} "
                       f"({detection.severity.upper()} severity). "
                       "LocalGuard's detection engine is working.")
            detail = (
                "The EICAR test file was analysed through the standard "
                "detection pipeline:\n\n"
                f"    Detection:  {detection.detection_name}\n"
                f"    Method:     {detection.detection_method}\n"
                f"    Severity:   {detection.severity}\n"
                f"    Confidence: {detection.confidence}\n"
                f"    Risk score: {detection.risk_score}/100\n"
                f"    SHA-256:    {detection.sha256}\n\n"
                "The file was never executed, and it was deleted "
                "immediately after the test. It was NOT quarantined - "
                "no vault entry was created."
            )
        else:
            status = "failed"
            message = (f"Unexpected verdict: {detection.detection_name} "
                       f"({detection.severity}).")
            detail = (
                "The EICAR test file was scanned, but LocalGuard did not "
                "produce the expected signature detection. This may mean "
                "the signature database is missing the EICAR entry.\n\n"
                f"    Verdict: {detection.detection_name}\n"
                f"    Method:  {detection.detection_method}\n"
                f"    Reason:  {detection.reason}"
            )

        return {
            "status": status,
            "message": message,
            "detail": detail,
            "detection_name": detection.detection_name,
            "severity": detection.severity,
            "sha256": detection.sha256,
            **env,
        }

    except Exception as exc:  # noqa: BLE001 - must never crash the caller
        logger.exception("EICAR self-test failed")
        return {
            "status": "failed",
            "message": f"Self-test error: {exc}",
            "detail": (
                "An unexpected error occurred while running the EICAR "
                "self-test. Check logs/localguard.log for details."
            ),
            "detection_name": "",
            "severity": "",
            "sha256": "",
        }
    finally:
        # Cleanup is unconditional: the test artifact never outlives
        # the test on any code path. Antivirus products routinely hold
        # a scan handle on freshly-written files, so cleanup is
        # best-effort: clear restrictive attributes first, then remove
        # the tree; any deferred remnant is inert and Windows temp
        # maintenance removes it later.
        if temp is not None:
            try:
                for leftover in Path(temp.name).rglob("*"):
                    if leftover.is_file():
                        try:
                            leftover.chmod(0o666)
                        except OSError:
                            pass
            except OSError:
                pass
            try:
                temp.cleanup()
            except OSError:
                logger.debug(
                    "EICAR temp cleanup deferred (antivirus file lock)")
