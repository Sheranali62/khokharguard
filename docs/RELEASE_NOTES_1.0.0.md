# Khokhar & Son's Antivirus 1.0.0 — Release Notes

**Release date:** 2026-09-18
**Artefacts:** `KhokharGuard_Setup_1.0.0.exe` (installer) ·
`KhokharGuard-portable-1.0.0` (portable bundle, CI artefact)

KhokharGuard is local-first Windows malware protection. It scans, classifies,
quarantines, and — only with your explicit confirmation — removes malware
and suspicious files, with USB-drive protection, real-time monitoring of
common infection points, persistence analysis, and background protection.

> KhokharGuard complements Windows Security; it does not replace it.
> No antivirus can guarantee detection or removal of every threat.

## Highlights

- **Four scan modes** with live progress, pause/resume/stop, and full
  statistics. Signature, heuristic, PE, archive, and (optional) YARA
  detection — all offline, no file ever executed during analysis.
- **USB protection** — insertion detection, optional auto-scan, autorun
  and masquerading-executable analysis (`invoice.pdf.exe`-style names).
- **Real-time monitoring** of Downloads/Desktop/Temp with a polling
  fallback; auto-quarantine only for signature-confirmed threats.
- **Background service** — protection keeps running when the window is
  closed (`KhokharGuard.exe service run` or install the Windows service
  from Settings). The GUI detects a running background core and defers
  to it; pause/resume from the tray controls whichever layer is active.
- **Secure quarantine** — hash-verified vault, non-executable wrapper,
  restore with byte verification, confirmed-only permanent deletion.
- **Transparent self-test** — one-click EICAR check on the About page;
  if another antivirus intercepts the test file, KhokharGuard says so and
  explains how to demonstrate its own detection.
- **Privacy-first** — telemetry, cloud reputation, and file uploads are
  off by default and can stay off.

## Requirements

- Windows 10 or 11 (64-bit)
- ~200 MB disk space; no Python required (frozen build)

## Install

1. Run `KhokharGuard_Setup_1.0.0.exe` (Administrator approval requested;
   non-admins may use `/CURRENTUSER` for a per-user install).
2. Choose optional desktop icon / start-with-Windows.
3. Launch **Khokhar & Son's Antivirus** from the Start Menu.

Portable: unzip the CI artefact and run `KhokharGuard.exe` directly.

## First steps

1. Check the dashboard banner shows **Protected**.
2. Click **Quick Scan** — results appear in minutes.
3. Optionally install the background service in **Settings →
   Background Service** so protection persists without the window.
4. Verify detection with **About → Run Detection Self-Test**.

## Notes and known limitations

- The heuristic engine produces *indicators, not verdicts*; uncertain
  files are classified as suspicious for review, never auto-deleted.
- 7z/RAR inspection requires 7-Zip installed.
- HKLM, scheduled-task, and service cleanups need Administrator
  approval; KhokharGuard never elevates silently.
- The SCM-hosted service runs under its own account; for cross-process
  status reporting use the console-session headless mode
  (`KhokharGuard.exe service run`).
- The bundled signature set contains the EICAR test entry until an
  update source extends it.
- Microsoft Defender users: Defender may intercept the EICAR self-test
  file on write — the dialog explains what to do.

## Verification

Every release build runs: `python -m compileall .`, the sandboxed
pytest suite (184 tests), the PyInstaller build with a frozen-CLI smoke
test, the Inno Setup compile, and release-consistency checks — see
`.github/workflows/ci.yml`.

## Support

Logs: `%LOCALAPPDATA%\KhokharGuard\logs\khokharguard.log` (frozen) or
`logs/khokharguard.log` (source). The log never contains passwords,
tokens, credentials, or file contents.
