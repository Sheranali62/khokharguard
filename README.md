# Khokhar & Son's Antivirus

**Local-first Windows malware protection.** Version **1.1.1**

KhokharGuard scans, classifies, quarantines, and (with your explicit
confirmation) removes malware and suspicious files on Windows 10/11 —
with USB-drive protection, real-time monitoring of common infection
points, startup/scheduled-task/service analysis, and security reports.
It works fully offline.

> **Transparency first:** No antivirus can guarantee detection or
> removal of every threat. KhokharGuard is designed to **complement**
> Windows Security (Microsoft Defender), not replace it. It never
> disables or modifies Defender.

---

## Table of Contents

1. [Features](#features)
2. [Security Model](#security-model)
3. [Installation (from source)](#installation-from-source)
4. [Build Instructions](#build-instructions)
5. [Installation (installer)](#installation-installer)
6. [Usage](#usage)
7. [GUI Overview](#gui-overview)
8. [CLI Commands](#cli-commands)
9. [Testing Instructions](#testing-instructions)
10. [EICAR Self-Test](#eicar-self-test)
11. [Configuration](#configuration)
12. [Architecture](#architecture)
13. [Changelog](CHANGELOG.md)
13. [Upgrading (incl. from LocalGuard 1.0.0)](docs/UPGRADING.md)
14. [Release Notes (1.1.0)](docs/RELEASE_NOTES_1.1.0.md) · [1.0.0](docs/RELEASE_NOTES_1.0.0.md)
13. [Security Limitations](#security-limitations)
14. [Known Limitations](#known-limitations)

---

## Features

- **Scanning** — Quick (common infection points), Full (all local
  drives), Custom (files/folders), USB drives. Pause / resume / stop.
  Multithreaded with bounded workers; huge files are hashed with
  chunked streaming, never fully loaded into RAM.
- **Detection layers** — exact SHA-256 signature matching, heuristic
  risk scoring (filename, location, script content, hidden attributes),
  safe PE structural analysis (sections, entropy, imports, signature
  presence), optional YARA rules, bounded archive inspection
  (ZIP/TAR/GZ/BZ2/XZ; 7z/RAR when 7-Zip is installed).
- **Quarantine** — hash-verified move into an isolated vault with a
  non-executable `.quar` wrapper, hidden/system attributes, and full
  metadata records. Restore and permanent deletion require explicit
  confirmation; restore verifies the stored hash first.
- **USB protection** — insertion detection with auto-scan, plus
  targeted analysis of `autorun.inf`, shortcut structures,
  double-extension files (`invoice.pdf.exe`), and hidden executables.
  Trusted devices (by serial **and** volume label) can skip automatic
  rescans; unidentifiable drives can never be trusted.
- **Real-time monitoring** — watchdog-based (with polling fallback)
  watching Downloads/Desktop/Temp for new suspicious files.
  Auto-quarantine applies **only** to signature-confirmed threats.
- **Ransomware canaries** — harmless decoy documents in
  Documents/Desktop/Pictures; touching one raises an immediate warning
  and a critical security event (an early bulk-encryption indicator,
  not a guarantee).
- **Incremental scans** — clean verdicts are cached (path + size +
  mtime + signature version), so repeat scans skip unchanged files.
  Threats are never cached; signature updates invalidate the cache.
- **Persistence analysis** — startup folders, registry Run/RunOnce
  keys, scheduled tasks, and Windows services, each with evidence-based
  risk flags. Nothing is removed automatically; cleanups snapshot a
  restore record first.
- **System tray** — proper shield icon assets (green = protected,
  amber = paused, red = attention) with Open Dashboard / Quick Scan /
  Scan USB / Pause Protection / Settings / Exit. Windows notifications
  are delivered through the tray icon (rate-limited per event kind).
  Closing the window minimizes to the tray when the tray is available;
  paused and warning states are always visible in the tooltip and menu.
- **Detection self-test** — one-click EICAR test on the About page
  (see below).
- **Signature updates (optional)** — everything works offline; if you
  configure an HTTPS update URL, manifests are size-capped, every file
  is hash-verified, paths are traversal-guarded, and (when a signing
  public key is installed) Ed25519-signed manifests are enforced.
  Versioned backups allow one-click rollback from Settings.
- **Reports** — TXT / CSV / JSON export per scan; security event log.
- **Privacy** — telemetry OFF, cloud reputation OFF, file uploads OFF.
  No network access is required at any point.

## Security Model

The default workflow is **DETECT → ANALYZE → CLASSIFY → QUARANTINE →
USER CONFIRMATION → REMOVE/RESTORE**.

Risk classification bands (internal indicators, **not** proof of
malware):

| Score   | Classification |
|---------|----------------|
| 0–19    | CLEAN / LOW    |
| 20–39   | SUSPICIOUS     |
| 40–69   | HIGH RISK      |
| 70–100  | CRITICAL       |

Heuristic findings are always classified as *suspicious* for user
review — never auto-deleted. Only signature-confirmed detections
(including the harmless EICAR test file) can be auto-quarantined, and
only when you enable that setting.

## Installation (from source)

Requirements: **Windows 10/11**, **Python 3.12+**

```bat
git clone <repository-url> KhokharGuard
cd KhokharGuard
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Optional extras:

```
pip install yara-python      # YARA rule scanning support
pip install pyinstaller      # only needed to build the EXE
```

## Build Instructions

Build the standalone executable (no Python needed on target machines):

```bat
pip install -r requirements.txt
pip install pyinstaller
scripts\build_exe.bat
:: or manually:
python -m compileall .
pyinstaller khokharguard.spec --noconfirm
```

The frozen build bundles the tray dependencies (pystray, Pillow) and
the icon assets (`assets/icons/*.png`); the executable itself embeds
the multi-resolution `khokharantivirus.ico` shield. Optional yara-python is
excluded from the bundle unless installed before building.

Output: `dist\KhokharGuard\KhokharGuard.exe` (onedir bundle including
schema, config, signatures, icon assets, and VERSION).

Then build the installer:

```bat
iscc installer\KhokharGuard_Setup.iss
```

Output: `dist\installer\KhokharGuard_Setup_1.1.1.exe` (Inno Setup;
creates Start Menu / optional desktop shortcuts, optional HKCU
autostart, per-user data directories, and a clean uninstaller that
preserves quarantine/logs/reports). The installer requires
Administrator approval by default; passing `/CURRENTUSER` installs
per-user into `%LOCALAPPDATA%\Programs\KhokharGuard` with a per-user
Start Menu entry (no elevation needed).

### Continuous integration

`.github/workflows/ci.yml` runs the full pipeline on a Windows runner
for every push and pull request: `python -m compileall .`, the sandboxed
pytest suite, the PyInstaller build with a frozen-CLI smoke test, and
the Inno Setup compile. Pushing a `v*` tag additionally publishes the
installer and portable bundle as workflow artefacts.

## Installation (installer)

1. Run `KhokharGuard_Setup_1.1.1.exe`.
2. Follow the wizard (desktop icon and autostart are optional).
3. Launch **Khokhar & Son's Antivirus** from the Start Menu.
4. On first run, choose your protection options — every option is
   explained and changeable later in Settings.

## Usage

### GUI Overview

The sidebar provides: **Dashboard**, **Quick / Full / Custom Scan**,
**USB Protection**, **Quarantine**, **Scan History**, **Real-Time /
Security**, **Settings**, and **About**.

- **Dashboard** — protection banner, component status (real-time, USB,
  Windows Security, signatures, admin level), scan action buttons,
  recent security events, and threat statistics.
- **Scan page** — live progress (files, directories, threats,
  suspicious, skipped, errors, elapsed, current file), pause/resume/
  stop, results table, and per-finding actions (Quarantine, Details,
  Allow).
- **USB Protection** — connected removable drives with capacity/free
  space/filesystem, one-click USB scan, auto-scan toggle, and history
  of previously seen devices.
- **Quarantine** — Restore / Delete Permanently / Details with
  confirmation dialogs on both destructive paths.
- **Scan History** — per-scan records, results viewer, TXT/CSV/JSON
  export, delete/clear.
- **Real-Time / Security** — startup entries, scheduled tasks,
  services (each with Scan + confirmed removal), and Windows Security
  status with a button to open Windows Security.
- **Settings** — general, protection, notifications, performance,
  exclusions (file / folder / extension / hash), and privacy switches.
  Dark/light themes.

### Notifications settings (Settings → Notifications)

Each notification kind can be switched off individually (USB detected,
threat detected, scan finished, protection paused, signature update
available), and the minimum interval between two notifications of the
same kind is configurable per kind. The master switch is *Show
notifications* in General. Security events are always recorded in
Scan History even when their notification is off — muting only affects
the popup, never the audit trail.

### System Tray

A shield icon runs in the Windows notification area (pystray; the app
runs fine without it if the dependency is missing). The icon uses the
bundled assets from `assets/icons/` (regenerate with
`scripts/generate_icons.py`): green check = protected, amber pause
bars = protection paused, red exclamation = attention required
(recent findings awaiting review). **While a scan runs the shield
flashes a blue progress badge** and the tooltip shows the live file
count (`SCANNING (1,234 files)`); when the scan ends — completed,
stopped, or failed — the correct state icon is restored, and a clean
scan clears a stale warning shield. Paused/warning states take
priority over the progress flash. Menu:

- **Open Dashboard** — show/focus the main window
- **Quick Scan** — start a quick scan immediately
- **Scan USB** — jump to the USB Protection page
- **Pause Protection** — toggle real-time + USB monitoring on/off
  (a checkmark shows the paused state; the icon turns amber)
- **Settings** — open the Settings page
- **Exit** — quit KhokharGuard completely

Windows notifications (spec section 41: USB detected, threat
quarantined, scan complete, protection paused, update available) are
delivered through the tray icon when it is running, honouring the
per-kind enable/disable switches and rate limits from Settings →
Notifications; without a tray, source builds fall back to PowerShell
toasts. Real-time detections drive the same red-shield warning and
notification path as scan findings, including auto-scan findings from
inserted USB drives.

Closing the main window minimizes to the tray (changeable in Settings:
*minimize to tray*). Exit fully via the tray menu.

### CLI Commands

```
python main.py scan C:\Users\me\Downloads
python main.py quick-scan
python main.py scan-usb E:\
python main.py quarantine
python main.py restore 3
python main.py status
python main.py service status
python main.py version
```

(The packaged EXE accepts the same commands: `KhokharGuard.exe scan C:\`.)

### Background protection service

Real-time and USB protection normally run inside the GUI process
(kept alive by minimising to the tray). To keep them running with no
window at all, either install the Windows service from **Settings →
Background Service** (visible in services.msc, needs Administrator
approval) or run the headless core directly:

```
KhokharGuard.exe service run      # headless core (blocks)
KhokharGuard.exe service status   # installed/running query
```

The core publishes a loopback-only, token-authenticated IPC channel
(token stored in the per-user app data directory); a GUI launched
later detects it and defers monitoring to it, and the tray's
Pause Protection controls the active layer. Findings raised while
no GUI is open are buffered (bounded queue) and stream into the
session when it reopens, and the service's scan/threat history is
merged into the GUI's history and dashboard views. Service commands
never execute arbitrary input - the surface is a fixed method
allow-list (`status`, `pause`, `resume`, `apply_settings`,
`shutdown`, `recent_findings`, `get_history`).

## Testing Instructions

```bat
python -m compileall .
python -m pytest
```

Every test is **fully sandboxed** (see `tests/conftest.py`):

- An autouse fixture redirects all writable locations (database,
  settings, signatures, quarantine vault, logs, reports, per-user app
  data) into a per-test temporary directory; shared singletons are
  reset around each test.
- Toast notifications cannot spawn PowerShell during tests.
- A session guard snapshots protected repository files
  (`signatures/hashes.json`, `config/settings.json`, the source-tree
  database, `logs/`, `reports/`) and fails the whole run if anything
  modified them.

The suite covers: hash calculation (reference vectors, chunking,
partial hashing), signature matching and EICAR, risk-score bands and
caps, scanner collect/stop/pause/skip behaviour, analyzer detections
(double extension, script content, EICAR in subdirectories), archive
limits and bomb guards, path traversal, log sanitisation, database
lifecycle and parameterized-query safety, quarantine → restore →
delete round trips, and USB detection logic.

## EICAR Self-Test

KhokharGuard ships with the **EICAR** industry-standard test signature.
EICAR is a harmless text string every antivirus vendor uses to verify
detection - it is **not** malware and cannot harm your computer.

### One-click test (About page)

Open **About → Detection Self-Test (EICAR) → Run Detection
Self-Test**. KhokharGuard writes the EICAR string into a private
temporary folder, scans it through the real detection pipeline, shows
the verdict, and deletes the file immediately. The test file is never
executed and never enters the quarantine vault.

Possible outcomes:

- **Self-Test Passed** — detected as `EICAR.Test.File` (HIGH,
  signature method).
- **Self-Test Skipped - Another Antivirus Active** — the active
  antivirus (typically Microsoft Defender) removed or altered the test
  file before KhokharGuard could read it. This is the *other* product
  doing its job - EICAR exists to trigger exactly that reaction - so
  it is expected behaviour, not a KhokharGuard failure. The dialog
  explains the situation and offers a shortcut to Windows Security:
  temporarily add an exclusion for the KhokharGuard program folder (or
  run the test where real-time protection is paused), rerun the
  self-test, and you will get the full **detected** verdict.
  Remember to remove the exclusion afterwards.
- **Self-Test Problem** — an unexpected verdict or error (e.g. the
  signature database is missing the EICAR entry).

### Manual test

1. Create a file containing exactly this line:
   `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
2. Save it as `eicar.com` anywhere (e.g. Downloads).
3. Run a Quick Scan — the file is detected as `EICAR.Test.File`
   (severity HIGH, method signature).
4. Quarantine it, then verify Restore returns it byte-identical.

No real malware samples are included in this repository.

## Configuration

- `config/default_config.json` — bundled defaults (do not edit).
- `config/settings.json` — your settings (also editable via the GUI).
- `signatures/hashes.json` — hash signature database; add your own
  entries as `"<sha256>": {"name": "...", "severity": "...",
  "category": "..."}`.
- `signatures/yara/*.yar` — optional YARA rules (requires
  `yara-python`).
- Data locations: `%LOCALAPPDATA%\KhokharGuard\` (database, logs,
  quarantine, reports when frozen; source runs keep them in the repo).

## Architecture

```
main.py                 GUI + CLI entry point
engine/                 scanning, hashing, signatures, heuristics,
                        PE analysis, archives, YARA, risk scoring,
                        scan controller (pause/stop, statistics)
protection/             USB monitor, real-time monitor, startup /
                        scheduled-task / service analysis, manager
quarantine/             vault manager, DB facade, restore manager
cleanup/                startup/task cleanup + recovery (snapshots)
services/               reporting, update service (verified HTTPS),
                        startup registration, IPC scaffolding
database/               SQLite layer (parameterized queries only)
utils/                  paths, logging (secret redaction), security
                        utils, settings, notifications, Windows glue
ui/                     Tkinter pages + app shell (worker threads +
                        UI queue; the GUI never blocks)
tests/                  pytest suite
```

Every detection record includes: name, severity, confidence, method,
reason, SHA-256, size, risk score, and recommended action.

## Security Limitations

- KhokharGuard cannot detect what its signatures, heuristics, PE
  heuristics, and YARA rules do not cover. Detection coverage is
  inherently incomplete.
- The heuristic engine produces **indicators, not verdicts** — false
  positives and false negatives will occur.
- Real-time protection watches user-writable locations; it is not a
  kernel minifilter and cannot intercept every filesystem operation.
- No behavioral/sandbox execution analysis: files are never executed
  during analysis (by design).
- The bundled signature set contains the EICAR test entry plus the
  in-house starter YARA rules until you or an update source extend it.
- Update verification validates manifest SHA-256 integrity; production
  deployments should add cryptographic signing on top.

## Known Limitations

- 7z/RAR archive inspection requires 7-Zip (`7z.exe`) to be installed.
- Some cleanups (HKLM Run keys, scheduled tasks, services) require
  Administrator privileges; KhokharGuard tells you when elevation is
  needed and never elevates silently.
- Full scans skip reparse points and symlinked paths by design.
- YARA is optional; without it, rule-based detection is unavailable
  (everything else works; the bundled starter rules cover script
  cradles, shortcut/autorun abuse, and persistence patterns).
- Released binaries are unsigned unless Authenticode signing is
  configured in CI (Azure Artifact Signing secrets); unsigned builds
  trigger SmartScreen prompts on first run.

---

MIT License — see [LICENSE](LICENSE).
