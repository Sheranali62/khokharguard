# Changelog

All notable changes to Khokhar & Son's Antivirus are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-09-19

### Changed

- **Rebrand to Khokhar & Son's Antivirus:** all user-facing surfaces
  (window title, tray, notifications, reports, canary text, About,
  installer, service name, CLI) now carry the Khokhar & Son's brand;
  the short technical name is KhokharGuard. Brand app icon
  (`assets/icons/khokharantivirus.ico`) and tray/UI state icons are
  generated from the approved brand kit in `assets/brand/` by
  `scripts/generate_icons.py`; the theme uses the brand palette
  (Luxury Gold `#D4AF37` accents on deep black, Warm White `#F7F5F0`
  light background). Executable, spec, installer and artefact names
  change accordingly (`KhokharGuard.exe`, `khokharguard.spec`,
  `KhokharGuard_Setup_<ver>.exe`, fresh installer AppId); user data
  directories are now `%LOCALAPPDATA%\KhokharGuard`.

### Added

- **Ransomware canary files:** harmless decoy documents in
  Documents/Desktop/Pictures, watched while protection runs. Any
  modification or deletion of a decoy raises an immediate notification
  and a critical `canary_tampered` security event, then re-plants the
  decoy. Toggle in Settings > Protection; decoys explain themselves in
  plain text and are always safe to delete.
- **Incremental scanning:** a persistent cache of clean verdicts
  (keyed by path, size, mtime, signature and engine version) lets
  repeat scans skip files that have not changed. Only clean verdicts
  are cached - threats and suspicious files are re-analysed every
  scan - and any signature update invalidates the cache. Controlled by
  the existing "Skip unchanged files" setting; live `cache_hits`
  counter in scan progress.
- **Verified signature update system (spec section 37):** HTTPS-only
  fetches with hard size caps, per-file SHA-256 integrity, optional
  Ed25519 manifest signing (drop a public key in
  `signatures/update_public_key.pub` and unsigned manifests are
  refused - includes an auditable, RFC 8032-vector-tested pure-Python
  verifier in `utils/ed25519.py`), path-traversal guards, versioned
  backups with rollback, and a Settings > Signature Updates section
  (Check Now / Roll Back / update URL). YARA hot-reload and lazy hash
  reload make new signatures active immediately.
- **USB trusted-device allowlist:** drives trusted by serial number
  AND volume label skip the automatic rescan on insertion; everything
  else (including a different drive with the same label, or a spoofed
  serial) still scans. Manage on the USB page (Trust / Revoke with
  confirmation); unidentifiable drives can never be trusted; trust
  changes are recorded in the security event log.

### Added (previous)

- **Authenticated quarantine actions over IPC:** the GUI can now ask the
  background service to restore or permanently delete service-quarantined
  items (`quarantine_restore` / `quarantine_delete`). The service refuses
  anything without the explicit `user_confirmed` flag that travels with
  the authenticated request, refuses unknown records, and writes a
  security event for the audit trail. The quarantine page marks
  service-origin rows (`[service]`) and routes their Restore/Delete
  through the IPC path; failures surface as ordinary error messages.
- **YARA hot reload:** rule files added to, edited in, or removed from
  `signatures/yara/` apply on the next scan without restarting
  protection. The engine fingerprints the rule directory per scan and
  recompiles only on change; a broken edit keeps the last good rule set
  active and the engine recovers automatically once the file is fixed.

### Changed

- CI: signing now prefers **OIDC workload identity federation**
  (`azure/login@v3` + `id-token: write`) over the stored client secret;
  the client-secret triple remains a fallback. New optional secret
  `AZURE_SUBSCRIPTION_ID`. Configuration is documented in
  `docs/AZURE_SIGNING_SETUP.md`.
- CI: actions bumped to Node 24 runtimes (`checkout@v5`,
  `setup-python@v6`, `upload-artifact@v6`) clearing the Node 20
  deprecation annotations.

## [1.0.0] - 2026-09-18

Initial release.

### Added

**Scanning engine**

- Quick, full, custom, and USB scan modes with live progress,
  pause/resume/stop, and full statistics (files, directories, threats,
  suspicious, skipped, errors).
- SHA-256 hashing with chunked reads and an optional rescan cache;
  large files are never loaded fully into memory.
- Signature matching against the local database (`signatures/hashes.json`)
  with EICAR test-signature support.
- Heuristic risk engine (0-100 score, four bands): suspicious locations,
  double extensions, masquerading filenames, persistence mechanisms,
  script content indicators, and more. Indicators are advisory - the
  engine classifies uncertain files as suspicious for review, never as
  proven malware.
- Static PE analysis without execution: architecture, sections, imports,
  entry point, entropy, compile timestamp, signature presence.
- Archive inspection (ZIP/TAR plus 7z/RAR when 7-Zip is installed) with
  archive-bomb guards: member count, total size, compression ratio,
  recursion depth, and time limits.
- Optional YARA rule scanning (`signatures/yara/`); the app works fully
  without YARA installed.
- Starter YARA rule set shipped in-house: download cradles, obfuscated
  base64 execution, scheduled-task persistence, mshta remote execution,
  malicious .lnk/.url shortcut structures, and autorun.inf abuse - all
  content-based, severity-honest (`medium` rules classify as
  SUSPICIOUS for review, never auto-deleted), and validated by tests.
- YARA detections surface with their own method and detection name
  (`YARA.<RuleName>`) instead of a generic heuristic verdict.

**Protection**

- USB protection: insertion detection, device tracking, optional
  auto-scan of removable drives, and inspection of autorun mechanisms,
  shortcut structures, and masquerading executables.
- Real-time monitoring (watchdog, with a polling fallback) of
  Downloads/Desktop/Temp for new suspicious files; auto-quarantine only
  ever applies to signature-confirmed threats.
- Background protection service (`KhokharGuard.exe service ...` or the
  Settings page): keeps real-time and USB protection running when the
  GUI is closed. The GUI detects a running background core through
  authenticated IPC and defers to it - the two never double-watch the
  same folders.
- Findings raised while the GUI is closed stream into the session
  when it reopens (`recent_findings` IPC method, watermark-based), so
  background detections appear in the UI exactly like local ones.
- Service-session scan and threat history merges into the GUI's
  history and dashboard views (`get_history` IPC method, cached),
  closing the cross-account visibility gap of the SCM-hosted mode.
- Startup folder, registry Run/RunOnce, scheduled task, and service
  analysis with evidence-based flags and confirmed-only removal.
  Removals snapshot state first (registry values, task XML) so cleanup
  is reversible.

**Quarantine**

- Secure vault workflow: hash-verified move to an isolated directory,
  non-executable `.quar` wrapper, hidden/system attributes, and ACL
  tightening where practical. Restore verifies bytes before release;
  permanent deletion requires explicit confirmation.

**User experience**

- Dark/light themed Tkinter dashboard: protection status, scan pages,
  USB protection, quarantine, scan history, real-time/security pages,
  settings, and about. Long operations run on worker threads; the GUI
  never blocks.
- System tray icon with protected/paused/warning states, a flashing
  progress badge while scans run, and the full spec section 43 menu.
- Windows notifications through the tray icon with per-kind enable/
  disable switches and configurable rate limits (Settings >
  Notifications).
- One-click EICAR detection self-test (About page) that reports
  honestly when another antivirus intercepts the test file and offers
  an exclusion hint so a full detection verdict can be demonstrated.
- First-run wizard, scan history with TXT/CSV/JSON report export, and
  a security event log.

**Platform and delivery**

- SQLite storage (10 tables, parameterized queries only) with
  corruption self-healing; JSON settings with documented defaults.
- Safe CLI (`scan`, `quick-scan`, `scan-usb`, `quarantine`, `restore`,
  `status`, `service`, `version`) - no arbitrary command execution.
- Fully sandboxed test suite (no test touches the repo, the user
  profile, or spawns processes), performance benchmarks, and
  adversarial tests (malformed PEs, archive bombs, corrupt databases,
  hostile paths).
- PyInstaller build (`khokharguard.spec`) and Inno Setup installer with
  Start Menu shortcuts, optional autostart, and per-user install
  support (`/CURRENTUSER`).
- Windows CI (GitHub Actions): compileall, pytest, PyInstaller build
  with CLI smoke test, and Inno Setup compile on every push; release
  artefacts on `v*` tags.
- Authenticode signing via Azure Artifact Signing in CI (enabled by
  adding the documented secrets; builds remain fully functional and
  publish unsigned when signing is not configured).

### Security

- Local-first and offline-capable; telemetry, cloud reputation, and
  file uploads are off by default and can stay off.
- The service IPC channel is loopback-only, token-authenticated
  (constant-time comparison), size-capped, and limited to a fixed
  method allow-list.
- KhokharGuard never disables Windows Security, never executes scanned
  content, and never removes system files without strong evidence and
  explicit user confirmation.

### Limitations

- No kernel-level protection; KhokharGuard complements Windows Security
  and does not replace it. No antivirus can guarantee detection or
  removal of every threat.
- 7z/RAR inspection requires 7-Zip; HKLM/task/service cleanups and the
  SCM service lifecycle require Administrator approval.
- In 1.0 the SCM-hosted service runs under its own account and does
  not report status into user sessions; console-session headless mode
  (`service run`) provides cross-process reporting via IPC.
- Signature updates ship as manifest-verified archives; production
  deployments should add cryptographic signing on top.

[1.0.0]: https://example.invalid/khokharguard/releases/tag/v1.0.0

## [1.1.1] - 2026-09-19
### Fixed
- GUI exit no longer crashes with `NameError: logger` (present since v1.0.0; only the GUI path was affected).
- Frozen-build logging: dict-argument log lines render again on Python 3.12 builds (SanitizingFilter kept LogRecord mapping arguments intact).
- Update signing keys are read byte-exactly; hex/base64 key files supported; invalid key files fail with clear errors (ends the intermittent signature-verification "flakes").
### Added
- Migration summary dialog links to the bundled full upgrade guide (docs/UPGRADING.md).
