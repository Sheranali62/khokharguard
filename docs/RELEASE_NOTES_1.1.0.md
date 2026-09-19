# Khokhar & Son's Antivirus 1.1.0 — Release Notes

**Release date:** 2026-09-19
**Artefacts:**
`KhokharGuard_Setup_1.1.0.exe` (installer, 17.1 MB) ·
`KhokharGuard-portable-1.1.0.zip` (portable bundle, 22.2 MB)

KhokharGuard is local-first Windows malware protection. It scans,
classifies, quarantines, and — only with your explicit confirmation —
removes malware and suspicious files, with USB-drive protection,
real-time monitoring of common infection points, persistence analysis,
ransomware canaries, and a background protection service. It works
fully offline.

> KhokharGuard complements Windows Security; it does not replace it.
> No antivirus can guarantee detection or removal of every threat.

## Highlights

- **Khokhar & Son's brand launch.** The whole application now carries
  the brand: app icon (executable, installer, title bar, taskbar, tray
  states), Luxury Gold `#D4AF37` / Deep Black `#0B0B0B` / Warm White
  `#F7F5F0` theme, and renamed surfaces everywhere.
- **Legacy data migration.** Users of the pre-rebrand LocalGuard
  build: on first start the app imports your previous settings, scan
  history, security events, quarantine vault, and reports into the new
  `%LOCALAPPDATA%\KhokharGuard` location. The import is one-time,
  copies (never moves or deletes), never overwrites newer data, and a
  summary dialog confirms exactly what was brought over.
- **Dashboard layout fix.** The content area of every page now renders
  (previously only the sidebar was visible — a defect present since
  the first release).
- **Verified signature updates hardened.** Fixed a rare Ed25519
  verification failure (roughly 1 in 2000 random keys) by rewriting
  the internals with standard extended-coordinate formulas; manifest
  verification is also ~750× faster.

## Also in this release

- Ransomware canary files, incremental scans that skip unchanged
  files, verified signature updates, and the USB trusted-device
  allowlist (introduced late in the 1.0 line) are fully branded and
  covered by the migration.
- IPC quarantine actions, YARA hot-reload, and OIDC-first release
  signing (inactive until the Azure signing account is configured).

## Known limitations

- The artefacts are **not Authenticode-signed** for this release: the
  Azure Artifact Signing account has not been configured yet (see
  `docs/AZURE_SIGNING_SETUP.md`). Expect SmartScreen's "unknown
  publisher" prompt; verify the SHA-256 digests below.
- No kernel-level protection; KhokharGuard complements Windows
  Security and works in user mode.
- YARA scanning needs optional `yara-python`; without it everything
  else still works.

## Verification (SHA-256)

```
ecafb1326c900131b14512fe563f04d302f6330ab641c9e2548731f4176694d0  KhokharGuard_Setup_1.1.0.exe
d457668606d2fbe557144d499a460614769d38cbaa6acac2d477937c95d8c94c  KhokharGuard-portable-1.1.0.zip
```

Verified by use on Windows 11: installer metadata reports
`ProductName: Khokhar & Son's Antivirus`, `ProductVersion: 1.1.0`; the
portable CLI prints the branded version banner and status; all icon,
YARA, schema, and config resources are present in the bundle.

## Upgrade notes

- Install over any previous version; per-user data
  (`%LOCALAPPDATA%\KhokharGuard`) is preserved.
- Coming from the pre-rebrand LocalGuard build? The first launch shows
  a summary of everything imported; old files are left untouched.
