# Upgrading KhokharGuard

How to move between KhokharGuard versions, including the special case
of coming from the original **LocalGuard 1.0.0** build (the project was
rebranded to **Khokhar & Son's Antivirus / KhokharGuard** in v1.1.0).

Everything here is local-first: upgrades never delete user data, never
run network checks, and never remove your previous install for you.

---

## Upgrading from LocalGuard 1.0.0 to KhokharGuard 1.1.0+

### What changed in the product

| | LocalGuard 1.0.0 | KhokharGuard 1.1.0 |
|---|---|---|
| Product name (UI, metadata) | LocalGuard Antivirus | Khokhar & Son's Antivirus |
| Executable / installer | `LocalGuard.exe`, `LocalGuard_Setup_1.0.0.exe` | `KhokharGuard.exe`, `KhokharGuard_Setup_1.1.0.exe` |
| Install directory | `%ProgramFiles%\LocalGuard` | `%ProgramFiles%\KhokharGuard` |
| Per-user data directory | `%LOCALAPPDATA%\LocalGuard` | `%LOCALAPPDATA%\KhokharGuard` |
| Background service | (not present in 1.0.0) | `KhokharGuardService` (optional, `KhokharGuard.exe service install`) |
| Theme / icons | LocalGuard shield icons | Brand kit gold theme, `khokharantivirus.ico` |
| YARA rule file | `localguard_eicar.yar` | `khokharguard_eicar.yar` |
| Authenticode | NotSigned | NotSigned (signing pending Azure setup — see `docs/AZURE_SIGNING_SETUP.md`) |

### Installed setup (LocalGuard_Setup_1.0.0.exe) → KhokharGuard_Setup_1.1.0.exe

1. **Uninstall LocalGuard 1.0.0 first** (Windows Settings → Apps, or
   Control Panel → Programs). It lives in `%ProgramFiles%\LocalGuard`
   under a different uninstall registry entry, and both builds register
   a per-user Run value, so keeping both would create two autostart
   entries and two tray icons.
   - Uninstalling does **not** delete `%LOCALAPPDATA%\LocalGuard` —
     your data stays.
2. Install `KhokharGuard_Setup_1.1.0.exe`.
3. On first start, the **legacy migration runs automatically**: settings
   (only keys you had explicitly changed), scan history, security
   events, and quarantine records are copied into
   `%LOCALAPPDATA%\KhokharGuard`, and a **"Data import complete"**
   summary dialog shows the counts once. Its **Review imported
   quarantined items** button opens the Quarantine page.
4. Verify: Help/About shows the data location, your old scan history is
   on the History page, and previously quarantined items can be
   restored.
5. If you used the legacy "start with Windows" option, re-enable it in
   Settings → General (the old registry value is deliberately not
   carried over; the new build registers its own).

### Portable 1.0.0 → portable 1.1.0

1. Extract `KhokharGuard-portable-1.1.0.zip` to a **new** folder. Note
   the layout change: the v1.0.0 zip wrapped everything in
   `LocalGuard-portable-1.0.0\`; the v1.1.0 zip contains
   `KhokharGuard.exe` and `_internal\` at the top level, so it must be
   extracted to its own dedicated folder.
2. Run `KhokharGuard.exe` from the new folder once. First start
   migrates the old `%LOCALAPPDATA%\LocalGuard` data automatically (the
   portable builds share the same per-user data directory model).
3. After confirming your history and quarantine carried over, you can
   delete the old `LocalGuard-portable-1.0.0` folder. Keep the new
   folder path stable if you created shortcuts to it.

### What migration copies — and what it never does

- **Copied** (never moved): settings you explicitly set, scan history,
  security events, quarantine records, quarantine vault files (restore
  keeps working — imported records are re-pointed at the new vault),
  exported reports.
- **Never**: overwritten existing KhokharGuard data, deleted the
  legacy `%LOCALAPPDATA%\LocalGuard` folder, re-registered the legacy
  autostart value, executed or opened any migrated file. Everything is
  a copy; the legacy folder stays until you remove it yourself.
- Runs once; a marker file (`legacy_migration.json`) records the
  completed import. Re-running is a no-op.

### Signature and detection-database notes

- The signature database format did not change between 1.0.0 and
  1.1.0; `signatures/hashes.json` carries over and updates normally.
- Custom signatures are preserved: the updater only ever adds or
  replaces published files, and your `signatures/update_public_key.pub`
  (if you installed one) is untouched by the rebrand.
- The YARA EICAR rule was renamed
  (`localguard_eicar.yar` → `khokharguard_eicar.yar`) — detection
  behaviour is identical; nothing to do on your side.

---

## Upgrading from KhokharGuard 1.1.0 forward

Standard flow for all later versions:

1. Read `docs/RELEASE_NOTES_X.Y.Z.md` for the target version
   (highlights, fixes, known limitations, checksums).
2. **Installer users:** run the new `KhokharGuard_Setup_X.Y.Z.exe`
   over the existing installation — it upgrades in place; user data in
   `%LOCALAPPDATA%\KhokharGuard` is untouched.
3. **Portable users:** extract the new zip to a new folder, let it run
   once against the existing data directory, then retire the old
   folder after verifying.
4. Verify after upgrading (`KhokharGuard.exe version` /
   `status`, or Help → About): version matches, data location
   unchanged, scan history and quarantine intact.
5. If a release ever misbehaves: uninstalling/downgrading never
   requires deleting `%LOCALAPPDATA%\KhokharGuard` — your history,
   quarantine vault, and settings survive version changes by design.

### Rolling back

- **Installer:** uninstall the newer build, install the older setup
  exe. The database and quarantine vault are shared per-user data, not
  part of the install directory, so a rollback keeps them.
- **Portable:** keep the previous version folder until the new one is
  verified, then swap.
- If the signature database was updated and you need the previous
  set: Settings → Updates offers rollback to versioned backups
  (`signature_backups/`).

---

## Verifying your download (any version)

```powershell
# Metadata + signature state
(Get-Item .\KhokharGuard_Setup_X.Y.Z.exe).VersionInfo |
  Select-Object ProductName, ProductVersion
(Get-AuthenticodeSignature .\KhokharGuard_Setup_X.Y.Z.exe).Status

# SHA-256 (compare against docs/RELEASE_NOTES_X.Y.Z.md)
Get-FileHash .\KhokharGuard_Setup_X.Y.Z.exe -Algorithm SHA256
```

v1.1.0 reference digests (also in the release notes):
- `KhokharGuard_Setup_1.1.0.exe`:
  `ecafb1326c900131b14512fe563f04d302f6330ab641c9e2548731f4176694d0`
- `KhokharGuard-portable-1.1.0.zip`:
  `d457668606d2fbe557144d499a460614769d38cbaa6acac2d477937c95d8c94c`

v1.0.0 reference digests:
- `LocalGuard_Setup_1.0.0.exe`:
  `2a7828a9a01d1ae77b1bf08d6ecd02f3f76e7391b80daeaeb509aa288e7e94e5`
- `LocalGuard-portable-1.0.0.zip`:
  `bc82837707e197227a9ecef638358cc6320c43585920af708d331746a9391adc`

Both releases are currently **unsigned** (`NotSigned`): Authenticode
signing is wired in CI and activates once the Azure Artifact Signing
account is configured — see `docs/AZURE_SIGNING_SETUP.md`. Until then,
always download from the official GitHub releases page and check the
SHA-256 digests above.
