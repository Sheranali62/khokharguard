# Releasing KhokharGuard

A step-by-step checklist for cutting a release. Every release is a
version tag; CI does the build, test, signing, and packaging, and this
document is the human verification harness around it.

## 0. Prerequisites (check before starting)

- [ ] Working tree clean; on `main` and in sync
      (`git status`, `git pull --rebase`).
- [ ] Full suite green locally:
      `.venv/Scripts/python.exe -m pytest`
      (expect the documented pass/skip counts; investigate any
      increase in skips).
- [ ] `python -m compileall -q .` clean.
- [ ] No secrets, tokens, or personal paths in `git diff origin/main`.

## 1. Version bump (semver: MAJOR.MINOR.PATCH)

`VERSION` is the single source of truth: the PyInstaller spec, the
About page, and the installer filename all derive from it.
`scripts/check_release.py` enforces consistency (installer `.iss`
declaration, README references, artefact filenames).

- [ ] `VERSION` (single line, e.g. `1.1.0`)
- [ ] `CHANGELOG.md` — add a `## [X.Y.Z] - YYYY-MM-DD` section under
      the Unreleased content; keep a link definition at the bottom
- [ ] `docs/RELEASE_NOTES_X.Y.Z.md` created (see step 2)

Then:

```bash
.venv/Scripts/python.exe scripts/check_release.py   # must pass
```

## 2. Pre-flight review

- [ ] `CHANGELOG.md` entries describe user-visible changes honestly,
      including known limitations.
- [ ] `docs/RELEASE_NOTES_X.Y.Z.md` exists for the new version
      (copy the previous release's structure: highlights, fixes,
      security notes, limitations, checksums placeholder).
- [ ] Any new runtime files/directories are covered by `.gitignore`.
- [ ] Spec compliance spot-check: quarantine-before-delete,
      no auto-execution of scanned files, telemetry still OFF by
      default (these are release blockers, not nice-to-haves).

## 3. Tag and push

```bash
git commit -m "Release X.Y.Z"   # only if docs changed since last commit
git tag -a vX.Y.Z -m "Khokhar & Son's Antivirus X.Y.Z"
git push origin main
git push origin vX.Y.Z
```

- The tag push triggers the release workflow on
  `actions/runs?query=tag:vX.Y.Z`.
- **Never re-point a published tag.** If CI fails on the tag, fix on
  `main`, then create `vX.Y.Z+1` (or re-point **only** if no artefact
  was downloaded or release published yet — and force-push with a
  note in the changelog). Duplicated version artefacts with different
  bytes are how supply-chain confusion happens.

## 4. Watch the CI release run

- [ ] All jobs green (`gh run watch <run-id>` or the Actions tab).
- [ ] **Sign frozen binaries** and **Sign installer** steps: either
      *skipped* (signing secrets absent — artefacts will be unsigned;
      flag this in the release notes) or *succeeded* (signed). A
      signing **failure** blocks the release: fix before publishing.
      Signing auth is OIDC-first (needs `AZURE_CLIENT_ID`,
      `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` + a federated
      credential) with a client-secret fallback — see
      `docs/AZURE_SIGNING_SETUP.md`.
- [ ] If the `REQUIRE_SIGNED_ARTIFACTS` repository **variable** is set
      to `true`, the **Require signed artefacts** step must have
      *succeeded* — it hard-fails the build when any shipped `.exe`
      (installer or portable) is unsigned. Flip the variable on only
      after the first signed release has been verified end to end
      (`docs/AZURE_SIGNING_SETUP.md`, step 6).
- [ ] `Verify release artefacts` step passed (runs
      `scripts/check_release.py --artifacts dist`).
- [ ] Both artefacts uploaded:
      `KhokharGuard-Setup-vX.Y.Z` and `KhokharGuard-portable-vX.Y.Z`.

## 5. Verify artefacts by use (not just by size)

The commands below are the ones actually used for v1.1.0 — copy them
and substitute the version.

Download both artefacts (run page, or:

```bash
gh run download <run-id> --repo Sheranali62/khokharguard \
  -n KhokharGuard-Setup-vX.Y.Z -D setup
gh run download <run-id> --repo Sheranali62/khokharguard \
  -n KhokharGuard-portable-vX.Y.Z -D portable
```

) and:

**Installer**
- [ ] Zip extracts intact (no truncation).
- [ ] Version metadata + signature state in one shot:

      ```powershell
      powershell -NoProfile -Command "(Get-Item 'setup/KhokharGuard_Setup_X.Y.Z.exe').VersionInfo |
        Select-Object ProductName, ProductVersion | Format-List;
      'Authenticode: ' + (Get-AuthenticodeSignature
        'setup/KhokharGuard_Setup_X.Y.Z.exe').Status"
      ```

      Expect `ProductName: Khokhar & Son's Antivirus`, the released
      version, and `Valid` — or `NotSigned`, explicitly recorded as
      such in the release notes.
- [ ] Installer runs on a clean VM/user profile: installs, Start Menu
      shortcut launches, uninstall removes everything.

**Portable bundle**
- [ ] Extracts and runs from a user-writable directory.
- [ ] `./KhokharGuard.exe version` prints the branded version banner
      (`Khokhar & Son's Antivirus X.Y.Z`).
- [ ] `./KhokharGuard.exe status` completes and reports the real
      data dir (`%LOCALAPPDATA%\KhokharGuard\khokharguard.db`).
- [ ] Bundle contents present: `_internal/assets/icons/`
      (khokharantivirus.ico + tray/shield PNGs),
      `_internal/signatures/hashes.json`,
      `_internal/signatures/yara/*.yar`, `_internal/database/schema.sql`,
      `_internal/config/default_config.json`.
- [ ] GUI launch opens the dashboard; close is clean (no zombie
      processes, `logs/khokharguard.log` has no CRITICAL lines).

**Checksums**

```bash
sha256sum setup/KhokharGuard_Setup_X.Y.Z.exe \
  KhokharGuard-portable-X.Y.Z.zip
```

(On Windows PowerShell:
`Get-FileHash <file> -Algorithm SHA256`.)

- [ ] Record the digests in the release notes (replaces the
      placeholder).

## 6. Publish the GitHub Release

```bash
gh release create vX.Y.Z \
  --repo Sheranali62/khokharguard \
  --title "Khokhar & Son's Antivirus vX.Y.Z" \
  --notes-file docs/RELEASE_NOTES_X.Y.Z.md \
  KhokharGuard_Setup_vX.Y.Z.exe \
  KhokharGuard-portable-vX.Y.Z.zip
```

- [ ] Release notes include: highlights, fixes, security notes,
      **known limitations**, and the SHA-256 checksums from step 5.
- [ ] Unsigned release? State it plainly in the notes and remind users
      of the SmartScreen behaviour.
- [ ] Verify the release page renders and both assets download.

## 7. Post-release

- [ ] Announce only what is true: KhokharGuard is local-first,
      complements Windows Security, and guarantees nothing about
      detecting every threat.
- [ ] Bump `VERSION` on `main` to the next `-dev` version **only** if
      the team decides to track in-flight versions (optional).
- [ ] Open issues for anything deferred from the changelog's
      "Unreleased" section.

## Rollback / incident handling

- A bad release is **not** deleted from GitHub: publish a patch
  release and mark the broken one with a release-page warning note
  (`gh release edit vX.Y.Z --notes-file warning.md`).
- If a release artefact is found to be compromised: delete the
  **asset**, publish a superseding release, and rotate anything the
  incident touches (signing secrets, CI credentials).
- Quarantine/restoration data is user-local; release problems never
  require touching user machines remotely (KhokharGuard has no such
  capability by design).
