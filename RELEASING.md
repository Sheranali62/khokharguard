# Releasing LocalGuard

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
git tag -a vX.Y.Z -m "LocalGuard Antivirus X.Y.Z"
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
      *skipped* (secrets absent — artefacts will be unsigned; flag
      this in the release notes) or *succeeded* (signed). A signing
      **failure** blocks the release: fix before publishing.
- [ ] `Verify release artefacts` step passed (runs
      `scripts/check_release.py --artifacts dist`).
- [ ] Both artefacts uploaded:
      `LocalGuard-Setup-vX.Y.Z` and `LocalGuard-portable-vX.Y.Z`.

## 5. Verify artefacts by use (not just by size)

Download both artefacts from the run page (or
`gh api repos/Sheranali62/localguard/actions/artifacts`) and:

**Installer**
- [ ] Zip extracts intact (no truncation).
- [ ] `Get-AuthenticodeSignature .\LocalGuard_Setup_vX.Y.Z.exe` →
      `Valid` (or explicitly recorded as unsigned this release).
- [ ] Installer runs on a clean VM/user profile: installs, Start Menu
      shortcut launches, uninstall removes everything.

**Portable bundle**
- [ ] Extracts and runs from a user-writable directory.
- [ ] `LocalGuard.exe version` prints the released version.
- [ ] `LocalGuard.exe quick-scan` (or a scan of a temp tree) completes.
- [ ] GUI launch opens the dashboard; close is clean (no zombie
      processes, `logs/localguard.log` has no CRITICAL lines).

**Checksums**

```bash
sha256sum LocalGuard_Setup_vX.Y.Z.exe LocalGuard-portable-vX.Y.Z.zip
```

- [ ] Record the digests in the release notes (replaces the
      placeholder).

## 6. Publish the GitHub Release

```bash
gh release create vX.Y.Z \
  --repo Sheranali62/localguard \
  --title "LocalGuard Antivirus vX.Y.Z" \
  --notes-file docs/RELEASE_NOTES_X.Y.Z.md \
  LocalGuard_Setup_vX.Y.Z.exe \
  LocalGuard-portable-vX.Y.Z.zip
```

- [ ] Release notes include: highlights, fixes, security notes,
      **known limitations**, and the SHA-256 checksums from step 5.
- [ ] Unsigned release? State it plainly in the notes and remind users
      of the SmartScreen behaviour.
- [ ] Verify the release page renders and both assets download.

## 7. Post-release

- [ ] Announce only what is true: LocalGuard is local-first,
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
  require touching user machines remotely (LocalGuard has no such
  capability by design).
