"""Release consistency checks: run in CI before publishing artefacts.

Verifies that every place declaring the application version agrees,
and that the artefacts expected from a release build exist for the
declared version.

Usage:
    python scripts/check_release.py               # source consistency
    python scripts/check_release.py --artifacts dist  # + artefacts
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _fail(errors: list, message: str) -> None:
    """Record one failure."""
    errors.append(message)


def read_version() -> str:
    """The declared VERSION (single source of truth)."""
    return (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def check_installer_iss(version: str, errors: list) -> None:
    """installer/KhokharGuard_Setup.iss must declare the same version."""
    text = (ROOT / "installer" / "KhokharGuard_Setup.iss").read_text(
        encoding="utf-8")
    match = re.search(r'#define MyAppVersion "(.*?)"', text)
    if not match:
        _fail(errors, "installer/KhokharGuard_Setup.iss: MyAppVersion missing")
        return
    declared = match.group(1)
    if declared != version:
        _fail(errors,
              f"installer declares version {declared!r}, VERSION says "
              f"{version!r}")
    # The output filename embeds the version (Inno resolves
    # {#MyAppVersion} at compile time).
    if not re.search(
            r"OutputBaseFilename=KhokharGuard_Setup_(\{#MyAppVersion\}|"
            + re.escape(version) + r")", text):
        _fail(errors, "installer OutputBaseFilename does not embed the "
                      "declared version")


def check_changelog(version: str, errors: list) -> None:
    """CHANGELOG.md must have an entry for the current version."""
    changelog = ROOT / "CHANGELOG.md"
    if not changelog.is_file():
        _fail(errors, "CHANGELOG.md is missing")
        return
    text = changelog.read_text(encoding="utf-8")
    if f"[{version}]" not in text:
        _fail(errors, f"CHANGELOG.md has no [{version}] entry")


def check_pyproject_like_versions(version: str, errors: list) -> None:
    """The spec and README should not contradict VERSION where they
    mention concrete release filenames."""
    readme = ROOT / "README.md"
    if readme.is_file():
        text = readme.read_text(encoding="utf-8")
        stale = re.findall(
            r"KhokharGuard_Setup_(\d+\.\d+\.\d+)\.exe", text)
        for found in set(stale):
            if found != version:
                _fail(errors,
                      f"README.md references installer version {found!r} "
                      f"but VERSION is {version!r}")


def check_artifacts(version: str, dist: Path, errors: list) -> None:
    """Release artefacts for *version* must exist."""
    installer = dist / "installer" / f"KhokharGuard_Setup_{version}.exe"
    if not installer.is_file():
        _fail(errors, f"missing installer artefact: {installer}")
    bundle = dist / "KhokharGuard" / "KhokharGuard.exe"
    if not bundle.is_file():
        _fail(errors, f"missing frozen exe: {bundle}")


def main(argv: list | None = None) -> int:
    """Run all checks; non-zero exit on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", metavar="DIR",
                        help="also verify release artefacts under DIR")
    args = parser.parse_args(argv)

    errors: list = []
    version = read_version()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        _fail(errors, f"VERSION is not semver: {version!r}")

    check_installer_iss(version, errors)
    check_changelog(version, errors)
    check_pyproject_like_versions(version, errors)
    if args.artifacts:
        check_artifacts(version, Path(args.artifacts), errors)

    if errors:
        print("RELEASE CHECK FAILED:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(f"Release consistency OK (version {version})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
