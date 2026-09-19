# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build specification for Khokhar & Son's Antivirus.

Build with:  pyinstaller khokharguard.spec --noconfirm

The resulting onedir bundle (dist/KhokharGuard/KhokharGuard.exe) includes:
  - all Python modules
  - database/schema.sql
  - config/default_config.json
  - signatures/hashes.json and signatures/yara/*.yar
  - VERSION
"""

import os
from pathlib import Path

block_cipher = None
ROOT = Path(SPECPATH)

datas = [
    (str(ROOT / "database" / "schema.sql"), "database"),
    (str(ROOT / "config" / "default_config.json"), "config"),
    (str(ROOT / "signatures" / "hashes.json"), "signatures"),
    (str(ROOT / "VERSION"), "."),
]

# Tray/UI icon assets (tray_*.png, shield_*.png) for runtime loading.
icon_assets = ROOT / "assets" / "icons"
if icon_assets.is_dir():
    for asset in icon_assets.glob("*.png"):
        datas.append((str(asset), "assets/icons"))
    brand_ico = icon_assets / "khokharantivirus.ico"
    if brand_ico.is_file():
        datas.append((str(brand_ico), "assets/icons"))

yara_rules = ROOT / "signatures" / "yara"
if yara_rules.is_dir():
    for rule in yara_rules.glob("*.yar"):
        datas.append((str(rule), "signatures/yara"))

# Upgrade guide (surfaced from the migration summary dialog).
upgrade_doc = ROOT / "docs" / "UPGRADING.md"
if upgrade_doc.is_file():
    datas.append((str(upgrade_doc), "docs"))

hiddenimports = [
    "psutil",
    "watchdog.observers",
    "pywintypes",
    "winreg",
    # Windows service hosting (spec section 45): the frozen exe
    # registers itself as its own service binary via main.py dispatch.
    "win32service",
    "win32serviceutil",
    "win32event",
    "servicemanager",
    # System tray (spec section 43):
    "pystray",
    "pystray._win32",
    "PIL",
    "PIL.Image",
    "PIL.ImageDraw",
]

a = Analysis(
    ["main.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "matplotlib", "numpy", "pandas", "PyQt5", "PyQt6",
        "PySide2", "PySide6", "scipy", "IPython", "jupyter",
        # Test-only modules must not ship in the frozen app:
        "pytest", "yara",  # yara-python ships its own binary via hook if installed
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="KhokharGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,          # GUI application: no console window
    icon=str(ROOT / "assets" / "icons" / "khokharantivirus.ico")
         if (ROOT / "assets" / "icons" / "khokharantivirus.ico").exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="KhokharGuard",
)
