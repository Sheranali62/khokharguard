"""Generate Khokhar & Son's icon assets from the premium brand kit.

Reads the approved brand artwork (assets/brand/) and produces every
icon the application needs, in assets/icons/:

    khokharantivirus.ico  multi-resolution application icon (16-256 px),
                          embedded in KhokharAntivirus.exe by the
                          PyInstaller spec and used by the installer and
                          shortcuts (title bar + taskbar).
    tray_protected.png    64x64 tray icon - brand artwork (gold/black).
    tray_paused.png       64x64 tray icon - desaturated + amber, pause
                          bars.
    tray_warning.png      64x64 tray icon - red tinted, exclamation bar.
    tray_scanning.png     64x64 tray icon - gold tinted, ring arc.
    tray_protected_overlay_0/1.png  scanning flash frames (progress
                          ring segments over the protected art).
    shield_16/32/48.png   UI shield images (dashboard/about sizing).

Run from the repo root:  python scripts/generate_icons.py
Requires Pillow. The brand kit files are read-only inputs; outputs are
reproducible from them at any time.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageEnhance

ROOT = Path(__file__).resolve().parent.parent
BRAND = ROOT / "assets" / "brand"
OUT = ROOT / "assets" / "icons"

SOURCE_ICON = BRAND / "05_App_Icon.png"
TRAY_SIZE = 64
ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]

# State tints (RGB) and overlay marks.
AMBER = (245, 158, 11)
RED = (239, 68, 68)
GOLD = (212, 175, 55)
MARK = (255, 255, 255)


def _load_source() -> Image.Image:
    """The approved app-icon artwork, RGBA square."""
    with Image.open(SOURCE_ICON) as handle:
        image = handle.convert("RGBA")
    side = min(image.size)
    left = (image.width - side) // 2
    top = (image.height - side) // 2
    return image.crop((left, top, left + side, top + side))


def _tint(image: Image.Image, color, strength: float) -> Image.Image:
    """Blend the artwork toward *color* by a fraction (0..1)."""
    layer = Image.new("RGBA", image.size, color + (255,))
    return Image.blend(image, layer, strength)


def _scaled_round(size: int) -> Image.Image:
    """Brand artwork resized with circular mask (tray-friendly)."""
    source = _load_source().resize((size, size), Image.LANCZOS)
    mask = Image.new("L", (size * 4, size * 4), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, size * 4, size * 4), fill=255)
    mask = mask.resize((size, size), Image.LANCZOS)
    result = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    result.paste(source, (0, 0), mask)
    return result


def generate_app_ico() -> None:
    """Multi-resolution .ico straight from the brand artwork."""
    source = _load_source()
    source.save(
        OUT / "khokharantivirus.ico",
        format="ICO",
        sizes=[(size, size) for size in ICO_SIZES],
    )


def _pause_bars(draw: ImageDraw.ImageDraw, size: int) -> None:
    """Two white pause bars centred in the lower third."""
    bar_w, bar_h = max(4, size // 10), size // 4
    gap = max(3, size // 14)
    x0 = (size - (bar_w * 2 + gap)) // 2
    y0 = int(size * 0.58)
    for offset in (0, bar_w + gap):
        draw.rounded_rectangle(
            (x0 + offset, y0, x0 + offset + bar_w, y0 + bar_h),
            radius=bar_w // 3, fill=MARK + (255,))


def _exclamation(draw: ImageDraw.ImageDraw, size: int) -> None:
    """White exclamation mark centred in the lower third."""
    bar_w = max(4, size // 10)
    cx = size // 2
    top, bottom = int(size * 0.52), int(size * 0.78)
    draw.rounded_rectangle((cx - bar_w // 2, top, cx + bar_w // 2, bottom),
                           radius=bar_w // 3, fill=MARK + (255,))
    dot = max(3, bar_w)
    draw.ellipse((cx - dot // 2, bottom + size // 24,
                  cx + dot // 2, bottom + size // 24 + dot),
                 fill=MARK + (255,))


def _ring(draw: ImageDraw.ImageDraw, size: int, start: int, end: int,
          color=MARK, width: int = 5) -> None:
    """Arc segment around the icon edge (scan progress hint)."""
    pad = width
    box = (pad, pad, size - pad, size - pad)
    draw.arc(box, start=start, end=end, fill=color + (255,), width=width)


def generate_tray_states() -> dict:
    """All four tray states plus the two flash overlay frames."""
    tray = _scaled_round(TRAY_SIZE)

    protected = tray.copy()
    protected.save(OUT / "tray_protected.png")

    paused = _tint(tray, AMBER, 0.45)
    paused = ImageEnhance.Color(paused).enhance(0.35)
    draw = ImageDraw.Draw(paused)
    _pause_bars(draw, TRAY_SIZE)
    paused.save(OUT / "tray_paused.png")

    warning = _tint(tray, RED, 0.5)
    draw = ImageDraw.Draw(warning)
    _exclamation(draw, TRAY_SIZE)
    warning.save(OUT / "tray_warning.png")

    scanning = _tint(tray, GOLD, 0.35)
    draw = ImageDraw.Draw(scanning)
    _ring(draw, TRAY_SIZE, start=210, end=150)
    scanning.save(OUT / "tray_scanning.png")

    # Flash frames: alternating ring halves over the protected art.
    for index, (start, end) in enumerate(((180, 360), (0, 180))):
        frame = tray.copy()
        draw = ImageDraw.Draw(frame)
        _ring(draw, TRAY_SIZE, start=start, end=end, color=GOLD, width=6)
        frame.save(OUT / f"tray_protected_overlay_{index}.png")
    return {"tray": ["protected", "paused", "warning", "scanning"]}


def generate_ui_shields() -> None:
    """Small round UI images for dashboard/about placement."""
    for size in (16, 32, 48):
        _scaled_round(size).save(OUT / f"shield_{size}.png")


def main() -> int:
    """Regenerate every icon asset from the brand kit."""
    if not SOURCE_ICON.is_file():
        raise SystemExit(f"Brand kit missing: {SOURCE_ICON}")
    OUT.mkdir(parents=True, exist_ok=True)
    generate_app_ico()
    states = generate_tray_states()
    generate_ui_shields()
    produced = sorted(p.name for p in OUT.iterdir() if p.is_file())
    print("Generated from brand kit:")
    for name in produced:
        print("  ", name)
    print("states:", states)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
