#!/usr/bin/env python3
"""Generate the LocalGuard icon assets from vector definitions.

Produces (in assets/icons/):

    localguard.ico      multi-resolution application icon (protected)
    tray_protected.png  64x64 tray icon - green shield, check mark
    tray_paused.png     64x64 tray icon - amber shield, pause bars
    tray_warning.png    64x64 tray icon - red shield, exclamation mark
    tray_protected_overlay_0.png / _1.png  scanning progress overlays
                        composited over the protected shield (badge is
                        blue-green filled / hollow ring). The tray swaps
                        them to "flash" a live progress hint while a
                        scan runs.
    shield_16.png / shield_32.png / shield_48.png  UI shield images

All three states share the same shield silhouette so the tray icon
never "jumps" when the security state changes; only the tint and mark
differ (green check = protected, amber pause = paused, red
exclamation = warning/attention).

Run:  .venv/Scripts/python.exe scripts/generate_icons.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "icons"

# Theme palette (ui/theme.py) so tray and UI colors always match.
GREEN = (34, 197, 94)      # success
AMBER = (245, 158, 11)     # warning
RED = (239, 68, 68)        # danger
BLUE = (59, 130, 246)      # scanning / active work
OUTLINE = (30, 31, 36)
MARK = (255, 255, 255)
TRANSPARENT = (0, 0, 0, 0)

BASE = 64        # final render size for tray PNGs
SCALE = 8        # supersampling factor for smooth edges
BIG = BASE * SCALE

# Shield silhouette in BASE coordinate space.
SHIELD_POINTS = [
    (32, 4), (55, 11), (55, 30), (32, 59), (9, 30), (9, 11),
]


def _scaled(points: list) -> list:
    """Scale point list into the supersampled canvas."""
    return [(x * SCALE, y * SCALE) for x, y in points]


def render_state(ok: bool | None = None, state: str = "protected") -> Image.Image:
    """Render one shield state at BASE x BASE, RGBA.

    ``state``: "protected" (green check), "paused" (amber pause bars),
    or "warning" (red exclamation). ``ok`` is honoured for backwards
    compatibility: True -> protected, False -> paused.
    """
    if ok is not None:
        state = "protected" if ok else "paused"

    image = Image.new("RGBA", (BIG, BIG), TRANSPARENT)
    draw = ImageDraw.Draw(image)
    s = SCALE

    fill = {"protected": GREEN, "paused": AMBER, "warning": RED}[state]
    draw.polygon(_scaled(SHIELD_POINTS), fill=fill + (255,),
                 outline=OUTLINE + (255,), width=1 * s)

    if state == "protected":
        # Check mark.
        draw.line([(20 * s, 31 * s), (29 * s, 40 * s), (45 * s, 21 * s)],
                  fill=MARK + (255,), width=5 * s, joint="curve")
    elif state == "paused":
        # Pause bars.
        draw.rectangle((22 * s, 21 * s, 28 * s, 43 * s), fill=MARK + (255,))
        draw.rectangle((36 * s, 21 * s, 42 * s, 43 * s), fill=MARK + (255,))
    else:  # warning
        # Exclamation mark: bar + dot.
        draw.line([(32 * s, 19 * s), (32 * s, 36 * s)],
                  fill=MARK + (255,), width=6 * s)
        draw.ellipse((29 * s, 41 * s, 35 * s, 47 * s), fill=MARK + (255,))

    return image.resize((BASE, BASE), Image.LANCZOS)


def render_scanning_state() -> Image.Image:
    """Render the scanning variant of the shield (blue, hollow ring).

    A distinct tint communicates "working" without losing the brand
    silhouette; the hollow ring distinguishes it from "paused" at a
    glance even at 16 px.
    """
    image = Image.new("RGBA", (BIG, BIG), TRANSPARENT)
    draw = ImageDraw.Draw(image)
    s = SCALE
    draw.polygon(_scaled(SHIELD_POINTS), fill=BLUE + (255,),
                 outline=OUTLINE + (255,), width=1 * s)
    ring = 2 * s
    draw.ellipse((32 * s - 11 * s, 32 * s - 11 * s,
                  32 * s + 11 * s, 32 * s + 11 * s),
                 outline=MARK + (255,), width=ring)
    return image.resize((BASE, BASE), Image.LANCZOS)


def apply_scan_overlay(base: Image.Image, phase: int = 0) -> Image.Image:
    """Composite the scan-progress badge onto a copy of *base*.

    ``phase`` selects the alternating overlay frame: 0 -> filled
    blue-green badge, 1 -> hollow badge. Tray flashing alternates the
    two so the overlay visibly pulses while a scan runs.
    """
    image = base.copy().convert("RGBA")
    draw = ImageDraw.Draw(image)
    # Badge sits at the lower-right, sized for 16 px legibility.
    cx, cy, r = 46, 46, 10
    box = (cx - r, cy - r, cx + r, cy + r)
    if phase == 0:
        draw.ellipse(box, fill=BLUE + (255,), outline=MARK + (255,), width=2)
        draw.line([(cx - 4, cy), (cx + 4, cy)], fill=MARK + (255,), width=2)
    else:
        draw.ellipse(box, outline=BLUE + (255,), width=3)
    return image


def build_ico(images: list, target: Path) -> None:
    """Write a multi-resolution .ico from rendered states."""
    # Re-render the protected state at the sizes ICO files expect.
    sources = [img for img in images]
    sources.append(render_state(state="protected").resize((16, 16), Image.LANCZOS))
    sources.append(render_state(state="protected").resize((24, 24), Image.LANCZOS))
    sources.append(render_state(state="protected").resize((32, 32), Image.LANCZOS))
    sources.append(render_state(state="protected").resize((48, 48), Image.LANCZOS))
    sources.append(render_state(state="protected").resize((64, 64), Image.LANCZOS))
    sources.append(render_state(state="protected").resize((128, 128), Image.LANCZOS))
    sources.append(render_state(state="protected").resize((256, 256), Image.LANCZOS))
    sources[0].save(target, format="ICO",
                    sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
                           (64, 64), (128, 128), (256, 256)],
                    append_images=sources[1:])


def main() -> None:
    """Render every asset and report sizes."""
    OUT.mkdir(parents=True, exist_ok=True)

    protected = render_state(state="protected")
    paused = render_state(state="paused")
    warning = render_state(state="warning")

    protected.save(OUT / "tray_protected.png")
    paused.save(OUT / "tray_paused.png")
    warning.save(OUT / "tray_warning.png")
    render_scanning_state().save(OUT / "tray_scanning.png")

    # Scanning progress overlays (alternating frames for the tray
    # flash). The badge is composited over the protected shield so the
    # overlay alone describes the progress hint.
    apply_scan_overlay(protected, phase=0).save(
        OUT / "tray_protected_overlay_0.png")
    apply_scan_overlay(protected, phase=1).save(
        OUT / "tray_protected_overlay_1.png")

    for size in (16, 32, 48):
        protected.resize((size, size), Image.LANCZOS).save(
            OUT / f"shield_{size}.png")

    build_ico([protected], OUT / "localguard.ico")

    for asset in sorted(OUT.iterdir()):
        print(f"  {asset.name}: {asset.stat().st_size:,} bytes")
    print("Icon assets generated in assets/icons/")


if __name__ == "__main__":
    main()
