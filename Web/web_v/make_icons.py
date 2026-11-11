"""Draw CyberScan's app icons as PNG (iPhone needs PNG; Android likes 192/512 + maskable).

    .venv\\Scripts\\python.exe web_v\\make_icons.py
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

OUT = Path(__file__).resolve().parent / "static" / "m"
CYAN, VIOLET, BG = (34, 232, 255), (180, 108, 255), (7, 5, 26)
S = 4  # draw big, shrink: smooth edges


def shield(d: ImageDraw.ImageDraw, cx: float, cy: float, k: float, color, width: int) -> None:
    # the logo's shield outline (from the 64-unit SVG), as a polygon
    pts = [(32, 14), (20, 19), (20, 27), (21, 33), (24, 38), (28, 41), (32, 42.5), (36, 41), (40, 38), (43, 33), (44, 27), (44, 19)]
    poly = [(cx + (x - 32) * k, cy + (y - 28) * k) for x, y in pts]
    d.line(poly + [poly[0]], fill=color, width=width, joint="curve")
    tick = [(26.5, 28.5), (30.3, 32.3), (37.7, 24.3)]
    d.line([(cx + (x - 32) * k, cy + (y - 28) * k) for x, y in tick], fill=(200, 250, 255), width=int(width * 1.15), joint="curve")


def icon(size: int, maskable: bool = False, rounded: bool = False) -> Image.Image:
    n = size * S
    img = Image.new("RGB", (n, n), BG)
    glow = Image.new("RGB", (n, n), (0, 0, 0))
    g = ImageDraw.Draw(glow)
    # violet haze and a hexagon ring
    g.ellipse([n * .1, n * .25, n * .9, n * 1.05], fill=(60, 24, 110))
    glow = glow.filter(ImageFilter.GaussianBlur(n * .12))
    img = Image.blend(img, glow, .55)
    d = ImageDraw.Draw(img)
    k = (n * (0.28 if maskable else 0.42)) / 32  # maskable keeps the logo inside the safe circle
    cx, cy = n / 2, n / 2 + k * 1.5
    import math
    hexr = k * 27
    hexpts = [(cx + hexr * math.cos(math.pi / 6 + i * math.pi / 3), cy - k * 1.5 + hexr * math.sin(math.pi / 6 + i * math.pi / 3)) for i in range(6)]
    d.line(hexpts + [hexpts[0]], fill=VIOLET, width=max(2, int(k * 1.1)), joint="curve")
    # neon: blurred copy under a sharp line
    halo = Image.new("RGB", (n, n), (0, 0, 0))
    shield(ImageDraw.Draw(halo), cx, cy, k, CYAN, int(k * 4.5))
    halo = halo.filter(ImageFilter.GaussianBlur(k * 2.2))
    img = Image.composite(Image.new("RGB", (n, n), CYAN), img, halo.convert("L").point(lambda v: min(255, int(v * 1.1))))
    shield(ImageDraw.Draw(img), cx, cy, k, CYAN, int(k * 2.6))
    img = img.resize((size, size), Image.LANCZOS)
    if rounded:
        mask = Image.new("L", (size, size), 0)
        ImageDraw.Draw(mask).rounded_rectangle([0, 0, size - 1, size - 1], radius=int(size * .22), fill=255)
        out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        out.paste(img, (0, 0), mask)
        return out
    return img


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    icon(192, rounded=True).save(OUT / "icon-192.png", optimize=True)
    icon(512, rounded=True).save(OUT / "icon-512.png", optimize=True)
    icon(512, maskable=True).save(OUT / "icon-maskable-512.png", optimize=True)
    icon(180).save(OUT / "apple-touch-icon.png", optimize=True)  # iOS rounds the corners itself
    for p in sorted(OUT.glob("*.png")):
        print(p.name, p.stat().st_size)


if __name__ == "__main__":
    main()
