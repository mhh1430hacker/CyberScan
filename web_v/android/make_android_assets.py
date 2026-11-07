"""Draw the Android launcher icons, splash screens and Play Store graphics from the web app's icons.

    .venv\\Scripts\\python.exe web_v\\android\\make_android_assets.py
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

HERE = Path(__file__).resolve().parent
ICONS = HERE.parent / "static" / "m"
RES = HERE / "android" / "app" / "src" / "main" / "res"
STORE = HERE / "store"
BG = (7, 5, 26)
DENSITY = {"mdpi": 1, "hdpi": 1.5, "xhdpi": 2, "xxhdpi": 3, "xxxhdpi": 4}


def launcher() -> None:
    full = Image.open(ICONS / "icon-512.png").convert("RGBA")          # rounded square, for old launchers
    bleed = Image.open(ICONS / "icon-maskable-512.png").convert("RGBA")  # full bleed, logo in the safe zone
    for name, k in DENSITY.items():
        folder = RES / f"mipmap-{name}"
        folder.mkdir(parents=True, exist_ok=True)
        s = round(48 * k)
        full.resize((s, s), Image.LANCZOS).save(folder / "ic_launcher.png")
        mask = Image.new("L", (s * 4, s * 4), 0)
        ImageDraw.Draw(mask).ellipse((0, 0, s * 4 - 1, s * 4 - 1), fill=255)
        round_icon = bleed.resize((s, s), Image.LANCZOS)
        round_icon.putalpha(mask.resize((s, s), Image.LANCZOS))
        round_icon.save(folder / "ic_launcher_round.png")
        f = round(108 * k)                                               # adaptive icon layer
        bleed.resize((f, f), Image.LANCZOS).save(folder / "ic_launcher_foreground.png")
    (RES / "values" / "ic_launcher_background.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n    <color name="ic_launcher_background">#07051A</color>\n</resources>\n',
        encoding="utf-8")


def logo(size: int) -> Image.Image:
    """The glowing hexagon and shield, cut from the maskable icon (transparent around it)."""
    bleed = Image.open(ICONS / "icon-maskable-512.png").convert("RGB")
    crop = bleed.crop((128, 112, 384, 400)).resize((size, round(size * 288 / 256)), Image.LANCZOS)
    alpha = crop.convert("L").point(lambda v: 0 if v < 26 else min(255, (v - 26) * 3))
    out = crop.convert("RGBA")
    out.putalpha(alpha)
    return out


def splashes() -> None:
    for png in RES.glob("drawable*/splash.png"):
        w, h = Image.open(png).size
        img = Image.new("RGB", (w, h), BG)
        mark = logo(round(min(w, h) * 0.32))
        img.paste(mark, ((w - mark.width) // 2, (h - mark.height) // 2), mark)
        img.save(png, optimize=True)


def store() -> None:
    STORE.mkdir(exist_ok=True)
    Image.open(ICONS / "icon-maskable-512.png").convert("RGB").save(STORE / "icon-512.png")   # Play wants 512×512, no transparency
    w, h = 1024, 500
    img = Image.new("RGB", (w, h), BG)
    glow = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(glow)
    d.ellipse((60, -40, 560, 540), fill=(46, 18, 92))
    d.ellipse((620, 120, 1100, 600), fill=(8, 60, 84))
    img = Image.blend(img, glow.filter(ImageFilter.GaussianBlur(120)), 0.9)
    mark = logo(250)
    img.paste(mark, (110, (h - mark.height) // 2), mark)
    d = ImageDraw.Draw(img)
    try:
        big = ImageFont.truetype("segoeuib.ttf", 76)
        small = ImageFont.truetype("segoeui.ttf", 30)
    except OSError:
        big = small = ImageFont.load_default()
    d.text((430, 165), "CyberScan", font=big, fill=(234, 255, 255))
    d.text((434, 268), "See what's inside a file,", font=small, fill=(127, 243, 255))
    d.text((434, 308), "before you open it.", font=small, fill=(180, 108, 255))
    img.save(STORE / "feature-graphic-1024x500.png")


if __name__ == "__main__":
    launcher()
    splashes()
    store()
    print("icons, splash screens and store graphics written")
