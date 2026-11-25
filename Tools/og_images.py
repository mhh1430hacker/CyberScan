"""Draw the social-card images (Open Graph / Twitter, 1200x630) for the site's pages.

    .venv/Scripts/python.exe tools/og_images.py

Writes web_v/static/og/{landing,scan,journey,support,tests,privacy}.png in the site's identity:
night background (#04030c), violet / cyan / magenta light, a glass panel, the shield mark, the
page's title in English and Arabic. web_v/site_extras.py points each page's og:image at its card.
Fonts: Segoe UI (Windows) when present, else DejaVu Sans, else Pillow's built-in font.
"""
from __future__ import annotations

import math
import random
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "web_v" / "static" / "og"
W, H = 1200, 630
BG = (4, 3, 12)
VIOLET, CYAN, MAGENTA = (201, 162, 255), (34, 232, 255), (255, 79, 216)

CARDS = {
    "landing": ("CyberScan", "Static analysis of files, links and text,\nexplained in plain words.", "سايبر سكان · افحص دون أن تشغّل", "ainex-ai.xyz", CYAN),
    "scan": ("Scan a file, link or text", "Nothing you check is ever run.\nEvery finding explained.", "افحص ملفًا أو رابطًا أو نصًا", "scan.ainex-ai.xyz", CYAN),
    "journey": ("The File Journey", "Follow one file from the moment you drop it\nto the verdict, step by step.", "رحلة الملف", "j.ainex-ai.xyz", VIOLET),
    "support": ("The Cubeverse", "Support the developer, Mahdi Al-Hajji (Mynex),\nand explore five interactive cube worlds.", "ادعم المطوّر · عالم المكعبات", "ainex-ai.xyz/support", MAGENTA),
    "tests": ("Measured, not promised", "False alarms on clean files, synthetic samples\nand speed: the method and the real numbers.", "أرقام مقيسة، لا وعود", "ainex-ai.xyz/tests", CYAN),
    "privacy": ("Privacy, terms and security", "No accounts, no trackers. Files are read in memory\nand deleted after the check.", "الخصوصية والشروط والأمان", "ainex-ai.xyz/privacy", VIOLET),
}


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    names = (["segoeuib.ttf", "seguisb.ttf"] if bold else ["segoeui.ttf"]) + (["DejaVuSans-Bold.ttf"] if bold else ["DejaVuSans.ttf"])
    for name in names:
        for folder in (Path("C:/Windows/Fonts"), Path("/usr/share/fonts/truetype/dejavu")):
            if (folder / name).is_file():
                return ImageFont.truetype(str(folder / name), size)
    return ImageFont.load_default(size)


def arabic(text: str) -> str:
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
        return get_display(arabic_reshaper.reshape(text))
    except ImportError:
        return text


def glow(base: Image.Image, xy: tuple[int, int], radius: int, color: tuple[int, int, int], alpha: int) -> None:
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    ImageDraw.Draw(layer).ellipse((xy[0] - radius, xy[1] - radius, xy[0] + radius, xy[1] + radius), fill=(*color, alpha))
    base.alpha_composite(layer.filter(ImageFilter.GaussianBlur(radius * 0.55)))


def shield(d: ImageDraw.ImageDraw, x: int, y: int, s: float, color: tuple[int, int, int]) -> None:
    """The site's mark (a shield with a check, drawn on the icon's 64-unit grid), scaled by s."""
    path = [(32, 14), (20, 19), (20, 27)]
    path += [(20 + 12 * (i / 12) ** 1.6, 27 + 15 * math.sin(i / 12 * math.pi / 2)) for i in range(1, 13)]
    path += [(32 + 12 * (i / 12) ** 0.62, 42 - 15 * (1 - math.cos(i / 12 * math.pi / 2))) for i in range(1, 13)]
    path += [(44, 19), (32, 14)]
    width = max(3, int(3 * s / 2.2))
    d.line([(x + px * s, y + py * s) for px, py in path], fill=color, width=width, joint="curve")
    d.line([(x + 26.5 * s, y + 28.5 * s), (x + 30.3 * s, y + 32.3 * s), (x + 37.7 * s, y + 24.3 * s)], fill=color, width=width, joint="curve")


def card(key: str, title: str, sub: str, ar: str, url: str, accent: tuple[int, int, int]) -> Image.Image:
    img = Image.new("RGBA", (W, H), (*BG, 255))
    glow(img, (1040, 40), 420, VIOLET, 70)
    glow(img, (120, 560), 380, accent, 46)
    glow(img, (700, 700), 300, MAGENTA, 38)
    fine = Image.new("RGBA", (W, H), (0, 0, 0, 0))   # drawn on its own layer: ImageDraw doesn't blend alpha
    d = ImageDraw.Draw(fine)
    rng = random.Random(key)
    for _ in range(140):   # a quiet star field
        x, y = rng.randrange(W), rng.randrange(H)
        a = rng.randrange(40, 150)
        d.point((x, y), fill=(220, 210, 255, a))
    for gx in range(0, W, 60):   # faint grid, fading right to left
        d.line([(gx, 0), (gx, H)], fill=(201, 162, 255, 6 + gx // 100))
    img.alpha_composite(fine)
    # the glass panel
    panel = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    pd = ImageDraw.Draw(panel)
    pd.rounded_rectangle((60, 70, 1140, 560), radius=36, fill=(18, 12, 40, 150), outline=(201, 162, 255, 70), width=2)
    img.alpha_composite(panel)
    d = ImageDraw.Draw(img)
    shield(d, 92, 104, 2.2, accent)
    d.text((250, 128), "CYBERSCAN", font=font(26, True), fill=(*accent, 255))
    d.text((250, 168), url, font=font(24), fill=(207, 198, 234, 255))
    d.text((104, 252), title, font=font(70 if len(title) < 22 else 58, True), fill=(255, 255, 255, 255))
    d.multiline_text((104, 350), sub, font=font(32), fill=(220, 212, 245, 255), spacing=10)
    f_ar = font(34, True)
    t_ar = arabic(ar)
    w_ar = d.textlength(t_ar, font=f_ar)
    d.text((1096 - w_ar, 478), t_ar, font=f_ar, fill=(*VIOLET, 255))
    # the identity's three-colour line
    for i, c in enumerate((VIOLET, CYAN, MAGENTA)):
        d.rounded_rectangle((104 + i * 70, 492, 160 + i * 70, 498), radius=3, fill=(*c, 255))
    return img.convert("RGB")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for key, spec in CARDS.items():
        path = OUT / f"{key}.png"
        card(key, *spec).save(path, optimize=True)
        print(f"{path.relative_to(ROOT)}  {path.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
