r"""Vector icons for the launcher shortcuts and the Quick Settings tile, plus the themed (monochrome) launcher icon.

    .venv\Scripts\python.exe web_v\android\make_android_drawables.py
"""
from pathlib import Path

from PIL import Image

RES = Path(__file__).resolve().parent / "android" / "app" / "src" / "main" / "res"
ICONS = Path(__file__).resolve().parent.parent / "static" / "m"

GLYPHS = {
    # 24x24 stroke paths
    "file": "M14,3H7a2,2 0,0 0,-2,2v14a2,2 0,0 0,2,2h10a2,2 0,0 0,2,-2V8z M14,3v5h5 M12,12v5 M9.5,14.5 12,12 14.5,14.5",
    "link": "M10,14a4.5,4.5 0,0 0,6.4,0l3,-3a4.5,4.5 0,0 0,-6.4,-6.4l-1.2,1.2 M14,10a4.5,4.5 0,0 0,-6.4,0l-3,3a4.5,4.5 0,0 0,6.4,6.4l1.2,-1.2",
    "history": "M3.5,12a8.5,8.5 0,1 0,2.5,-6 M3.5,4v4h4 M12,7.5V12l3,2",
}


def shortcut(name: str, path: str) -> str:
    # a dark round badge with the cyan glyph, sized like an adaptive shortcut icon
    return f"""<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="48dp" android:height="48dp" android:viewportWidth="48" android:viewportHeight="48">
    <path android:fillColor="#120D33" android:pathData="M24,0a24,24 0,1 1,0,48a24,24 0,1 1,0,-48z"/>
    <group android:translateX="12" android:translateY="12">
        <path android:strokeColor="#22E8FF" android:strokeWidth="1.9" android:strokeLineCap="round"
            android:strokeLineJoin="round" android:fillColor="#00000000" android:pathData="{path}"/>
    </group>
</vector>
"""


TILE = """<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp" android:height="24dp" android:viewportWidth="24" android:viewportHeight="24">
    <path android:strokeColor="#FFFFFFFF" android:strokeWidth="2" android:strokeLineCap="round"
        android:strokeLineJoin="round" android:fillColor="#00000000" android:pathData="{path}"/>
</vector>
"""

for name, path in GLYPHS.items():
    (RES / "drawable" / f"ic_sc_{name}.xml").write_text(shortcut(name, path), encoding="utf-8")
(RES / "drawable" / "ic_tile_link.xml").write_text(TILE.format(path=GLYPHS["link"]), encoding="utf-8")

# themed icon (Android 13+): the logo as a single-colour silhouette
bleed = Image.open(ICONS / "icon-maskable-512.png").convert("L")
mask = bleed.point(lambda v: 0 if v < 70 else 255)
for d, k in {"mdpi": 1, "hdpi": 1.5, "xhdpi": 2, "xxhdpi": 3, "xxxhdpi": 4}.items():
    s = round(108 * k)
    img = Image.new("RGBA", (s, s), (255, 255, 255, 0))
    img.putalpha(mask.resize((s, s), Image.LANCZOS))
    white = Image.new("RGBA", (s, s), (255, 255, 255, 255))
    white.putalpha(img.getchannel("A"))
    white.save(RES / f"mipmap-{d}" / "ic_launcher_monochrome.png")

for f in ("ic_launcher.xml", "ic_launcher_round.xml"):
    p = RES / "mipmap-anydpi-v26" / f
    s = p.read_text(encoding="utf-8")
    if "monochrome" not in s:
        s = s.replace("</adaptive-icon>", '    <monochrome android:drawable="@mipmap/ic_launcher_monochrome"/>\n</adaptive-icon>')
        p.write_text(s, encoding="utf-8")
print("drawables ok")
