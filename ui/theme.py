"""Colour, type and the application stylesheet: the "Precision" system.

Drawn from what the best-regarded product interfaces share (Linear, Raycast,
Vercel, Apple): an achromatic near-black canvas with five steps of depth,
hairline borders made of white at low opacity instead of solid lines, one
type family set tightly at display sizes, medium weights for emphasis, and a
single accent kept for the primary action.

CyberScan adds two things of its own. Verdict colours (green, amber, red,
slate) appear only where a verdict is stated. A target's kind hue
(ui.file_kind) appears only as a thin signal line and its icon, so the colour
of what you scanned follows it without turning into decoration.

Every text token is measured against every surface: body text at least
4.5:1 (WCAG AA).
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QColor, QFont, QFontDatabase

TOKENS = {
    "bg": "#08090a",
    "rail": "#0b0c0d",
    "surface": "#0f1011",
    "surface_2": "#141517",
    "surface_3": "#191a1c",
    "raised": "#202124",
    "line": "#1b1c1f",
    "line_strong": "#27282c",
    "line_field": "#5a5e66",
    "text": "#f7f8f8",
    "text_dim": "#c9ced6",
    "text_mute": "#8f949c",
    "accent": "#5ee0d0",
    "accent_ink": "#03110f",
    "ok": "#4cc38a",
    "warn": "#f2b33d",
    "danger": "#f2595e",
    "info": "#7aa2ff",
    "neutral": "#8f949c",
    # translucent layers (stylesheet only)
    "glass": "rgba(255, 255, 255, 0.028)",
    "glass_quiet": "rgba(255, 255, 255, 0.018)",
    "glass_hover": "rgba(255, 255, 255, 0.05)",
    "glass_rail": "rgba(9, 10, 11, 0.86)",
    "glass_edge": "rgba(255, 255, 255, 0.07)",
    "glass_edge_top": "rgba(255, 255, 255, 0.11)",
    "glass_field": "rgba(255, 255, 255, 0.035)",
}

TONES = {
    "ok": TOKENS["ok"],
    "low": TOKENS["ok"],
    "success": TOKENS["ok"],
    "warn": TOKENS["warn"],
    "warning": TOKENS["warn"],
    "medium": TOKENS["warn"],
    "danger": TOKENS["danger"],
    "error": TOKENS["danger"],
    "high": TOKENS["danger"],
    "info": TOKENS["info"],
    "neutral": TOKENS["neutral"],
    "accent": TOKENS["accent"],
    "repair": "#a594ff",
}

# The primary-action colour of each mode: Scan (teal) and Repair (indigo).
MODE_ACCENTS = {
    "scan": {"accent": "#5ee0d0", "ink": "#03110f", "hover": "#7ee9dc", "top": "#8ff0e4", "bottom": "#3fbfb0",
             "strong": "#e6fffb", "ring": "rgba(94, 224, 208, 0.55)"},
    "repair": {"accent": "#a594ff", "ink": "#0c0820", "hover": "#b9acff", "top": "#d3cbff", "bottom": "#7b69e6",
               "strong": "#f1eeff", "ring": "rgba(165, 148, 255, 0.55)"},
}

FAMILIES = ["Inter", "IBM Plex Sans Arabic", "Segoe UI", "Tahoma"]
UI_FONT = '"Inter", "IBM Plex Sans Arabic", "Segoe UI", "Tahoma"'
DISPLAY_FONT = "Inter"
MONO_FONT = "Cascadia Mono"
FONT_DIR = Path(__file__).resolve().parent / "fonts"
_fonts_loaded = False


def load_fonts() -> None:
    """Register the bundled typefaces (Inter, IBM Plex Sans Arabic; both OFL)."""
    global _fonts_loaded
    if _fonts_loaded:
        return
    for path in sorted(FONT_DIR.glob("*.ttf")):
        QFontDatabase.addApplicationFont(str(path))
    _fonts_loaded = True


# Painted text follows the reader's text size too (set by ``stylesheet``),
# not only styled labels.
TEXT_SCALE = 1.0


def ui_font(pixels: float, weight: int = 400, tracking: float = 0.0) -> QFont:
    """The interface face for painted text: Inter, Arabic through IBM Plex."""
    font = QFont()
    font.setFamilies(FAMILIES)
    font.setPixelSize(max(1, round(pixels * TEXT_SCALE)))
    font.setWeight(QFont.Weight(weight))
    if tracking:
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, tracking)
    return font


def tone_color(tone: str) -> str:
    return TONES.get(tone, TOKENS["neutral"])


def mix(color_a: str | QColor, color_b: str | QColor, amount: float) -> QColor:
    """Blend ``color_a`` toward ``color_b`` by ``amount`` (0..1)."""
    a, b = QColor(color_a), QColor(color_b)
    amount = max(0.0, min(1.0, amount))
    return QColor(
        round(a.red() + (b.red() - a.red()) * amount),
        round(a.green() + (b.green() - a.green()) * amount),
        round(a.blue() + (b.blue() - a.blue()) * amount),
        round(a.alpha() + (b.alpha() - a.alpha()) * amount),
    )


def alpha(color: str | QColor, value: float) -> QColor:
    result = QColor(color)
    result.setAlphaF(max(0.0, min(1.0, value)))
    return result


def stylesheet(scale: float = 1.0, language: str = "en", mode: str = "scan") -> str:
    global TEXT_SCALE
    t = TOKENS
    p = MODE_ACCENTS.get(mode, MODE_ACCENTS["scan"])
    arabic = language == "ar"
    # Arabic letters sit smaller than Latin ones at the same pixel size.
    script = 1.08 if arabic else 1.0
    TEXT_SCALE = scale

    def px(value: float) -> str:
        return f"{round(value * scale * script)}px"

    def track(value: str) -> str:
        # Letter spacing breaks Arabic's joined script; it is Latin-only.
        return "0px" if arabic else value

    from ui.icons import glyph_file

    check = glyph_file("check", p["ink"], 14)
    return f"""
QMainWindow {{ background: {t['bg']}; }}
QWidget {{ color: {t['text']}; font-family: {UI_FONT}; font-size: {px(14)}; }}
QWidget#main, QWidget#stage, QWidget#page, QScrollArea, QScrollArea > QWidget > QWidget {{
    background: transparent; border: 0;
}}
QToolTip {{ background: {t['raised']}; color: {t['text']}; border: 1px solid {t['glass_edge_top']}; padding: 6px 9px; border-radius: 6px; }}

/* ---- type ---- */
QLabel#display {{ font-size: {px(46)}; font-weight: 600; letter-spacing: {track('-1.3px')}; color: {t['text']}; }}
QLabel#headline {{ font-size: {px(30)}; font-weight: 600; letter-spacing: {track('-0.7px')}; }}
QLabel#title {{ font-size: {px(17)}; font-weight: 600; letter-spacing: {track('-0.2px')}; }}
QLabel#section {{ font-size: {px(14)}; font-weight: 600; color: {t['text']}; }}
QLabel#lead {{ font-size: {px(16)}; color: {t['text_dim']}; }}
QLabel#body {{ font-size: {px(14)}; color: {t['text_dim']}; }}
QLabel#mute {{ font-size: {px(13)}; color: {t['text_mute']}; }}
QLabel#eyebrow {{ font-size: {px(11)}; font-weight: 600; letter-spacing: {track('0.7px')}; color: {t['text_mute']}; }}
QLabel#mono, QPlainTextEdit#mono {{ font-family: "{MONO_FONT}", "Consolas", monospace; font-size: {px(12)}; color: {t['text_dim']}; }}
QLabel#error {{ color: {t['danger']}; font-size: {px(13)}; }}
QLabel#brand {{ font-family: "{'Reem Kufi' if arabic else 'Space Grotesk'}"; font-size: {round(20 * scale)}px; font-weight: 600; letter-spacing: {track('-0.4px')}; }}
QLabel#brandTag {{ font-size: {px(10)}; font-weight: 600; letter-spacing: {track('1.2px')}; color: {t['text_mute']}; }}
QLabel#key {{
    font-size: {px(11)}; font-weight: 600; color: {t['text_dim']};
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1d1e21, stop:1 #141517);
    border: 1px solid {t['glass_edge_top']}; border-bottom-color: rgba(0, 0, 0, 0.6);
    border-radius: 5px; padding: 1px 6px; min-width: 10px;
}}
QLabel#chip {{
    font-size: {px(12)}; font-weight: 500; color: {t['text_dim']}; background: {t['glass_field']};
    border: 1px solid {t['glass_edge']}; border-radius: 11px; padding: 3px 10px;
}}

/* ---- surfaces ---- */
QFrame#card {{
    background: {t['glass']}; border: 1px solid {t['glass_edge']};
    border-top-color: {t['glass_edge_top']}; border-radius: 14px;
}}
QFrame#cardQuiet {{ background: transparent; border: 0; border-bottom: 1px solid {t['glass_edge']}; border-radius: 0; }}
QFrame#command {{
    background: rgba(20, 21, 23, 0.92); border: 1px solid {t['glass_edge_top']};
    border-radius: 14px;
}}
QFrame#command[focused="true"] {{ border: 1px solid {p['ring']}; }}
QFrame#command[invalid="true"] {{ border: 1px solid {t['danger']}; }}
QFrame#segmentBar {{ background: rgba(255, 255, 255, 0.035); border: 1px solid {t['glass_edge']}; border-radius: 10px; }}
QPushButton#segment {{ background: transparent; border: 1px solid transparent; border-radius: 7px; padding: 5px 16px; color: {t['text_mute']}; font-weight: 500; min-height: 0; }}
QPushButton#segment:hover {{ color: {t['text']}; }}
QPushButton#segment:checked {{ background: {alpha(p['accent'], 0.16).name(QColor.NameFormat.HexArgb)}; color: {p['strong']}; border-color: {alpha(p['accent'], 0.45).name(QColor.NameFormat.HexArgb)}; }}
QPushButton#segment:focus {{ border: 1px solid {p['accent']}; }}
QPushButton#segment:disabled {{ color: {t['line_field']}; }}
QFrame#topbar {{ background: transparent; border-bottom: 1px solid {t['glass_edge']}; }}

/* ---- buttons ---- */
QPushButton {{
    background: rgba(255, 255, 255, 0.035); color: {t['text']};
    border: 1px solid {t['glass_edge']}; border-top-color: {t['glass_edge_top']};
    border-radius: 8px; padding: 7px 14px; min-height: {px(20)}; font-weight: 500;
}}
QPushButton:hover {{ background: rgba(255, 255, 255, 0.07); }}
QPushButton:pressed {{ background: rgba(255, 255, 255, 0.10); }}
QPushButton:focus {{ border: 1px solid {p['accent']}; }}
QPushButton:disabled {{ color: {t['text_mute']}; background: transparent; }}
QPushButton#primary {{
    background: {p['accent']}; color: {p['ink']}; border: 1px solid {p['top']};
    border-bottom-color: {p['bottom']}; padding: 7px 16px; font-weight: 600;
}}
QPushButton#primary:hover {{ background: {p['hover']}; }}
QPushButton#primary:focus {{ border: 2px solid {p['strong']}; }}
QPushButton#primary:disabled {{ background: {t['surface_3']}; color: {t['text_mute']}; border-color: {t['glass_edge']}; }}
QPushButton#danger {{
    background: {alpha(t['danger'], 0.14).name(QColor.NameFormat.HexArgb)}; color: #ffd7d8;
    border: 1px solid {alpha(t['danger'], 0.55).name(QColor.NameFormat.HexArgb)}; padding: 7px 14px; font-weight: 600;
}}
QPushButton#danger:hover {{ background: {alpha(t['danger'], 0.24).name(QColor.NameFormat.HexArgb)}; }}
QPushButton#danger:focus {{ border: 2px solid {t['danger']}; }}
QFrame#notice {{
    background: {alpha(t['danger'], 0.10).name(QColor.NameFormat.HexArgb)};
    border: 1px solid {alpha(t['danger'], 0.40).name(QColor.NameFormat.HexArgb)}; border-radius: 10px;
}}
QFrame#notice[tone="warn"] {{
    background: {alpha(t['warn'], 0.10).name(QColor.NameFormat.HexArgb)};
    border: 1px solid {alpha(t['warn'], 0.40).name(QColor.NameFormat.HexArgb)};
}}
QLabel#noticeText {{ color: {t['text']}; font-size: {px(14)}; font-weight: 600; }}
QPushButton#ghost {{ background: transparent; border: 1px solid transparent; color: {t['text_dim']}; padding: 6px 10px; }}
QPushButton#ghost:hover {{ background: {t['glass_hover']}; color: {t['text']}; }}
QPushButton#ghost:focus {{ border: 1px solid {p['accent']}; }}
QPushButton#link {{ background: transparent; border: 0; color: {p['accent']}; padding: 4px 2px; font-weight: 500; }}
QPushButton#link:hover {{ color: {p['hover']}; }}
QPushButton#link:focus {{ border: 1px solid {p['accent']}; border-radius: 4px; }}
QPushButton#icon {{ background: transparent; border: 1px solid transparent; border-radius: 8px; padding: 6px; min-height: 0; }}
QPushButton#icon:hover {{ background: {t['glass_hover']}; border-color: {t['glass_edge']}; }}
QPushButton#icon:focus {{ border: 1px solid {p['accent']}; }}

/* ---- fields ---- */
QLineEdit {{
    background: {t['glass_field']}; border: 1px solid {t['glass_edge_top']}; border-radius: 8px;
    padding: 8px 12px; selection-background-color: {p['accent']}; selection-color: {p['ink']};
}}
QLineEdit:focus {{ border: 1px solid {p['accent']}; }}
QLineEdit#target {{ background: transparent; border: 0; font-size: {px(17)}; padding: 6px 4px; }}
QLineEdit#search {{ border-radius: 8px; padding: 7px 10px; }}
QPlainTextEdit {{
    background: rgba(0, 0, 0, 0.35); border: 1px solid {t['glass_edge']}; border-radius: 10px; padding: 10px;
    selection-background-color: {p['accent']}; selection-color: {p['ink']};
}}
QCheckBox {{ spacing: 10px; color: {t['text']}; }}
QCheckBox::indicator {{ width: 18px; height: 18px; border-radius: 5px; border: 1px solid {t['line_field']}; background: rgba(255,255,255,0.03); }}
QCheckBox::indicator:checked {{ background: {p['accent']}; border-color: {p['accent']}; image: url({check}); }}
QCheckBox:focus {{ color: {p['accent']}; }}

/* ---- tabs ---- */
QTabWidget::pane {{ border: 0; }}
QTabBar::tab {{
    background: transparent; color: {t['text_mute']}; padding: 6px 12px; margin-right: 2px;
    border: 1px solid transparent; border-radius: 7px; font-weight: 500;
}}
QTabBar::tab:selected {{ background: {t['glass_hover']}; color: {t['text']}; border-color: {t['glass_edge']}; }}
QTabBar::tab:hover {{ color: {t['text']}; }}

/* ---- scrollbars ---- */
QScrollBar:vertical {{ background: transparent; width: 9px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: rgba(255,255,255,0.10); border-radius: 4px; min-height: 36px; }}
QScrollBar::handle:vertical:hover {{ background: rgba(255,255,255,0.18); }}
QScrollBar:horizontal {{ background: transparent; height: 9px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: rgba(255,255,255,0.10); border-radius: 4px; min-width: 36px; }}
QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{ background: none; border: 0; width: 0; height: 0; }}

QMessageBox, QDialog {{ background: {t['surface_2']}; }}
QMenu {{ background: {t['surface_3']}; border: 1px solid {t['glass_edge_top']}; border-radius: 10px; padding: 5px; }}
QMenu::item {{ padding: 7px 16px; border-radius: 6px; }}
QMenu::item:selected {{ background: {t['glass_hover']}; }}
QMenu::separator {{ height: 1px; background: {t['glass_edge']}; margin: 4px 8px; }}
"""
