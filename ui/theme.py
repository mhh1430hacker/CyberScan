"""Colour, type and the application stylesheet.

One dark family with four steps of elevation. Saturated colour is reserved
for two things only: the verdict (green, amber, red, slate) and the target's
kind hue (see ui.file_kind). Everything else stays quiet so the eye lands on
the verdict first. Text tokens are measured against every surface: body text
is at least 4.5:1 (WCAG AA) and field borders at least 3:1.
"""
from __future__ import annotations

from PySide6.QtGui import QColor

TOKENS = {
    "bg": "#070b12",
    "rail": "#0a101b",
    "surface": "#0d1424",
    "surface_2": "#111a2c",
    "surface_3": "#172235",
    "raised": "#1c2840",
    "line": "#1d2a3e",
    "line_strong": "#2a3a52",
    "line_field": "#5b6f8c",
    "text": "#eef2f8",
    "text_dim": "#a8b6c8",
    "text_mute": "#8796ab",
    "accent": "#5ee0d0",
    "accent_ink": "#04110f",
    "ok": "#4ade80",
    "warn": "#fbbf24",
    "danger": "#f87171",
    "info": "#7cb0ff",
    "neutral": "#94a3b8",
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
}

UI_FONT = '"Segoe UI Variable Text", "Segoe UI", "Noto Sans Arabic", "Tahoma"'
DISPLAY_FONT = "Segoe UI Variable Display"
MONO_FONT = "Cascadia Mono"


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


def stylesheet(scale: float = 1.0, language: str = "en") -> str:
    t = TOKENS
    # Letter spacing breaks the joined script of Arabic; spaced caps are Latin-only.
    spacing = (lambda value: "0px") if language == "ar" else (lambda value: value)

    def px(value: float) -> str:
        return f"{round(value * scale)}px"

    from ui.icons import glyph_file

    check = glyph_file("check", t["accent_ink"], 14)

    return f"""
QMainWindow, QWidget#root {{ background: {t['bg']}; }}
QWidget {{ color: {t['text']}; font-family: {UI_FONT}; font-size: {px(14)}; }}
QWidget#main, QWidget#stage, QWidget#page, QScrollArea, QScrollArea > QWidget > QWidget {{
    background: transparent; border: 0;
}}
QToolTip {{ background: {t['raised']}; color: {t['text']}; border: 1px solid {t['line_strong']}; padding: 6px 9px; }}

/* ---- text roles ---- */
QLabel#display {{ font-family: "{DISPLAY_FONT}", {UI_FONT}; font-size: {px(40)}; font-weight: 700; }}
QLabel#headline {{ font-family: "{DISPLAY_FONT}", {UI_FONT}; font-size: {px(32)}; font-weight: 700; }}
QLabel#title {{ font-size: {px(18)}; font-weight: 650; }}
QLabel#section {{ font-size: {px(15)}; font-weight: 650; color: {t['text']}; }}
QLabel#lead {{ font-size: {px(17)}; color: {t['text_dim']}; }}
QLabel#body {{ color: {t['text_dim']}; }}
QLabel#mute {{ color: {t['text_mute']}; font-size: {px(13)}; }}
QLabel#eyebrow {{ color: {t['text_mute']}; font-size: {px(11)}; font-weight: 700; letter-spacing: {spacing('1.4px')}; }}
QLabel#mono, QPlainTextEdit#mono {{ font-family: "{MONO_FONT}", "Consolas", monospace; font-size: {px(12)}; color: {t['text_dim']}; }}
QLabel#error {{ color: {t['danger']}; }}
QLabel#brand {{ font-size: {px(13)}; font-weight: 800; letter-spacing: 2.6px; }}
QLabel#brandTag {{ font-size: {px(10)}; font-weight: 700; letter-spacing: {spacing('1.6px')}; color: {t['accent']}; }}

/* ---- cards ---- */
QFrame#card {{ background: {t['surface']}; border: 1px solid {t['line']}; border-radius: 16px; }}
QFrame#cardQuiet {{ background: {t['surface_2']}; border: 1px solid {t['line']}; border-radius: 12px; }}
QFrame#topbar {{ background: transparent; }}

/* ---- buttons ---- */
QPushButton {{
    background: {t['surface_2']}; color: {t['text']};
    border: 1px solid {t['line_strong']}; border-radius: 10px;
    padding: 8px 16px; min-height: {px(22)}; font-weight: 600;
}}
QPushButton:hover {{ background: {t['surface_3']}; border-color: {t['line_field']}; }}
QPushButton:pressed {{ background: {t['raised']}; }}
QPushButton:focus {{ border: 2px solid {t['accent']}; }}
QPushButton:disabled {{ color: {t['text_mute']}; background: {t['surface']}; border-color: {t['line']}; }}
QPushButton#primary {{
    background: {t['accent']}; color: {t['accent_ink']}; border: 1px solid {t['accent']};
    padding: 10px 22px; font-size: {px(15)}; font-weight: 700;
}}
QPushButton#primary:hover {{ background: #7debdf; }}
QPushButton#primary:focus {{ border: 2px solid #e6fffb; }}
QPushButton#primary:disabled {{ background: {t['surface_3']}; color: {t['text_mute']}; border-color: {t['line']}; }}
QPushButton#ghost {{ background: transparent; border: 1px solid transparent; color: {t['text_dim']}; padding: 6px 10px; }}
QPushButton#ghost:hover {{ background: {t['surface_2']}; color: {t['text']}; }}
QPushButton#ghost:focus {{ border: 2px solid {t['accent']}; }}
QPushButton#link {{ background: transparent; border: 0; color: {t['accent']}; padding: 4px 2px; font-weight: 600; }}
QPushButton#link:hover {{ color: #9ff3ea; }}
QPushButton#link:focus {{ border: 1px solid {t['accent']}; border-radius: 4px; }}
QPushButton#icon {{ background: transparent; border: 1px solid transparent; border-radius: 10px; padding: 6px; min-height: 0; }}
QPushButton#icon:hover {{ background: {t['surface_2']}; border-color: {t['line_strong']}; }}
QPushButton#icon:focus {{ border: 2px solid {t['accent']}; }}

/* ---- fields ---- */
QLineEdit {{
    background: {t['surface_2']}; border: 1px solid {t['line_field']}; border-radius: 12px;
    padding: 10px 14px; selection-background-color: {t['accent']}; selection-color: {t['accent_ink']};
}}
QLineEdit:focus {{ border: 2px solid {t['accent']}; }}
QLineEdit#target {{ font-size: {px(15)}; padding: 13px 16px; border-radius: 14px; background: {t['bg']}; }}
QLineEdit#target[invalid="true"] {{ border: 2px solid {t['danger']}; }}
QLineEdit#search {{ border-radius: 18px; padding: 8px 14px; background: {t['surface']}; border-color: {t['line_strong']}; }}
QLineEdit#search:focus {{ border: 2px solid {t['accent']}; }}
QPlainTextEdit {{
    background: {t['bg']}; border: 1px solid {t['line']}; border-radius: 12px; padding: 10px;
    selection-background-color: {t['accent']}; selection-color: {t['accent_ink']};
}}
QCheckBox {{ spacing: 10px; color: {t['text']}; }}
QCheckBox::indicator {{ width: 20px; height: 20px; border-radius: 6px; border: 2px solid {t['line_field']}; background: {t['bg']}; }}
QCheckBox::indicator:checked {{ background: {t['accent']}; border-color: {t['accent']}; image: url({check}); }}
QCheckBox:focus {{ color: {t['accent']}; }}

/* ---- tabs (advanced data) ---- */
QTabWidget::pane {{ border: 0; }}
QTabBar::tab {{
    background: transparent; color: {t['text_mute']}; padding: 8px 14px; margin-right: 4px;
    border: 1px solid transparent; border-radius: 9px; font-weight: 600;
}}
QTabBar::tab:selected {{ background: {t['surface_3']}; color: {t['text']}; border-color: {t['line_strong']}; }}
QTabBar::tab:hover {{ color: {t['text']}; }}

/* ---- scrollbars ---- */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {t['line_strong']}; border-radius: 4px; min-height: 36px; }}
QScrollBar::handle:vertical:hover {{ background: {t['line_field']}; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {t['line_strong']}; border-radius: 4px; min-width: 36px; }}
QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{ background: none; border: 0; width: 0; height: 0; }}

QMessageBox, QDialog {{ background: {t['surface']}; }}
QMenu {{ background: {t['raised']}; border: 1px solid {t['line_strong']}; border-radius: 10px; padding: 6px; }}
QMenu::item {{ padding: 8px 18px; border-radius: 6px; }}
QMenu::item:selected {{ background: {t['surface_3']}; }}
"""
