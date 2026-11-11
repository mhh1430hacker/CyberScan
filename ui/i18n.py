"""Languages beyond English and Arabic for the scan-result texts.

English is the source; Arabic lives in ``ui.copy.AR``. Every other language is a
catalogue in ``ui/lang/<code>.json``: ``{"strings": {english: translation},
"counts": {key: {"one": ..., "other": ...}}}``, keyed by the exact English text
that ``ui.copy.tr`` receives. A string missing from a catalogue stays English.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

LANG_DIR = Path(__file__).resolve().parent / "lang"

# code -> own name; the website offers the same list (web_v/static/js/i18n.js).
LANGUAGES: dict[str, str] = {
    "en": "English", "ar": "العربية", "zh": "中文", "es": "Español", "hi": "हिन्दी", "fr": "Français",
    "bn": "বাংলা", "pt": "Português", "ru": "Русский", "ur": "اردو", "id": "Bahasa Indonesia",
    "de": "Deutsch", "ja": "日本語", "tr": "Türkçe", "vi": "Tiếng Việt", "ko": "한국어", "it": "Italiano",
    "fa": "فارسی", "pl": "Polski", "uk": "Українська", "nl": "Nederlands", "th": "ไทย", "sw": "Kiswahili",
    "ms": "Bahasa Melayu", "fil": "Filipino", "ta": "தமிழ்", "te": "తెలుగు", "mr": "मराठी",
    "gu": "ગુજરાતી", "pa": "ਪੰਜਾਬੀ",
}
RTL = frozenset({"ar", "fa", "ur"})


def supported(code: str | None) -> str | None:
    code = (code or "").strip().lower()
    return code if code in LANGUAGES else None


@lru_cache(maxsize=None)
def catalogue(code: str) -> dict:
    try:
        return json.loads((LANG_DIR / f"{code}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"strings": {}, "counts": {}}


def translate(text: str, code: str) -> str:
    return catalogue(code).get("strings", {}).get(text, text)


def count(key: str, number: int, code: str, english: tuple[str, str]) -> str:
    forms = catalogue(code).get("counts", {}).get(key) or {}
    if number == 1:
        return forms.get("one") or english[0]
    return (forms.get("other") or english[1]).format(n=number)
