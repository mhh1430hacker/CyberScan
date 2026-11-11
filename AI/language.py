"""Optional, honest language identification for local conversations."""
from __future__ import annotations

import importlib.util
import re
import threading
from dataclasses import dataclass
from functools import lru_cache


_ARABIC = re.compile(r"[\u0600-\u06ff\u0750-\u077f\u08a0-\u08ff]")
_LATIN = re.compile(r"[A-Za-z]")
_NON_TEXT = re.compile(r"^[\W\d_]+$", re.UNICODE)
_LANGDETECT_LOCK = threading.Lock()


@dataclass(frozen=True)
class LanguageResult:
    language: str
    confidence: float
    detector: str
    mixed_arabic_latin: bool
    status: str


@lru_cache(maxsize=1)
def supported_language_profiles() -> tuple[str, ...]:
    try:
        from langdetect.detector_factory import PROFILES_DIRECTORY
    except ImportError:
        return ()
    from pathlib import Path

    return tuple(sorted(path.name for path in Path(PROFILES_DIRECTORY).iterdir() if path.is_file()))


@lru_cache(maxsize=1)
def _factory_for_detection():
    from langdetect.detector_factory import DetectorFactory, PROFILES_DIRECTORY

    factory = DetectorFactory()
    factory.set_seed(0)
    factory.load_profile(PROFILES_DIRECTORY)
    return factory


def detect_language(text: str, *, minimum_confidence: float = 0.55) -> LanguageResult:
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if len(text) > 200_000:
        text = text[:200_000]
    arabic = bool(_ARABIC.search(text))
    latin = bool(_LATIN.search(text))
    mixed = arabic and latin
    if not text.strip() or _NON_TEXT.fullmatch(text.strip()):
        return LanguageResult("und", 0.0, "none", mixed, "insufficient_text")
    if importlib.util.find_spec("langdetect") is None:
        return LanguageResult("ar" if arabic and not latin else "und", 0.0, "unicode-script-fallback", mixed,
                              "partial_detector_unavailable")
    try:
        from langdetect.lang_detect_exception import LangDetectException

        with _LANGDETECT_LOCK:
            factory = _factory_for_detection()
            detector = factory.create()
            detector.append(text)
            candidates = detector.get_probabilities()
    except (LangDetectException, ValueError, TypeError, RuntimeError):
        return LanguageResult("und", 0.0, "langdetect", mixed, "detection_failed")
    if not candidates:
        return LanguageResult("und", 0.0, "langdetect", mixed, "detection_failed")
    winner = candidates[0]
    confidence = float(winner.prob)
    if confidence < minimum_confidence:
        return LanguageResult("und", confidence, "langdetect", mixed, "low_confidence")
    return LanguageResult(winner.lang, confidence, "langdetect", mixed, "detected")


def language_profiles_available() -> dict[str, object]:
    profiles = supported_language_profiles()
    return {
        "detector": "langdetect" if profiles else "unicode-script-fallback",
        "language_profile_count": len(profiles),
        "language_profiles": list(profiles),
        "generation_languages_certified": [],
        "status": "detection_profiles_available" if profiles else "limited_fallback_only",
    }


def supported_language_codes() -> tuple[str, ...]:
    """Return detector codes available in this runtime, not model guarantees."""
    return supported_language_profiles()
