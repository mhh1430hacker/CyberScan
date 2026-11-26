"""Layer, registry and result helpers for the layered analysis (see ``core.layers``).

A layer checks ONE aspect of the input and answers with a binary signal:

* ``1``    the aspect looks suspicious (or, for privacy layers, something is exposed);
* ``0``    the check ran and found nothing;
* ``None`` the layer does not apply to this input, or its source was unavailable.

``weight`` is the layer's reliability (how much one of its answers should count, 0.2..3.0) and
``confidence`` (0..1) how sure this particular answer is. Both feed ``core.layers.aggregate``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

# category id -> (English, Arabic); the order is the order shown in the grid
CATEGORIES: dict[str, tuple[str, str]] = {
    "structure": ("File structure", "بنية الملف"),
    "entropy": ("Randomness", "العشوائية"),
    "code": ("Program code", "شيفرة البرنامج"),
    "documents": ("Documents", "المستندات"),
    "archives": ("Archives and apps", "الأرشيفات والتطبيقات"),
    "content": ("Scripts and commands", "السكربتات والأوامر"),
    "web": ("Web pages", "صفحات الويب"),
    "links": ("Links", "الروابط"),
    "email": ("Email", "البريد الإلكتروني"),
    "reputation": ("Reputation and external services", "السمعة والخدمات الخارجية"),
    "yara": ("Known-pattern rules (YARA)", "قواعد الأنماط المعروفة (YARA)"),
    "ml": ("Machine learning", "تعلّم الآلة"),
    "privacy": ("Secrets and privacy", "الأسرار والخصوصية"),
}

STATUS_WORDS = {
    "suspicious": ("Suspicious", "مشبوه"),
    "clean": ("Nothing found", "لم يُعثر على شيء"),
    "not_applicable": ("Does not apply", "لا ينطبق"),
    "unavailable": ("Not available", "غير متاح"),
    "timeout": ("Timed out", "انتهى الوقت"),
    "error": ("Could not run", "تعذّر التشغيل"),
}


@dataclass(frozen=True)
class Layer:
    id: str
    name_en: str
    name_ar: str
    category: str
    checks_en: str             # what the layer checks, one short sentence
    checks_ar: str
    weight: float              # reliability, 0.2 (weak hint) .. 3.0 (near-proof)
    applies: Callable[[dict[str, Any]], bool]
    run: Callable[[Any], dict[str, Any]]
    source: str                # the engine module / service the answer comes from
    affects_score: bool = True  # privacy layers are reported, never scored as a threat
    online: bool = False        # reads an online service's answer (already fetched by the scan)
    tags: tuple[str, ...] = field(default_factory=tuple)

    def applies_to(self, facts: dict[str, Any]) -> bool:
        try:
            return bool(self.applies(facts))
        except Exception:  # noqa: BLE001 - a broken predicate means "doesn't apply", never a crash
            return False

    def describe(self) -> dict[str, Any]:
        cat = CATEGORIES.get(self.category, (self.category, self.category))
        return {"id": self.id, "name": {"en": self.name_en, "ar": self.name_ar}, "category": self.category,
                "category_name": {"en": cat[0], "ar": cat[1]}, "checks": {"en": self.checks_en, "ar": self.checks_ar},
                "weight": self.weight, "source": self.source, "affects_score": self.affects_score, "online": self.online}


REGISTRY: list[Layer] = []
_IDS: set[str] = set()


def register(layer: Layer) -> Layer:
    if layer.id in _IDS:
        raise ValueError(f"duplicate layer id {layer.id!r}")
    if layer.category not in CATEGORIES:
        raise ValueError(f"unknown category {layer.category!r} for layer {layer.id!r}")
    if not 0.1 <= layer.weight <= 3.0:
        raise ValueError(f"weight out of range for layer {layer.id!r}")
    _IDS.add(layer.id)
    REGISTRY.append(layer)
    return layer


def layer(id: str, name_en: str, name_ar: str, category: str, checks_en: str, checks_ar: str, *, weight: float,
          applies: Callable[[dict[str, Any]], bool], source: str, affects_score: bool = True, online: bool = False):
    """Decorator: ``@layer(...)`` over ``def run(ctx) -> dict``."""
    def wrap(run: Callable[[Any], dict[str, Any]]) -> Callable[[Any], dict[str, Any]]:
        register(Layer(id, name_en, name_ar, category, checks_en, checks_ar, weight, applies, run, source,
                       affects_score=affects_score, online=online))
        return run
    return wrap


# ------------------------------------------------------------------ answers
def _detail(en: str, ar: str) -> dict[str, str]:
    return {"en": str(en)[:220], "ar": str(ar)[:220]}


def hit(confidence: float, en: str, ar: str, **extra: Any) -> dict[str, Any]:
    """Signal 1: suspicious (privacy layers: something is exposed)."""
    return {"signal": 1, "confidence": confidence, "detail": _detail(en, ar), **extra}


def clean(confidence: float, en: str = "Nothing found.", ar: str = "لم يُعثر على شيء.", **extra: Any) -> dict[str, Any]:
    """Signal 0: the check ran and found nothing."""
    return {"signal": 0, "confidence": confidence, "detail": _detail(en, ar), **extra}


def unavailable(en: str = "The source of this check was not available.", ar: str = "مصدر هذا الفحص غير متاح.",
                status: str = "unavailable") -> dict[str, Any]:
    """Signal None: the layer applies but could not answer (no key, offline, timed out, no data)."""
    return {"signal": None, "confidence": 0.0, "detail": _detail(en, ar), "status": status}


def found_labels(labels: list[str]) -> str:
    """Short, language-neutral list of what matched (engine labels are English identifiers)."""
    shown = list(dict.fromkeys(labels))[:3]
    more = len(set(labels)) - len(shown)
    return "; ".join(shown) + (f" (+{more})" if more > 0 else "")
