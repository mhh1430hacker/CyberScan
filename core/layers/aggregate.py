"""Combine the layers' binary signals into one layered score (0-100), explained.

Formula (also returned in the result, so "Why this result?" can show it):

    For every layer that answered (signal 1 or 0; ``None`` is left out of BOTH sums) and that
    counts toward the threat score (privacy layers are reported separately):
        S = Σ w·c over layers that said 1 (suspicious)
        C = Σ w·c over layers that said 0 (clean)
        W = Σ w   over layers that answered
    log-odds  L = ln(p0 / (1 - p0)) + ln(4)·S − 3·C / W        with prior p0 = 0.10
    score     = round(100 · 1 / (1 + e^(−L)))

    w = the layer's reliability (0.2 weak hint .. 3.0 near-proof), c = its confidence (0..1).
    Each suspicious answer multiplies the odds by 4^(w·c); the clean answers pull the odds down by
    at most e^(−3), as a SHARE of the weight that answered, so adding more clean layers never
    drowns a strong signal and a single weak hint stays low.

Hard rules that already decide the verdict also hold here: a known-malware listing (offline
table, MalwareBazaar, VirusTotal 10+ engines, malware inside an archive) puts the layered score
at 99 or more; 5+ VirusTotal engines or an exact Safe Browsing / URLhaus listing at 85 or more.
"""
from __future__ import annotations

import math
from typing import Any

PRIOR = 0.10
SUSPICIOUS_FACTOR = math.log(4.0)
CLEAN_PULL = 3.0
HARD_FLOORS = {"known_malware": 99, "many_engines": 85, "listed_link": 85}

FORMULA = {
    "en": ("L = ln(0.10/0.90) + ln(4)·Σ(w·c of suspicious layers) − 3·Σ(w·c of clean layers)/Σ(w of answering layers); "
           "score = 100/(1+e^−L). Layers that don't apply or couldn't answer are left out of every sum; privacy layers "
           "are reported, not scored. Known-malware listings set the score to at least 99; 5+ VirusTotal engines or an "
           "exact Safe Browsing / URLhaus listing to at least 85."),
    "ar": ("L = ln(0.10/0.90) + ln(4)·مجموع(الوزن×الثقة للطبقات المشبوهة) − 3·مجموع(الوزن×الثقة للطبقات السليمة)/مجموع(أوزان الطبقات التي أجابت)؛ "
           "الدرجة = 100/(1+e^−L). الطبقات التي لا تنطبق أو لم تُجب لا تدخل أي مجموع؛ وطبقات الخصوصية تُعرض ولا تُحسب. "
           "إدراج الملف كبرمجية خبيثة معروفة يرفع الدرجة إلى 99 على الأقل، و5 محركات أو أكثر في VirusTotal أو إدراج دقيق في "
           "التصفح الآمن/URLhaus إلى 85 على الأقل."),
}


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


def aggregate(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """``entries``: the orchestrator's per-layer results (signal, confidence, weight, affects_score, hard, category)."""
    scored = [e for e in entries if e.get("signal") in (0, 1) and e.get("affects_score", True)]
    suspicious = [e for e in scored if e["signal"] == 1]
    clean = [e for e in scored if e["signal"] == 0]
    s_sum = sum(float(e["weight"]) * float(e["confidence"]) for e in suspicious)
    c_sum = sum(float(e["weight"]) * float(e["confidence"]) for e in clean)
    w_sum = sum(float(e["weight"]) for e in scored)
    log_odds = math.log(PRIOR / (1 - PRIOR)) + SUSPICIOUS_FACTOR * s_sum - (CLEAN_PULL * c_sum / w_sum if w_sum else 0.0)
    score: int | None = round(100 * _sigmoid(log_odds)) if scored else None
    hard = sorted({str(e["hard"]) for e in suspicious if e.get("hard") in HARD_FLOORS}, key=lambda h: -HARD_FLOORS[h])
    floor = HARD_FLOORS[hard[0]] if hard else None
    if floor is not None:
        score = max(score or 0, floor)
    privacy = [e for e in entries if e.get("signal") == 1 and not e.get("affects_score", True)]
    categories = sorted({e.get("category", "") for e in suspicious})
    applicable = [e for e in entries if e.get("status") != "not_applicable"]
    return {
        "score": score,
        "log_odds": round(log_odds, 3),
        "suspicious_weight": round(s_sum, 3),
        "clean_weight": round(c_sum, 3),
        "answer_weight": round(w_sum, 3),
        "weighted_share": round(s_sum / (s_sum + c_sum), 3) if (s_sum + c_sum) else None,
        "total": len(entries),
        "applicable": len(applicable),
        "answered": len([e for e in entries if e.get("signal") in (0, 1)]),
        "suspicious": len(suspicious),
        "clean": len([e for e in entries if e.get("signal") == 0]),
        "privacy_flags": len(privacy),
        "not_applicable": len([e for e in entries if e.get("status") == "not_applicable"]),
        "unavailable": len([e for e in entries if e.get("status") in {"unavailable", "timeout", "error"}]),
        "suspicious_categories": categories,
        "hard_rule": hard[0] if hard else None,
        "formula": FORMULA,
        "prior": PRIOR,
    }
