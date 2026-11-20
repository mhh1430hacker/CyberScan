"""Bit's brain: a language model chooses the little robot's next move on the support page.

The page sends a short summary of the moment (where the pointer is relative to the support
button, how it moves, what it hovers, Bit's current feelings, what the last tactics achieved).
The model answers with one decision: mood, tactic, facial expression, an effect on the cursor and
an optional line to say. The page carries the decision out at 60 frames a second and falls back to
its own decision engine whenever the model is slow, rate-limited or unavailable.

Model: Amazon Bedrock (CYBERSCAN_BIT_MODEL, default Amazon Nova Micro: fast and cheap) on AWS,
or a local Ollama model when running on the user's computer. Every answer is validated against
fixed vocabularies; nothing the model writes reaches the page except a short, plain-text line.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any

import assistant

MODEL = os.environ.get("CYBERSCAN_BIT_MODEL", "deepseek.v3.2")
# tried in order until one answers; a model that refuses (no access) is skipped for an hour
MODELS = [m for m in dict.fromkeys([MODEL, "deepseek.v3.2", "deepseek.v3-v1:0", "eu.amazon.nova-micro-v1:0"]) if m]
_model_off: dict[str, float] = {}
MOODS = {"playful", "mischievous", "affectionate", "excited", "bored", "curious", "proud", "shy", "grumpy", "silly"}
TACTICS = {"follow", "orbit", "tug", "grab", "block", "beckon", "dance", "peek", "nap", "zoom", "hide", "spin"}
EXPRESSIONS = {"happy", "love", "laugh", "wink", "surprised", "angry", "sad", "dizzy", "sleepy", "smug", "curious", "starry", "cry_laugh", "neutral"}
CURSOR_FX = {"none", "trail", "shake", "shrink", "grow", "heart", "rubber", "ghosts", "magnet", "spin", "sparkle", "jelly"}

SYSTEM = (
    "You are the mind of Bit, a tiny, cute, mischievous flying robot on a developer's support page. "
    "Your goal: playfully (never rudely) get the visitor's pointer to the 'Support the developer' button, "
    "and be adorable and funny when they get close or press it. You decide ONE next move from the situation. "
    "Answer with JSON only, no prose: {\"mood\":..., \"tactic\":..., \"expression\":..., \"cursor_fx\":..., \"line\":...}. "
    f"mood one of {sorted(MOODS)}; tactic one of {sorted(TACTICS)}; expression one of {sorted(EXPRESSIONS)}; "
    f"cursor_fx one of {sorted(CURSOR_FX)}; line: at most 6 words in the visitor's language, or empty. "
    "Vary your choices; use the outcomes of past tactics to learn what works; be gentle when the visitor is close; "
    "celebrate if the support details are open; nap if the visitor has been still for long."
)

_lock = threading.Lock()
_calls: dict[str, list[float]] = {}
PER_VISITOR_INTERVAL = 4.5   # seconds between two decisions for one visitor
PER_VISITOR_HOUR = 90


def allowed(client: str) -> bool:
    now = time.time()
    with _lock:
        recent = [t for t in _calls.get(client, []) if now - t < 3600]
        if recent and now - recent[-1] < PER_VISITOR_INTERVAL or len(recent) >= PER_VISITOR_HOUR:
            _calls[client] = recent
            return False
        recent.append(now)
        _calls[client] = recent
        if len(_calls) > 5000:   # forget the oldest visitors
            for key in sorted(_calls, key=lambda k: _calls[k][-1])[:1000]:
                _calls.pop(key, None)
        return True


def _summary(state: dict[str, Any]) -> str:
    """The situation as a few plain facts (numbers rounded, strings bounded)."""
    def num(key: str, lo: float, hi: float) -> float:
        try:
            return round(max(lo, min(hi, float(state.get(key, 0)))), 2)
        except (TypeError, ValueError):
            return 0.0
    lang = "Arabic" if state.get("lang") == "ar" else "English"
    hover = str(state.get("hover", ""))[:12]
    outcomes = state.get("outcomes") if isinstance(state.get("outcomes"), dict) else {}
    learned = ", ".join(f"{k}:{round(float(v), 2)}" for k, v in list(outcomes.items())[:8] if k in TACTICS and isinstance(v, (int, float)))
    return (
        f"visitor language: {lang}; device: {'phone (tilt)' if state.get('touch') else 'computer'}; "
        f"pointer distance to support button: {num('dist', 0, 5000):.0f}px; trend: {str(state.get('trend', 'still'))[:10]}; "
        f"pointer speed: {num('speed', 0, 200)}; still for: {num('still', 0, 600)}s; hovering: {hover or 'nothing'}; "
        f"support details open: {bool(state.get('bankOpen'))}; seconds on page: {num('age', 0, 36000):.0f}; "
        f"Bit feels joy {num('joy', 0, 1)}, mischief {num('mischief', 0, 1)}, affection {num('affection', 0, 1)}, "
        f"boredom {num('boredom', 0, 1)}; last tactic: {str(state.get('tactic', ''))[:10]}; "
        f"learned value of tactics (higher = pointer got closer): {learned or 'none yet'}."
    )


def _parse(text: str) -> dict[str, Any] | None:
    match = re.search(r"\{.*\}", text or "", flags=re.DOTALL)
    if not match:
        return None
    try:
        raw = json.loads(match.group(0))
    except ValueError:
        return None
    pick = lambda key, allowed, default: raw.get(key) if raw.get(key) in allowed else default  # noqa: E731
    line = re.sub(r"[<>{}\[\]`\\]", "", str(raw.get("line", "")))[:40].strip()
    return {"mood": pick("mood", MOODS, "playful"), "tactic": pick("tactic", TACTICS, "follow"),
            "expression": pick("expression", EXPRESSIONS, "happy"), "cursor_fx": pick("cursor_fx", CURSOR_FX, "none"), "line": line}


def decide(state: dict[str, Any], *, local: bool, ollama_model: str = "qwen3:8b") -> dict[str, Any]:
    """One decision from a model, or {"source": "none"} so the page keeps its own engine."""
    prompt = [{"role": "user", "content": _summary(state)}]
    try:
        if assistant._bedrock_configured():
            from botocore.exceptions import ClientError
            response = None
            for model in MODELS:
                if _model_off.get(model, 0) > time.monotonic():
                    continue
                try:
                    response = assistant._bedrock().converse(
                        modelId=model, system=[{"text": SYSTEM}],
                        messages=[{"role": "user", "content": [{"text": prompt[0]["content"]}]}],
                        inferenceConfig={"maxTokens": 160, "temperature": 0.9})
                    break
                except ClientError as exc:
                    print(f"bit: {model} refused: {exc}", flush=True)   # visible in CloudWatch
                    _model_off[model] = time.monotonic() + (60 if "Throttl" in str(exc) else 3600)
            if response is None:
                return {"source": "none"}
            text = "".join(b.get("text", "") for b in response.get("output", {}).get("message", {}).get("content", []))
            decision = _parse(text)
            return {**decision, "source": "bedrock"} if decision else {"source": "none"}
        if local and assistant._ollama_ready(ollama_model):
            import urllib.request
            body = json.dumps({"model": ollama_model, "stream": False, "format": "json", "think": False,
                               "options": {"temperature": 0.9, "num_predict": 120},
                               "messages": [{"role": "system", "content": SYSTEM}, *prompt]}).encode()
            with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:11434/api/chat", data=body,
                                                               headers={"Content-Type": "application/json"}), timeout=8) as r:
                text = json.loads(r.read()).get("message", {}).get("content", "")
            decision = _parse(text)
            return {**decision, "source": "ollama"} if decision else {"source": "none"}
    except Exception:  # noqa: BLE001 - the page always has its own engine to fall back on
        return {"source": "none"}
    return {"source": "none"}
