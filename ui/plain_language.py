"""Three reading levels for one scan result.

* Level 1, the summary: a headline, one sentence, what to do next, a simple
  three-step meter and three facts. Written so anyone can read it.
* Level 2, the details: what caught our attention, where, what was checked
  and facts about the file, in plain words and in short sections.
* Level 3, the advanced data: the engine's own output, unchanged.

Everything is derived from ``ui.result_view.ResultView`` (itself read from the
engine's ScanResult). No rule here changes a verdict, a score or a finding;
it only chooses words for them. Text is produced in the requested language
through ``ui.copy``; engine text (finding titles and explanations) is passed
through untouched because the engine produces it in English only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ui.copy import count_phrase, tr
from ui.file_kind import FileKind
from ui.result_view import SEVERITY_RANK, ResultView

# --- level 1 ---------------------------------------------------------------

HEADLINES = {
    "high": (
        "Be careful with this one",
        "We found strong warning signs.",
        "Don't open it, and don't send it to anyone.",
    ),
    "review": (
        "Take a second look",
        "We found a few things worth checking.",
        "Open it only if you know and trust where it came from.",
    ),
    "low": (
        "Nothing worrying found",
        "Our checks didn't spot any warning signs.",
        "If you trust where it came from, carry on with your usual care.",
    ),
    "inconclusive": (
        "We couldn't be sure",
        "Part of the check didn't finish, so this result can't be relied on.",
        "Scan it again, and don't rely on this result.",
    ),
}
UNRECOGNIZED = (
    "We couldn't be sure",
    "The engine gave an answer this screen doesn't recognise.",
    "Look at the advanced data, or scan it again.",
)
NOT_A_GUARANTEE = "This isn't a guarantee that it's safe."
METER_LEVEL = {"low": 1, "review": 2, "high": 3}

# --- level 2 ---------------------------------------------------------------

SEVERITY_WORDS = {
    "high": "Serious",
    "medium": "Moderate",
    "low": "Minor",
    "info": "Note",
    "unknown": "Unrated",
}
CATEGORY_WORDS = {
    "structural": "How the file is built",
    "statistical": "How random the content is",
    "heuristic": "Warning signs",
    "text": "Clues in the text",
    "url": "Clues in the link",
    "pe": "Parts of the program",
    "yara": "Known patterns",
    "archive": "What's inside the archive",
    "test_marker": "Test marker",
    "osint": "Online reports",
}
ENGINE_WORDS = {
    "YARA": "Known-pattern rules",
    "PE": "Program structure",
    "ML": "Learning model",
    "Archive": "Archive contents",
    "OSINT": "Online lookups",
    "Heuristics": "Warning-sign rules",
}
CHECK_WORDS = {
    "ran": ("✓", "Checked", "ok"),
    "not_applicable": ("–", "Doesn't apply here", "neutral"),
    "disabled": ("○", "Turned off in your settings", "neutral"),
    "unavailable": ("!", "Not available right now", "warn"),
    "partial": ("◐", "Only partly checked", "warn"),
    "failed": ("✕", "Couldn't run", "danger"),
    "unknown": ("?", "Status unknown", "neutral"),
}
SEVERITY_TONE = {"high": "danger", "medium": "warn", "low": "info", "info": "neutral", "unknown": "neutral"}
_KEEP_WHOLE = ("PowerShell", "JavaScript", "VBScript", "WScript", "ActiveX", "AutoRun", "AutoOpen")
_WORD = re.compile("|".join(_KEEP_WHOLE) + r"|[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z0-9]+")


@dataclass(frozen=True)
class Summary:
    key: str
    tone: str
    symbol: str
    headline: str
    sentence: str
    advice: str
    limit: str  # "" unless the result could be misread as a guarantee
    meter: int | None  # 1..3, or None when the level is unknown
    facts: tuple[str, ...]


@dataclass(frozen=True)
class PlainFinding:
    severity: str
    tone: str
    word: str
    title: str
    body: str
    where: str
    count: int = 1  # identical findings are shown once, with how many there were


@dataclass(frozen=True)
class PlainCheck:
    name: str
    symbol: str
    state: str
    tone: str
    raw: str
    reason: str = ""


@dataclass(frozen=True)
class Details:
    findings: tuple[PlainFinding, ...]
    places: tuple[tuple[str, int, str], ...]  # (label, count, tone)
    checks: tuple[PlainCheck, ...]
    facts: tuple[tuple[str, str], ...]  # (label, value)
    score_line: str


def humanize_title(title: str) -> str:
    """``EncodedPowerShell`` -> ``Encoded PowerShell``; ``ANTI_DISASSEMBLY_GAP`` -> ``Anti disassembly gap``.

    Only identifier-shaped titles are touched; sentences pass through unchanged.
    """
    text = title.strip()
    if not text or " " in text:
        return text
    if "_" in text:
        words = [word for word in text.split("_") if word]
        joined = " ".join(words)
        return joined.capitalize() if text.isupper() else joined
    words = re.findall(_WORD, text)
    return " ".join(words) if "".join(words) == text else text


def isolate(text: str, language: str) -> str:
    """Keep a left-to-right run (a size, a number pair) in order inside Arabic."""
    return f"⁨{text}⁩" if language == "ar" and text else text


def format_size(size: int | None) -> str:
    if size is None:
        return ""
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def summary(view: ResultView, kind: FileKind, elapsed: float | None, language: str) -> Summary:
    verdict = view.verdict
    headline, sentence, advice = (
        HEADLINES.get(verdict.key, UNRECOGNIZED)
        if view.classification in {"SUSPICIOUS", "REVIEW", "NO_INDICATORS_OBSERVED"}
        else UNRECOGNIZED
    )
    count = len(view.findings)
    facts = [
        count_phrase("finding", count, language)
        if count
        else tr("No warning signs found", language),
    ]
    kind_line = tr(kind.label, language)
    if view.file_size is not None:
        kind_line = f"{kind_line} · {isolate(format_size(view.file_size), language)}"
    facts.append(kind_line)
    if elapsed is not None:
        facts.append(tr("Checked in {seconds} s", language).format(seconds=f"{elapsed:.1f}"))
    return Summary(
        key=verdict.key,
        tone=verdict.tone,
        symbol=verdict.symbol,
        headline=tr(headline, language),
        sentence=tr(sentence, language),
        advice=tr(advice, language),
        limit=tr(NOT_A_GUARANTEE, language) if verdict.key == "low" else "",
        meter=METER_LEVEL.get(verdict.key) if verdict.key != "inconclusive" else None,
        facts=tuple(facts),
    )


def details(view: ResultView, kind: FileKind, language: str, reasons: dict[str, str] | None = None) -> Details:
    """Level 2. ``reasons`` maps an engine name to an English sentence saying
    why it ran the way it did; it is translated here."""
    from ui.finding_text import plain

    reasons = reasons or {}
    grouped: dict[tuple[str, str], list] = {}
    for item in sorted(view.findings, key=lambda item: (-SEVERITY_RANK[item.severity], -item.contribution)):
        text = plain(item.title, item.explanation, language)
        grouped.setdefault((text.title, item.severity), []).append((item, text))
    findings = tuple(
        PlainFinding(
            severity=item.severity,
            tone=SEVERITY_TONE[item.severity],
            word=tr(SEVERITY_WORDS[item.severity], language),
            title=text.title,
            body=text.body,
            where=tr(CATEGORY_WORDS.get(item.category, "Other"), language),
            count=len(members),
        )
        for members in grouped.values()
        for item, text in members[:1]
    )
    places = tuple(
        (
            tr(CATEGORY_WORDS.get(entry.category, "Other"), language),
            entry.count,
            SEVERITY_TONE[entry.top_severity],
        )
        for entry in view.categories
    )
    checks = tuple(
        PlainCheck(
            name=tr(ENGINE_WORDS.get(engine.name, engine.name), language),
            symbol=CHECK_WORDS[engine.state][0],
            state=tr(CHECK_WORDS[engine.state][1], language),
            tone=CHECK_WORDS[engine.state][2],
            raw=engine.status,
            reason=tr(reasons[engine.name], language) if reasons.get(engine.name) else "",
        )
        for engine in view.coverage
    )
    facts: list[tuple[str, str]] = [
        (tr("Name", language), view.display_name or view.target),
        (tr("Kind", language), tr(kind.label, language)),
    ]
    if view.file_size is not None:
        facts.append((tr("Size", language), isolate(format_size(view.file_size), language)))
    if view.mean_entropy is not None:
        level = (
            "Ordinary"
            if view.mean_entropy < 4.0
            else "Mixed"
            if view.mean_entropy < 6.5
            else "Very random · often compressed or encrypted"
        )
        facts.append(
            (
                tr("Content randomness", language),
                tr(level, language) + " · " + isolate(f"{view.mean_entropy:.1f} / 8", language),
            )
        )
    if view.sha256:
        facts.append((tr("Fingerprint (SHA-256)", language), view.sha256))
    score_line = (
        tr("Risk score {score} out of 100 · a guide, not a probability", language).format(score=view.score)
        if view.score is not None
        else tr("No risk score is available for this result.", language)
    )
    return Details(findings, places, checks, tuple(facts), score_line)
