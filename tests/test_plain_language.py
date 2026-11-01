"""The three reading levels: wording only, never a different meaning."""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from core.models import Finding, ScanResult
from ui import plain_language
from ui.copy import AR, count_phrase, tr
from ui.file_kind import KINDS, detect_mode, display_name, kind_for_name, kind_for_target
from ui.result_view import build_result_view
from ui.theme import TOKENS

ROOT = Path(__file__).resolve().parents[1]


def result(classification="REVIEW", score=25, evidence=None, engine_status=None, size=2048):
    return ScanResult(
        target="C:/samples/invoice.pdf.exe",
        heuristic_score=score,
        ml_risk_score=None,
        combined_score=score,
        classification=classification,
        evidence=evidence if evidence is not None else [Finding("yara", "high", "EncodedPowerShell", "Encoded PowerShell execution pattern", 50)],
        feature_summary={"file_size": size, "sha256": "ab" * 32},
        engine_status=engine_status if engine_status is not None else {"YARA": "available; 1 rule(s) loaded", "OSINT": "disabled by settings"},
    )


def summary_for(res, language="en", elapsed=1.5):
    view = build_result_view(res, {"entropy_topography": {"mean_entropy": 7.4}})
    return view, plain_language.summary(view, KINDS["program"], elapsed, language)


# --- level 1 ---------------------------------------------------------------


@pytest.mark.parametrize(
    "classification, key, meter",
    [("SUSPICIOUS", "high", 3), ("REVIEW", "review", 2), ("NO_INDICATORS_OBSERVED", "low", 1)],
)
def test_summary_follows_the_engine_verdict(classification, key, meter):
    evidence = [] if classification == "NO_INDICATORS_OBSERVED" else None
    _view, summary = summary_for(result(classification, evidence=evidence))
    assert summary.key == key
    assert summary.meter == meter
    assert summary.headline == plain_language.HEADLINES[key][0]


def test_nothing_found_never_claims_safety():
    _view, summary = summary_for(result("NO_INDICATORS_OBSERVED", 0, evidence=[]))
    words = " ".join((summary.headline, summary.sentence, summary.advice)).lower()
    for claim in ("is safe", "it's safe", "safe to open", "clean", "no threat", "protected"):
        assert claim not in words
    assert summary.limit == "This isn't a guarantee that it's safe."


def test_unfinished_engine_makes_the_result_inconclusive_with_no_meter_level():
    res = result("NO_INDICATORS_OBSERVED", 0, evidence=[], engine_status={"YARA": "error: rules failed to compile"})
    _view, summary = summary_for(res)
    assert summary.key == "inconclusive"
    assert summary.meter is None
    assert summary.headline == "We couldn't be sure"
    assert summary.limit == ""


def test_unknown_classification_is_never_presented_as_a_verdict():
    _view, summary = summary_for(result("SOMETHING_NEW"))
    assert summary.headline == "We couldn't be sure"
    assert summary.meter is None


def test_facts_use_real_counts_and_the_measured_time():
    findings = [Finding("heuristic", "medium", f"Rule{i}", "", 10) for i in range(3)]
    _view, summary = summary_for(result(evidence=findings), elapsed=2.25)
    assert summary.facts[0] == "3 things caught our attention"
    assert summary.facts[1] == "Program · 2.0 KB"
    assert summary.facts[2] == "Checked in 2.2 s" or summary.facts[2] == "Checked in 2.3 s"
    _view, no_time = summary_for(result(evidence=findings), elapsed=None)
    assert len(no_time.facts) == 2


@pytest.mark.parametrize(
    "count, english, arabic",
    [
        (1, "1 thing caught our attention", "شيء واحد لفت انتباهنا"),
        (2, "2 things caught our attention", "شيئان لفتا انتباهنا"),
        (7, "7 things caught our attention", "7 أشياء لفتت انتباهنا"),
        (12, "12 things caught our attention", "12 شيئًا لفت انتباهنا"),
    ],
)
def test_counts_read_naturally_in_both_languages(count, english, arabic):
    assert count_phrase("finding", count, "en") == english
    assert count_phrase("finding", count, "ar") == arabic


# --- level 2 ---------------------------------------------------------------


def test_details_use_plain_words_and_order_by_severity():
    evidence = [
        Finding("heuristic", "low", "Weak hint", "low explanation", 40),
        Finding("yara", "high", "ShadowCopyDeletion", "Shadow copy deletion associated with ransomware behavior", 10),
    ]
    view = build_result_view(result(evidence=evidence))
    details = plain_language.details(view, KINDS["program"], "en")
    assert [f.severity for f in details.findings] == ["high", "low"]
    assert details.findings[0].title == "Can delete backup copies"
    assert "ransomware" in details.findings[0].body
    assert details.findings[0].word == "Serious"
    # a finding outside the catalogue keeps the engine's words
    assert (details.findings[1].title, details.findings[1].body) == ("Weak hint", "low explanation")


def test_identical_findings_are_shown_once_with_their_count():
    evidence = [
        Finding("statistical", "high", "Entropy discontinuity", f"Entropy changed by -2.{i}00 bits/byte across offsets 0x{i}0-0x{i}F.", 12)
        for i in range(5)
    ]
    details = plain_language.details(build_result_view(result(evidence=evidence)), KINDS["program"], "en")
    assert len(details.findings) == 1 and details.findings[0].count == 5


def test_switched_off_check_is_not_reported_as_missing():
    view = build_result_view(result())
    details = plain_language.details(view, KINDS["program"], "en")
    states = {check.name: check.state for check in details.checks}
    assert states["Online lookups"] == "Turned off in your settings"
    assert states["Known-pattern rules"] == "Checked"
    assert all(check.raw for check in details.checks)


def test_missing_score_is_said_plainly_not_invented():
    res = result()
    res.combined_score = None
    view = build_result_view(res)
    assert plain_language.details(view, KINDS["program"], "en").score_line == "No risk score is available for this result."


def test_score_line_says_it_is_not_a_probability():
    view = build_result_view(result(score=72))
    line = plain_language.details(view, KINDS["program"], "en").score_line
    assert "72 out of 100" in line and "not a probability" in line


@pytest.mark.parametrize(
    "raw, human",
    [
        ("EncodedPowerShell", "Encoded PowerShell"),
        ("SuspiciousProcessInjection", "Suspicious Process Injection"),
        ("ANTI_DISASSEMBLY_GAP", "Anti disassembly gap"),
        ("Double extension spoofing", "Double extension spoofing"),
        ("HTTPServer", "HTTP Server"),
    ],
)
def test_identifier_titles_are_made_readable(raw, human):
    assert plain_language.humanize_title(raw) == human


def test_arabic_numbers_and_sizes_keep_their_order():
    view = build_result_view(result(size=371), {"entropy_topography": {"mean_entropy": 3.2}})
    facts = dict(plain_language.details(view, KINDS["program"], "ar").facts)
    assert facts["الحجم"] == "\u2068371 B\u2069"
    assert facts["عشوائية المحتوى"].endswith("\u20683.2 / 8\u2069")


# --- kinds -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "name, kind",
    [
        ("invoice.pdf.exe", "program"),
        ("report.PDF", "document"),
        ("setup.ps1", "script"),
        ("photos.zip", "archive"),
        ("cat.jpeg", "media"),
        ("notes.txt", "text"),
        ("blob", "file"),
    ],
)
def test_kind_comes_from_the_last_extension(name, kind):
    assert kind_for_name(name).key == kind


def test_kind_hues_never_reuse_a_verdict_colour():
    verdicts = {TOKENS["ok"], TOKENS["warn"], TOKENS["danger"]}
    assert not verdicts & {kind.hue for kind in KINDS.values()}


def test_input_kind_is_detected_from_what_was_typed(tmp_path):
    existing = tmp_path / "a.bin"
    existing.write_bytes(b"x")
    assert detect_mode("https://example.com/login") == "URL"
    assert detect_mode(str(existing)) == "File"
    assert detect_mode("C:\\does\\not\\exist.exe") == "File"  # reported as missing, not scanned as text
    assert detect_mode("44d88612fea8a8f36de82e1278abb02f") == "Indicator / text"
    assert detect_mode("example.org") == "Indicator / text"
    assert kind_for_target("https://x.test", "URL").key == "url"
    assert display_name("https://example.com/a/b", "URL") == "example.com/a/b"


# --- copy ------------------------------------------------------------------------


def _ui_literals() -> set[str]:
    """Every string literal passed to tr()/self.t()/t() in the interface modules."""
    found: set[str] = set()
    for path in (ROOT / "ui").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name in {"tr", "t"}:
                    found.add(node.args[0].value)
    return found


def _table_literals() -> set[str]:
    tables = [plain_language.HEADLINES.values(), [plain_language.UNRECOGNIZED]]
    found = {text for group in tables for row in group for text in row}
    found |= set(plain_language.SEVERITY_WORDS.values()) | set(plain_language.CATEGORY_WORDS.values())
    found |= set(plain_language.ENGINE_WORDS.values()) | {words[1] for words in plain_language.CHECK_WORDS.values()}
    found |= {kind.label for kind in KINDS.values()}
    from ui import qt_app, result_tiers, settings_sheet, widgets

    found |= set(qt_app.STAGE_TITLES) | set(qt_app.STAGE_CAPTIONS) | set(qt_app.RAIL_WORDS.values())
    found |= set(result_tiers.ADVANCED_TABS) | {text for _key, text in settings_sheet.ENGINE_OPTIONS}
    found |= set(widgets.LevelMeter.LABELS)
    found |= set(qt_app.REASONS.values()) | set(result_tiers.ResultPanel.AI_MESSAGES.values())
    from ui import repair

    found |= {text for _n, title, body in repair.STEPS for text in (title, body)} | set(repair.RULES)
    return found


def test_every_interface_sentence_has_an_arabic_translation():
    pytest.importorskip("PySide6")
    missing = sorted(text for text in _ui_literals() | _table_literals() if text not in AR)
    assert missing == []


def test_arabic_catalogue_has_no_untranslated_entries():
    allowed_latin = {"YARA", "PE", "MITRE ATT&CK", "JSON"}
    for english, arabic in AR.items():
        if english in allowed_latin:
            continue
        assert re.search(r"[\u0600-\u06FF]", arabic), english


def test_lookups_are_exact():
    assert tr("Scan", "ar") == "افحص"
    assert tr("Scan this file please", "ar") == "Scan this file please"
