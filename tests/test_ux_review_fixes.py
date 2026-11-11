"""The fixes from the ten-persona UX review (reports/ux_personas/REPORT.md).

Each test names the review item it locks in.
"""
from __future__ import annotations

import os

import pytest

from conftest import scan, settle, wait_for
from ui import names
from ui.link_hints import hints
from ui.structure import build_structure

RLO = "\u202e"


# --- P0 #1, #3, #4: names tell the truth ---------------------------------------------------


def test_hidden_direction_characters_are_made_visible():
    truth = names.inspect(f"holiday{RLO}gnp.exe")
    assert truth.hidden == ("RLO",) and truth.real_extension == "exe" and truth.disguised and truth.runs
    assert truth.shown == "holiday⟦RLO⟧gnp.exe"
    assert RLO not in truth.shown


def test_double_extension_is_named():
    truth = names.inspect("invoice_2026.pdf.exe")
    assert (truth.decoy_extension, truth.real_extension) == ("pdf", "exe")
    assert names.inspect("archive.tar.gz").decoy_extension == ""  # not a program: not a disguise
    assert names.inspect("report.final.docx").decoy_extension == ""


def test_shortening_never_hides_the_ending():
    assert names.elide("a_really_long_invoice_name_2026.pdf.exe", 20).endswith(".pdf.exe")
    assert names.elide("tiny.exe", 20) == "tiny.exe"
    assert names.elide(f"a_really_long_holiday_picture{RLO}gnp.exe", 22).endswith("⟦RLO⟧gnp.exe")
    width = lambda text: len(text) * 7  # noqa: E731 - a fixed-width "font"
    assert names.elide_to_width("quarterly_budget_notes_final.pdf.exe", 140, width).endswith(".pdf.exe")


# --- P0 #2: no green "nothing worrying" for what wasn't examined ----------------------------


class _View:
    def __init__(self, key="low", size=100, osint="disabled", findings=()):
        from ui.result_view import VERDICTS, EngineCoverage

        self.verdict = VERDICTS[key]
        self.file_size = size
        self.coverage = (EngineCoverage("OSINT", osint, osint),)
        self.findings = findings
        self.classification = {"low": "NO_INDICATORS_OBSERVED", "high": "SUSPICIOUS", "review": "REVIEW"}[key]
        self.sha256 = None


def test_presentation_key_is_honest_about_what_was_examined():
    from ui.plain_language import presentation_key

    eicar = "44d88612fea8a8f36de82e1278abb02f"
    assert presentation_key(_View(), "Indicator / text", eicar) == "unchecked_indicator"
    assert presentation_key(_View(), "Indicator / text", "example.com") == "unchecked_indicator"
    assert presentation_key(_View(), "URL", "https://example.com") == "unchecked_link"
    assert presentation_key(_View(size=0), "File", "C:/empty.dat") == "empty"
    assert presentation_key(_View(), "Indicator / text", "a sentence of plain text") == "low"
    assert presentation_key(_View(osint="ran"), "Indicator / text", eicar) == "low"
    assert presentation_key(_View("high"), "URL", "https://example.com") == "high"  # never softens a warning


def test_summary_for_a_disguised_program_says_so_and_offers_quarantine():
    from ui.file_kind import KINDS
    from ui.plain_language import summary

    result = summary(_View("review"), KINDS["program"], 0.3, "en", mode="File", target=f"C:/x/holiday{RLO}gnp.exe")
    assert "disguised" in result.notice and result.notice_tone == "danger"
    assert result.advice.startswith("Don't open it")
    assert result.actions[0] == "quarantine"
    assert result.facts[-1] == "Checked in under a second"


# --- lookalike links ---------------------------------------------------------------------------


def test_link_hints_name_the_real_owner():
    (text, values), = hints("https://login-microsoft.secure-verify.example.com/account?id=1")
    assert values["brand"] == "microsoft" and values["owner"] == "example.com"
    assert hints("https://www.microsoft.com/en-us") == []
    assert hints("http://192.168.1.5/login")[0][1]["host"] == "192.168.1.5"
    assert hints("https://user:pw@evil.example/x")[0][0].startswith("Everything before the @")


# --- P1 #14: one place, not three overlapping windows ---------------------------------------------


def test_overlapping_regions_are_merged():
    data = bytes(8192) + os.urandom(8192)
    position = {"entropy_boundaries": [
        {"offset_start": 0, "offset_end": 5120, "severity": "high"},
        {"offset_start": 1024, "offset_end": 6144, "severity": "medium"},
        {"offset_start": 12000, "offset_end": 13000, "severity": "medium"},
    ]}
    structure = build_structure(data, None, {}, position)
    spans = sorted((r.offset_start, r.offset_end, r.severity) for r in structure.regions)
    assert spans == [(0, 6144, "high"), (12000, 13000, "medium")]


# --- in the window ----------------------------------------------------------------------------------


def test_a_disguised_name_is_exposed_before_and_after_the_scan(window, qapplication, tmp_path):
    sample = tmp_path / f"holiday{RLO}gnp.exe"
    sample.write_bytes(b"Just a harmless line of text. " * 40)
    window.lens.set_target(str(sample))
    assert "⟦RLO⟧" in window.lens.preview_name.full_text()
    assert window.lens.preview_warning.isVisible() and ".EXE" in window.lens.preview_warning.text()
    scan(qapplication, window, str(sample))
    panel = window.result_panel
    assert panel.notice_box.isVisibleTo(panel) and "disguised" in panel.notice_text.text()
    card = window.rail.cards[0]
    assert "⟦RLO⟧" in card.item.name


def test_a_typo_link_is_questioned_once(window, qapplication):
    window.lens.set_target("htp:/bad link")
    window.lens.scan_button.click()
    assert window.view == "lens" and "typo" in window.lens.error.text()
    window.lens.scan_button.click()  # the user insists: scan it as text
    assert wait_for(qapplication, lambda: window.view == "result", 30)


def test_scan_something_else_starts_empty(window, qapplication, tmp_path):
    sample = tmp_path / "notes.txt"
    sample.write_text("Agenda.\n" * 20, encoding="utf-8")
    scan(qapplication, window, str(sample))
    window.result_panel.again_button.click()
    assert window.view == "lens" and window.lens.text() == ""


def test_links_and_fingerprints_get_no_cube_and_an_honest_verdict(window, qapplication):
    scan(qapplication, window, "44d88612fea8a8f36de82e1278abb02f")
    panel = window.result_panel
    assert panel.headline.text() == "We can't judge this offline"
    assert panel.online_button.isVisibleTo(panel) and not panel.inside_card.isVisibleTo(panel)
    window.new_scan()
    window.lens.set_target("https://login-microsoft.secure-verify.example.com/account?id=1")
    window.lens.scan_button.click()
    assert not window.sonar.isVisibleTo(window.journey_view)
    assert wait_for(qapplication, lambda: window.view == "result", 30)
    # it borrows the name microsoft on another site, which core/protection.py now flags
    assert panel.headline.text() == "Take a second look"
    assert "example.com" in panel.notice_text.text()


def test_an_empty_file_is_called_empty(window, qapplication, tmp_path):
    sample = tmp_path / "empty.dat"
    sample.write_bytes(b"")
    scan(qapplication, window, str(sample))
    assert window.result_panel.headline.text() == "This file is empty"
    assert window.rail.cards[0].item.verdict_word == "Empty file"


def test_quarantine_and_restore(window, qapplication, tmp_path, dialogs):
    sample = tmp_path / "invoice_2026.pdf.exe"
    sample.write_bytes(b"MZ" + bytes(2000) + b"powershell -nop -w hidden -enc SQBFAFgA")
    scan(qapplication, window, str(sample))
    panel = window.result_panel
    assert panel.quarantine_button.isVisibleTo(panel)
    panel.quarantine_button.click()
    assert not sample.exists()
    record = window.scan_history[-1]
    assert record.get("quarantined") and os.path.exists(record["quarantined"])
    assert not panel.quarantine_button.isVisibleTo(panel) and "quarantine" in panel.notice_text.text()
    window.restore_record(record["id"])
    assert sample.exists() and "quarantined" not in record


def test_repeated_scans_of_one_file_are_one_row(window, qapplication, tmp_path):
    sample = tmp_path / "notes.txt"
    sample.write_text("Agenda.\n" * 20, encoding="utf-8")
    scan(qapplication, window, str(sample))
    window.new_scan()
    scan(qapplication, window, str(sample))
    assert len(window.rail.cards) == 1 and window.rail.cards[0].item.repeat == 2


def test_large_text_scales_painted_text_too(window, qapplication):
    from ui import theme

    window.settings["large_text"] = True
    window._apply_text_scale()
    assert theme.TEXT_SCALE == pytest.approx(1.3)
    assert theme.ui_font(10).pixelSize() == 13
    window.settings["large_text"] = False
    window._apply_text_scale()
    assert theme.TEXT_SCALE == 1.0
