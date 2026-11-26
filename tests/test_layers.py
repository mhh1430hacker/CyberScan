"""Layered analysis (core/layers): registry integrity, applicability, the orchestrator (parallel,
time limits, failure isolation), the aggregation formula, the streamed progress payload, the
verdict rule, and the summary written for the reader's profile (template fallback)."""
from __future__ import annotations

import io
import math
import sys
import time
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "web_v"))

from core import layers  # noqa: E402
from core.layers.aggregate import aggregate  # noqa: E402
from core.layers.base import CATEGORIES, Layer, clean, hit, unavailable  # noqa: E402
from core.layers.context import LayerContext  # noqa: E402
from core.layers.orchestrator import run_layers  # noqa: E402
from core.models import ScanResult  # noqa: E402

PE_LIKE = b"MZ" + b"\x00" * 0x3A + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 200
PHISH_HTML = (b'<html><body><form action="http://192.0.2.44/login.php" method="post">'
              b'<input name="u"><input type="password" name="p"></form></body></html>')


def _docx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("_rels/.rels", "<Relationships/>")
    return buf.getvalue()


# ------------------------------------------------------------------ registry
def test_registry_ids_unique_and_complete():
    ids = [layer.id for layer in layers.REGISTRY]
    assert len(ids) == len(set(ids))
    assert len(ids) >= 100
    for layer in layers.REGISTRY:
        assert layer.category in CATEGORIES
        assert layer.name_en and layer.name_ar and layer.checks_en and layer.checks_ar
        assert 0.1 <= layer.weight <= 3.0
        assert layer.source


def _signature(layer: Layer) -> tuple:
    run = layer.run
    cells = tuple(repr(c.cell_contents) for c in (run.__closure__ or ()))
    defaults = repr(run.__defaults__)
    return (run.__code__, cells, defaults, layer.tags)


def test_every_layer_checks_something_distinct():
    sigs = [_signature(layer) for layer in layers.REGISTRY]
    assert len(sigs) == len(set(sigs)), "two layers run exactly the same check"
    label_sets = [frozenset(t for t in layer.tags if not t.startswith("scope:")) for layer in layers.REGISTRY if layer.tags]
    assert len(label_sets) == len(set(label_sets)), "two label layers watch the same findings"


def test_every_category_has_layers():
    present = {layer.category for layer in layers.REGISTRY}
    assert present == set(CATEGORIES)


def test_applies_to_follows_the_input():
    text = LayerContext(b"just a note about lunch\n", name="note.txt")
    pe = LayerContext(PE_LIKE, name="tool.exe")
    url = LayerContext(b"https://example.com/", mode="url", target="https://example.com/")
    by_id = {layer.id: layer for layer in layers.REGISTRY}
    assert not by_id["pe_section_entropy"].applies_to(text.facts)
    assert by_id["pe_section_entropy"].applies_to(pe.facts)
    assert not by_id["pdf_launch"].applies_to(pe.facts)
    assert by_id["link_ip_host"].applies_to(url.facts)
    assert not by_id["link_ip_host"].applies_to(text.facts)        # no links in the note
    assert not by_id["virustotal_file"].applies_to(pe.facts)       # no host result: no online answers to read
    assert by_id["offline_hash_table"].applies_to(pe.facts)
    assert not by_id["html_password_form"].applies_to(text.facts)
    assert by_id["html_password_form"].applies_to(LayerContext(PHISH_HTML, name="a.html").facts)
    assert LayerContext(_docx(), name="a.docx").facts["container"] == "ooxml"


def test_broken_predicate_means_not_applicable():
    layer = Layer("x", "X", "س", "structure", "c", "ف", 1.0, lambda f: 1 / 0, lambda ctx: clean(1.0), "test")
    assert layer.applies_to({}) is False


# ------------------------------------------------------------------ real inputs
def test_harmless_text_is_quiet():
    out = layers.analyze(b"Hello, this is a harmless note about lunch.\n", name="note.txt")
    s = out["summary"]
    assert s["suspicious"] == 0 and s["score"] is not None and s["score"] < 10
    assert len(out["layers"]) == len(layers.REGISTRY)


def test_phishing_form_lights_up_web_and_link_layers():
    out = layers.analyze(PHISH_HTML, name="invoice.html")
    hits = {e["id"] for e in out["layers"] if e["signal"] == 1}
    assert {"html_password_form", "html_form_target", "link_ip_host"} <= hits
    assert out["summary"]["score"] > 30


def test_pe_like_file_runs_program_layers():
    out = layers.analyze(PE_LIKE, name="tool.exe")
    by = {e["id"]: e for e in out["layers"]}
    assert by["pe_timestamp"]["signal"] == 1          # zero build time
    assert by["pdf_launch"]["status"] == "not_applicable"
    assert by["ml_ember2024"]["status"] in {"clean", "suspicious", "unavailable", "not_applicable"}   # optional model, read defensively


def test_external_layers_read_the_scans_answers_only():
    result = ScanResult(target="x", heuristic_score=0, ml_risk_score=None, combined_score=0, classification="NO_INDICATORS_OBSERVED")
    result.osint_summary = {"status": "matched", "hash_sources": {
        "VirusTotal": {"status": "match", "malicious": 40, "engines_total": 70},
        "MalwareBazaar": {"status": "not_found"}, "CIRCL hashlookup": {"status": "no_key"}}}
    out = layers.analyze(b"some bytes here", name="a.bin", result=result)
    by = {e["id"]: e for e in out["layers"]}
    assert by["virustotal_file"]["signal"] == 1 and by["virustotal_file"]["hard"] == "many_engines"
    assert by["malwarebazaar"]["signal"] == 0
    assert by["circl_known_good"]["signal"] is None
    assert out["summary"]["score"] >= 85 and out["summary"]["hard_rule"] == "many_engines"


# ------------------------------------------------------------------ orchestrator
def _ctx() -> LayerContext:
    return LayerContext(b"plain text", name="a.txt")


def test_layers_run_in_parallel():
    slow = [Layer(f"slow{i}", "S", "س", "structure", "c", "ف", 1.0, lambda f: True,
                  lambda ctx: (time.sleep(0.3), clean(0.5))[1], "test") for i in range(8)]
    t0 = time.monotonic()
    out = run_layers(_ctx(), layers=slow, max_workers=8)
    assert time.monotonic() - t0 < 1.5           # 8 x 0.3 s sequentially would be 2.4 s
    assert all(e["signal"] == 0 for e in out["layers"])


def test_a_late_layer_times_out_and_the_rest_finish():
    late = Layer("late", "L", "ل", "structure", "c", "ف", 1.0, lambda f: True, lambda ctx: (time.sleep(3), hit(1.0, "x", "x"))[1], "test")
    quick = Layer("quick", "Q", "ق", "structure", "c", "ف", 1.0, lambda f: True, lambda ctx: hit(0.9, "found", "وُجد"), "test")
    t0 = time.monotonic()
    out = run_layers(_ctx(), layers=[late, quick], layer_timeout=0.3)
    assert time.monotonic() - t0 < 2.0
    by = {e["id"]: e for e in out["layers"]}
    assert by["late"]["status"] == "timeout" and by["late"]["signal"] is None
    assert by["quick"]["signal"] == 1


def test_a_failing_layer_never_breaks_the_run():
    boom = Layer("boom", "B", "ب", "structure", "c", "ف", 1.0, lambda f: True, lambda ctx: 1 / 0, "test")
    junk = Layer("junk", "J", "ج", "structure", "c", "ف", 1.0, lambda f: True, lambda ctx: "not a dict", "test")
    fine = Layer("fine", "F", "ف", "structure", "c", "ف", 1.0, lambda f: True, lambda ctx: clean(0.5), "test")
    out = run_layers(_ctx(), layers=[boom, junk, fine])
    by = {e["id"]: e for e in out["layers"]}
    assert by["boom"]["status"] == "error" and by["boom"]["signal"] is None
    assert by["junk"]["signal"] is None
    assert by["fine"]["signal"] == 0


def test_progress_reports_every_layer_once():
    seen = []
    out = layers.analyze(b"note", name="n.txt", progress=lambda entry, done, total: seen.append((entry["id"], done, total)))
    assert [d for _, d, _ in seen] == list(range(1, len(layers.REGISTRY) + 1))
    assert {i for i, _, _ in seen} == {e["id"] for e in out["layers"]}
    assert all(t == len(layers.REGISTRY) for _, _, t in seen)


# ------------------------------------------------------------------ aggregation
def _e(signal, weight=1.0, conf=1.0, cat="structure", scored=True, hard=None, status=None):
    return {"id": f"x{id(object())}", "signal": signal, "weight": weight, "confidence": conf, "category": cat, "affects_score": scored,
            "status": status or ("suspicious" if signal == 1 else "clean" if signal == 0 else "not_applicable"), **({"hard": hard} if hard else {})}


def test_aggregate_formula_exact():
    entries = [_e(1, 2.0, 0.5), _e(0, 1.0, 1.0), _e(0, 1.0, 0.5)]
    s, c, w = 2.0 * 0.5, 1.0 + 0.5, 4.0
    expected = math.log(0.1 / 0.9) + math.log(4) * s - 3 * c / w
    out = aggregate(entries)
    assert out["log_odds"] == pytest.approx(expected, abs=1e-3)
    assert out["score"] == round(100 / (1 + math.exp(-expected)))


def test_none_is_excluded_from_numerator_and_denominator():
    base = [_e(1, 1.5, 0.8), _e(0, 1.0, 0.6)]
    with_none = base + [_e(None, 3.0, 0.0), _e(None, 2.0, 0.0, status="unavailable")]
    assert aggregate(base)["score"] == aggregate(with_none)["score"]
    assert aggregate(base)["answer_weight"] == aggregate(with_none)["answer_weight"]


def test_weight_and_confidence_matter():
    low = aggregate([_e(1, 0.4, 0.5), _e(0, 1.0, 0.5)])["score"]
    high = aggregate([_e(1, 2.5, 0.9), _e(0, 1.0, 0.5)])["score"]
    assert high > low


def test_many_clean_layers_dont_drown_a_strong_signal():
    # the clean pull is a share of the answering weight, so it is bounded (at most e^-3 on the odds):
    # 120 or 1,000 clean layers pull the same, and one strong signal still stands
    many = aggregate([_e(1, 3.0, 0.95)] + [_e(0, 1.0, 0.5)] * 120)["score"]
    huge = aggregate([_e(1, 3.0, 0.95)] + [_e(0, 1.0, 0.5)] * 1000)["score"]
    assert many >= 50 and abs(many - huge) <= 2


def test_privacy_layers_are_reported_not_scored():
    out = aggregate([_e(0, 1.0, 0.6), _e(1, 1.0, 0.9, cat="privacy", scored=False)])
    assert out["privacy_flags"] == 1 and out["suspicious"] == 0
    assert out["score"] == aggregate([_e(0, 1.0, 0.6)])["score"]


def test_hard_rules_set_a_floor():
    assert aggregate([_e(1, 3.0, 0.99, hard="known_malware")] + [_e(0)] * 50)["score"] >= 99
    assert aggregate([_e(1, 2.0, 0.85, hard="many_engines")] + [_e(0)] * 50)["score"] >= 85


def test_no_answers_no_score():
    assert aggregate([_e(None)])["score"] is None


# ------------------------------------------------------------------ verdict rule and progress payload
def _result(cls="NO_INDICATORS_OBSERVED", score=0):
    return ScanResult(target="t", heuristic_score=score, ml_risk_score=None, combined_score=score, classification=cls)


def test_layered_score_can_only_raise_a_clean_result_to_review():
    import services  # noqa: PLC0415

    strong = {"summary": {"score": 80, "suspicious": 6, "answered": 40, "suspicious_categories": ["code", "entropy", "structure"]}}
    r = _result()
    effect = services.apply_layered(r, strong, None, incomplete=False)
    assert effect["applied"] and effect["from"] == "NO_INDICATORS_OBSERVED" and effect["to"] == "REVIEW"
    assert any(f.category == "layers" for f in r.evidence)
    two_categories = {"summary": {**strong["summary"], "suspicious_categories": ["code", "entropy"]}}
    assert not services.apply_layered(_result(), two_categories, None, incomplete=False)["applied"]
    quiet = {"summary": {"score": 3, "suspicious": 0, "answered": 40, "suspicious_categories": []}}
    r2 = _result("SUSPICIOUS", 70)
    effect2 = services.apply_layered(r2, quiet, None, incomplete=False)
    assert not effect2["applied"] and r2.combined_score == 70 and effect2["to"] == "SUSPICIOUS"


def test_job_snapshot_streams_layers_and_stays_compatible():
    import server  # noqa: PLC0415

    job = server.Job()
    assert "layers" not in job.snapshot()                     # older pages: nothing new until layers run
    job.layer_progress({"id": "a", "signal": 1, "status": "suspicious"}, 1, 3)
    job.layer_progress({"id": "b", "signal": None, "status": "not_applicable"}, 2, 3)
    snap = job.snapshot()
    assert snap["layers"]["done"] == 2 and snap["layers"]["total"] == 3
    assert snap["layers"]["cells"] == [{"id": "a", "s": 1, "st": "suspicious"}, {"id": "b", "s": None, "st": "not_applicable"}]
    assert {"id", "status", "stages", "result", "error"} <= set(snap)


# ------------------------------------------------------------------ the summary written for the reader
CTX = {"verdict": "SUSPICIOUS", "score": 72, "mode": "file", "type": "pe", "name": "secret-plans.exe",
       "layers": {"score": 81, "suspicious": 7, "clean": 60, "answered": 67, "applicable": 70, "total": 179, "top": ["Process injection"]},
       "findings": [{"title": "Suspicious PE imports", "severity": "high", "weight": 35},
                    {"title": "High entropy", "severity": "medium", "weight": 18}]}


def test_summary_fallback_varies_by_profile():
    import tailored_summary as ts  # noqa: PLC0415

    ctx = ts.clean_context(CTX)
    assert "name" not in ctx and "secret-plans" not in repr(ctx)   # the file name never travels
    short = ts.local_summary(ctx, ts.clean_profile({"tech": "beginner", "detail": "short", "device": "phone", "tone": "calm", "checks": "personal"}), "en")
    full = ts.local_summary(ctx, ts.clean_profile({"tech": "expert", "detail": "full", "device": "linux", "tone": "technical", "checks": "code"}), "en")
    assert len(full["text"]) > len(short["text"]) and len(full["steps"]) > len(short["steps"])
    assert "Layered analysis" in full["text"] and "log-odds" in full["text"]
    assert "rm" in " ".join(full["steps"]) and "Downloads" in " ".join(short["steps"])
    assert short["written_for"] != full["written_for"]
    windows = ts.local_summary(ctx, ts.clean_profile({"device": "windows"}), "en")
    mac = ts.local_summary(ctx, ts.clean_profile({"device": "mac"}), "en")
    assert windows["steps"] != mac["steps"]


def test_summary_fallback_speaks_arabic_and_states_only_given_facts():
    import tailored_summary as ts  # noqa: PLC0415

    ctx = ts.clean_context(CTX)
    ar = ts.local_summary(ctx, ts.clean_profile({}), "ar")
    assert any("؀" <= ch <= "ۿ" for ch in ar["text"])
    en = ts.local_summary(ts.clean_context({**CTX, "verdict": "NO_INDICATORS_OBSERVED", "score": 0, "findings": []}), ts.clean_profile({}), "en")
    assert "Suspicious PE imports" not in en["text"]


def test_assistant_summarize_falls_back_without_a_model(monkeypatch):
    import assistant  # noqa: PLC0415

    monkeypatch.setattr(assistant, "_bedrock_configured", lambda: False)
    out = assistant.summarize(CTX, {"tech": "beginner", "device": "phone"}, "en", local=False, client="t")
    assert out["source"] == "local" and out["text"] and out["steps"]
    with pytest.raises(assistant.AskError):
        assistant.summarize("nope", {}, "en", local=False)


def test_strict_prompt_carries_the_rules_and_profile():
    import tailored_summary as ts  # noqa: PLC0415

    prompt = ts.system_prompt(ts.clean_context(CTX), ts.clean_profile({"device": "mac", "tech": "beginner"}), "ar")
    assert "Never invent" in prompt and "Mac" in prompt and "Arabic" in prompt and "secret-plans" not in prompt


def test_ml_layer_reads_the_scans_model_answer():
    result = ScanResult(target="x", heuristic_score=0, ml_risk_score=None, combined_score=0, classification="NO_INDICATORS_OBSERVED")
    result.feature_summary = {"ml_malware_model": {"status": "scored", "score": 0.97, "band": "high", "model": "EMBER2024 PE model",
                                                    "threshold_review": 0.5}}
    by = {e["id"]: e for e in layers.analyze(PE_LIKE, name="t.exe", result=result)["layers"]}
    assert by["ml_ember2024"]["signal"] == 1
    result.feature_summary = {"ml_malware_model": {"status": "unavailable", "detail": "Model file missing."}}
    by = {e["id"]: e for e in layers.analyze(PE_LIKE, name="t.exe", result=result)["layers"]}
    assert by["ml_ember2024"]["signal"] is None
