"""EMBER2024 malware-trained models: feature extraction, the LightGBM evaluator, and how the
score becomes evidence. Only synthetic, harmless files and this machine's own clean files."""
from __future__ import annotations

import gzip
import io
import random
import struct
import sys
import time
from pathlib import Path

import numpy as np
import pytest

from core import authenticode_der, ember_features, ml_malware
from core.ember_features import DIM, FeatureExtractor, hash_features, murmurhash3_32
from core.lgbm_lite import LightGBMModel
from core.models import Finding, ScanResult
from core.risk_engine import finalize_result
from repair_fixtures import build_pe

MODEL_DIR = Path(ml_malware.MODEL_DIR)
PE_MODEL = MODEL_DIR / "EMBER2024_PE.model.gz"
needs_models = pytest.mark.skipif(not PE_MODEL.exists(), reason="EMBER2024 models not installed")


@pytest.fixture(scope="module")
def extractor():
    return FeatureExtractor()


# ------------------------------------------------------------------ FeatureHasher without scikit-learn
def test_murmurhash_matches_scikit_learn():
    murmur = pytest.importorskip("sklearn.utils").murmurhash3_32
    rng = random.Random(4)
    words = ["", "a", "ab", "abc", "abcd", "kernel32.dll:CreateFileA", ".text", "ünïcode", "ordinal17"]
    words += ["".join(chr(rng.randint(32, 0x2FF)) for _ in range(rng.randint(0, 40))) for _ in range(300)]
    for word in words:
        assert murmurhash3_32(word.encode("utf-8")) == murmur(word, seed=0), word


def test_hash_features_matches_feature_hasher():
    hasher = pytest.importorskip("sklearn.feature_extraction").FeatureHasher
    rng = random.Random(9)
    strings = [f"lib{rng.randint(0, 50)}.dll:fn{rng.randint(0, 999)}" for _ in range(400)] + ["", "x", ".text"]
    pairs = [(f".s{rng.randint(0, 9)}", rng.choice([0, 1, 7.25, -3, 1e6])) for _ in range(60)] + [("n", "text")]
    for n, kind, items, alternate in ((1024, "string", strings, False), (128, "string", strings, True),
                                      (50, "pair", pairs, True), (32, "pair", pairs, True)):
        expected = hasher(n, input_type=kind, alternate_sign=alternate).transform([items]).toarray()[0]
        assert np.allclose(hash_features(items, n, kind, alternate), expected, rtol=0, atol=1e-9)


# ------------------------------------------------------------------ the feature vector
def test_vector_shape_dtype_and_determinism(extractor):
    pe = build_pe(overlay=b"harmless overlay text " * 40)[0]
    first, degraded = extractor.vector(pe)
    second, _ = extractor.vector(pe)
    assert first.shape == (DIM,) and first.dtype == np.float32
    assert np.array_equal(first, second) and not degraded
    assert first[2] == 1                                    # is_pe
    assert np.isclose(first[7:263].sum(), 1.0, atol=1e-5)  # the byte histogram is normalised


def test_non_pe_and_tiny_files(extractor):
    text, _ = extractor.vector(b"just some plain words, nothing more\n" * 30)
    one, _ = extractor.vector(b"A")
    assert text[2] == 0 and one[2] == 0 and text.shape == one.shape == (DIM,)
    assert not np.any(text[631:]), "PE-only groups are zeros for a text file"
    with pytest.raises(ValueError):
        extractor.vector(b"")


def test_large_input_entropy_histogram_matches_the_original_loop():
    histogram = ember_features.ByteEntropyHistogram()
    rng = np.random.default_rng(1)
    data = bytes(rng.integers(0, 256, 40_000, dtype=np.uint8)) + b"\x00" * 30_000 + bytes(range(256)) * 60
    fast = histogram.raw_features(data, None)
    slow = np.zeros((16, 16), dtype=np.int64)
    a = np.frombuffer(data, dtype=np.uint8)
    for start in range(0, len(a) - histogram.window + 1, histogram.step):
        h, c = histogram._entropy_bin_counts(a[start:start + histogram.window])
        slow[h, :] += c
    assert fast == slow.flatten().tolist()


def test_matches_thrember_when_installed(extractor):
    thrember = pytest.importorskip("thrember.features")
    pytest.importorskip("signify")
    reference = thrember.PEFeatureExtractor()
    samples = [build_pe()[0], build_pe(overlay=bytes(range(256)) * 30)[0], b"%PDF-1.4\n1 0 obj << >> endobj\n" * 20,
               Path(sys.executable).read_bytes()]
    for data in samples:
        expected = reference.feature_vector(data)
        got, degraded = extractor.vector(data)
        assert not degraded
        assert np.allclose(got, expected, rtol=1e-6, atol=1e-6)


@pytest.mark.parametrize("damage", ["truncated", "garbage_after_mz", "random_mz", "bad_certificate", "huge_counts"])
def test_malformed_programs_never_raise(extractor, damage):
    pe = bytearray(build_pe()[0])
    rng = random.Random(damage)
    if damage == "truncated":
        data = bytes(pe[:300])
    elif damage == "garbage_after_mz":
        data = b"MZ" + bytes(rng.getrandbits(8) for _ in range(5000))
    elif damage == "random_mz":
        data = bytes(pe[:0x80]) + bytes(rng.getrandbits(8) for _ in range(3000))
    elif damage == "bad_certificate":
        data = build_pe(certificate=b"\x30\x82\xff\xff" + bytes(rng.getrandbits(8) for _ in range(400)))[0]
    else:
        struct.pack_into("<H", pe, 0x80 + 6, 0xFFFF)      # NumberOfSections
        data = bytes(pe)
    started = time.monotonic()
    vector, _ = extractor.vector(data)
    assessment = ml_malware.assess(data)
    assert vector.shape == (DIM,) and np.all(np.isfinite(vector))
    assert assessment["status"] in {"scored", "not_applicable", "unavailable"}
    assert time.monotonic() - started < 20


def test_signature_parse_error_and_unsigned():
    unsigned = build_pe()[0]
    assert authenticode_der.signature_features(unsigned, 0)["parse_error"] == 0
    broken = build_pe(certificate=b"\x30\x03\x06\x01\x00")[0]
    features = authenticode_der.signature_features(broken, 0)
    assert features["num_certs"] == 0


def test_signature_matches_signify_on_a_signed_program():
    signify_pe = pytest.importorskip("signify.authenticode").SignedPEFile
    thrember = pytest.importorskip("thrember.features")
    import pefile

    data = Path(sys.executable).read_bytes()
    if not list(signify_pe(io.BytesIO(data)).iter_signed_datas()):
        pytest.skip("this Python is not signed")
    pe = pefile.PE(data=data, fast_load=True)
    expected = thrember.AuthenticodeSignature().raw_features(data, pe)
    got = authenticode_der.signature_features(data, pe.FILE_HEADER.TimeDateStamp)
    assert got == pytest.approx(expected)


# ------------------------------------------------------------------ the LightGBM evaluator
TINY_MODEL = """tree
version=v4
num_class=1
num_tree_per_iteration=1
label_index=0
max_feature_idx=2
objective=binary sigmoid:1

Tree=0
num_leaves=3
num_cat=1
split_feature=0 1
threshold=0 2.5
decision_type=1 10
left_child=1 -1
right_child=-3 -2
leaf_value=1 -1 0.5
cat_boundaries=0 1
cat_threshold=10

Tree=1
num_leaves=1
leaf_value=0.25

end of trees
"""


def test_evaluator_rules_by_hand():
    """Node 0: categorical on feature 0, categories 1 and 3 (bitset 0b1010) go left to node 1,
    others to leaf 2 (0.5). Node 1: feature 1 <= 2.5 goes to leaf 0 (1), else leaf 1 (-1);
    decision_type 10 = numerical, default left, missing type NaN. Tree 1 is a constant 0.25."""
    nan = float("nan")
    model = LightGBMModel(TINY_MODEL)
    assert model.raw_score([1, 0, 0]) == pytest.approx(1.25)     # category 1 -> node 1 -> 0 <= 2.5
    assert model.raw_score([3, 9, 0]) == pytest.approx(-0.75)    # category 3 -> node 1 -> 9 > 2.5
    assert model.raw_score([3, nan, 0]) == pytest.approx(1.25)   # NaN, missing type NaN -> default side (left)
    assert model.raw_score([2, 0, 0]) == pytest.approx(0.75)     # category 2 not in the set
    assert model.raw_score([-1, 0, 0]) == pytest.approx(0.75)    # negative category -> right
    assert model.raw_score([nan, 0, 0]) == pytest.approx(0.75)   # NaN category (missing None) -> category 0 -> right
    assert model.raw_score([33, 0, 0]) == pytest.approx(0.75)    # beyond the bitset -> right
    assert model.predict([2, 0, 0]) == pytest.approx(1 / (1 + np.exp(-0.75)))
    with pytest.raises(ValueError):
        model.raw_score([1, 0])                                   # too few features


def test_evaluator_matches_lightgbm(extractor):
    lgb = pytest.importorskip("lightgbm")
    rng = np.random.default_rng(0)
    # a small model trained here, with categorical features and missing values
    x = rng.normal(size=(600, 6))
    x[:, 0] = rng.integers(0, 12, 600)
    x[rng.random(x.shape) < 0.1] = np.nan
    x[rng.random(x.shape) < 0.1] = 0
    y = ((np.nan_to_num(x[:, 1]) + (x[:, 0] % 3 == 0)) > 0.5).astype(int)
    booster = lgb.train({"objective": "binary", "num_leaves": 8, "min_data_in_leaf": 5, "verbose": -1, "zero_as_missing": False},
                        lgb.Dataset(x, y, categorical_feature=[0]), num_boost_round=30)
    mine = LightGBMModel(booster.model_to_string())
    probe = np.vstack([x[:100], rng.normal(size=(50, 6)) * 3])
    assert np.allclose([mine.predict(row) for row in probe], booster.predict(probe), atol=1e-9)
    if PE_MODEL.exists():
        shipped = LightGBMModel.load(PE_MODEL)
        reference = lgb.Booster(model_str=gzip.decompress(PE_MODEL.read_bytes()).decode())
        rows = [extractor.vector(build_pe()[0])[0], extractor.vector(Path(sys.executable).read_bytes())[0]]
        rows += [rows[1] * rng.uniform(0.5, 1.5, DIM).astype(np.float32) for _ in range(10)]
        rows = np.array(rows, dtype=np.float32)
        assert np.allclose([shipped.predict(r) for r in rows], reference.predict(rows.astype(np.float64)), atol=1e-6)


# ------------------------------------------------------------------ from score to evidence
def scored(score: float, band: str, kind: str = "PE") -> dict:
    return {"status": "scored", "kind": kind, "score": score, "band": band, "model": "EMBER2024 Windows-program model",
            "benign_rate_high": "0 of 1,200"}


def verdict(*findings: Finding) -> ScanResult:
    result = ScanResult(target="x", heuristic_score=0, ml_risk_score=None, combined_score=0, classification="",
                        evidence=list(findings), feature_summary={}, model_status="", limitations="", summary="")
    return finalize_result(result)


def test_high_score_alone_asks_for_review_never_more():
    (finding,) = ml_malware.findings(scored(0.97, "high"), signed=False, corroborated=False)
    assert finding.contribution < 50 and finding.engines == [ml_malware.ENGINE]
    assert "0.97" in finding.evidence and "strongly resembles malware" in finding.evidence
    assert verdict(finding).classification == "REVIEW"


def test_high_score_with_other_evidence_adds_weight_but_is_not_known_malware():
    (finding,) = ml_malware.findings(scored(0.95, "high"), signed=False, corroborated=True)
    other = Finding("pe", "high", "Suspicious PE imports", "x", 35)
    result = verdict(finding, other)
    assert result.classification == "SUSPICIOUS"
    assert result.classification != "KNOWN_MALWARE"


def test_low_score_and_signed_programs_carry_no_weight():
    (low,) = ml_malware.findings(scored(0.01, "low"), signed=False, corroborated=False)
    (signed,) = ml_malware.findings(scored(0.99, "high"), signed=True, corroborated=True)
    assert low.contribution == signed.contribution == 0
    other = Finding("yara", "high", "Some rule", "x", 50)
    assert verdict(low, other).combined_score == 50, "a clean-looking score never lowers other evidence"
    assert ml_malware.findings({"status": "not_applicable"}, signed=False, corroborated=False) == []


@needs_models
def test_assess_routes_by_file_type():
    assert ml_malware.assess(b"plain text, not a program").get("status") == "not_applicable"
    elf = ml_malware.assess(b"\x7fELF" + b"\x00" * 200)
    assert elf["status"] == "not_applicable" and "isn't used" in elf["detail"]
    result = ml_malware.assess(build_pe()[0])
    assert result["status"] == "scored" and 0.0 <= result["score"] <= 1.0 and result["kind"] == "PE"
    pdf = ml_malware.assess(b"%PDF-1.4\n" + b"1 0 obj << /Type /Catalog >> endobj\n" * 40 + b"%%EOF\n")
    assert pdf["status"] == "scored" and pdf["kind"] == "PDF"


def test_too_large_and_tampered_model(monkeypatch):
    monkeypatch.setattr(ml_malware, "MAX_BYTES", 100)
    assert ml_malware.assess(build_pe()[0])["status"] in {"too_large", "not_applicable"}
    monkeypatch.setattr(ml_malware, "MAX_BYTES", 50 * 1024 * 1024)
    monkeypatch.setattr(ml_malware, "_cache", {"manifest": {"models": {"PE": {
        "name": "x", "file": "EMBER2024_PE.model.gz", "sha256": "0" * 64, "threshold_high": 0.9, "threshold_review": 0.5}}}})
    assert ml_malware.assess(build_pe()[0])["status"] in {"unavailable"}


@needs_models
def test_scan_result_carries_the_model_evidence_and_status():
    from core.file_analyzer import analyze_file

    result = analyze_file("sample.exe", file_data=build_pe()[0])
    assert result.engine_status[ml_malware.ENGINE].startswith("scored ")
    assert result.feature_summary["ml_malware_model"]["status"] == "scored"
    assert any(f.category == "model" and f.engines == [ml_malware.ENGINE] for f in result.evidence)
    assert result.classification != "KNOWN_MALWARE"
    text = analyze_file("notes.txt", file_data=b"meeting notes\n" * 20)
    assert text.engine_status[ml_malware.ENGINE].startswith("not applicable")
    assert not any(f.category == "model" for f in text.evidence)


def test_plain_words_in_english_and_arabic():
    from core.status_text import engine_text
    from ui.finding_text import plain

    en = plain("Machine-learning model: 0.93 — strongly resembles malware", "", "en")
    ar = plain("Machine-learning model: 0.93 — strongly resembles malware", "", "ar")
    assert en.known and "0.93" in en.title and "EMBER2024" in en.body
    assert ar.known and "0.93" in ar.title and "يشبه" in ar.title
    assert plain("Machine-learning model: 0.02 — resembles clean software", "", "ar").known
    status = engine_text(ml_malware.ENGINE, "scored 0.93 with the EMBER2024 Windows-program model")
    assert status["state"] == "ran" and "0.93" in status["en"]
    assert engine_text(ml_malware.ENGINE, "not applicable: text")["state"] == "not_applicable"
