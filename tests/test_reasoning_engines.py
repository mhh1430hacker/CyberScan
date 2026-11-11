"""The engines that check the model's own reasoning.

Claim-capability dissonance, the compression surprise map, conformal
abstention, orbit invariance, the counterfactual self-audit, and the safe JSON
IsolationForest.
"""
from __future__ import annotations

import hashlib
import math

import numpy as np
import pytest

from core import dissonance, surprise_map
from core.deep_embedding import HighDimensionalEmbedding
from ml import conformal, counterfactual, orbit
from ml.anomaly_detector import AnomalyDetector
from ml.anomaly_features import serialize_feature_vector
from ml.pe_layout import parse_layout
from ml.structural_classifier import CLASS_LABELS, StructuralClassifier
from repair_fixtures import build_pe


# -- claim-capability dissonance ---------------------------------------------------------------

def _program(imports=(), version_info=None):
    return {"status": "ok", "import_names": list(imports), "version_info": version_info or {}}


def test_media_viewer_that_steals_passwords_and_hooks_keys_is_high_dissonance():
    pe = _program(["SetWindowsHookExW", "CryptUnprotectData", "WriteProcessMemory", "CreateRemoteThread"],
                  {"FileDescription": "Photo Viewer"})
    result = dissonance.assess("viewer.exe", pe, "", signed=False)

    assert result["claim"]["role"] == "media_viewer"
    assert {"keyboard_hook", "credential_access", "process_injection"} <= {c["capability"] for c in result["capabilities"]}
    assert result["level"] == "high"
    assert "media viewer" in dissonance.describe(result)


def test_browser_that_uses_the_network_is_not_dissonant():
    pe = _program(["InternetOpenW", "HttpSendRequestW", "GetClipboardData"], {"ProductName": "Example Browser"})
    result = dissonance.assess("browser.exe", pe, "", signed=False)

    assert result["claim"]["role"] == "browser_network"
    assert result["level"] == "low"
    assert result["dissonance_bits"] < 1.0


def test_a_program_named_like_an_invoice_is_a_lie():
    result = dissonance.assess("invoice_0423.exe", _program(["URLDownloadToFileW", "ShellExecuteW"]), "", signed=False)

    assert [lie["kind"] for lie in result["lies"]] == ["document_lure"]
    assert result["level"] in {"medium", "high"}


def test_unsigned_windows_process_name_is_impersonation_but_signed_is_not():
    unsigned = dissonance.assess("svchost.exe", _program(), "", signed=False)
    signed = dissonance.assess("svchost.exe", _program(), "", signed=True)

    assert [lie["kind"] for lie in unsigned["lies"]] == ["windows_impersonation"]
    assert unsigned["level"] == "medium"
    assert signed["lies"] == []


def test_string_evidence_and_import_conjunctions():
    found = dissonance.capabilities_of(["RegSetValueExW"], r"software\microsoft\windows\currentversion\run")
    assert "autostart_registry" in found
    # Registry writes alone are ordinary; the Run key is what makes it autostart.
    assert "autostart_registry" not in dissonance.capabilities_of(["RegSetValueExW"], "")
    assert "shadow_copy_destruction" in dissonance.capabilities_of([], "vssadmin delete shadows /all /quiet")
    # An almost empty import table that resolves everything at run time hides its abilities.
    assert "hidden_imports" in dissonance.capabilities_of(["GetProcAddress", "LoadLibraryA", "ExitProcess"], "")
    assert "hidden_imports" not in dissonance.capabilities_of(["GetProcAddress", "LoadLibraryA"] + [f"f{i}" for i in range(20)], "")


def test_non_programs_are_not_assessed():
    assert dissonance.assess("notes.txt", {"status": "not_pe"}, "", signed=False) == {"status": "not_a_program"}


def test_profile_learned_from_benign_programs_lowers_surprise(tmp_path):
    pe = _program(["SetWindowsHookExW"], {"FileDescription": "Media Player"})
    prior = dissonance.assess("player.exe", pe, "", signed=False)
    # Benign media players that all hook the keyboard (global media keys).
    profile = dissonance.fit_profile([("media_viewer", ["keyboard_hook"])] * 200, "test players")
    path = tmp_path / "profile.json"
    digest = dissonance.save_profile(profile, path)
    loaded = dissonance.load_profile(path, digest)
    learned = dissonance.assess("player.exe", pe, "", signed=False, profile=loaded)

    assert learned["dissonance_bits"] < prior["dissonance_bits"]
    with pytest.raises(ValueError):
        dissonance.load_profile(path, "0" * 64)


# -- compression surprise map ------------------------------------------------------------------

def _code_like(rng, size):
    # Skewed toward a few byte values, like machine code.
    return rng.choice(256, size=size, p=_CODE_Q).astype(np.uint8).tobytes()


_CODE_Q = np.full(256, 0.2 / 236)
_CODE_Q[[0x00, 0x48, 0x89, 0x8B, 0xE8, 0xFF, 0x24, 0x4C, 0x0F, 0x83, 0xC3, 0x74, 0x75, 0x85, 0x45, 0x44, 0x01, 0x10, 0x20, 0x08]] = 0.04


def _program_bytes(code: bytes, resource: bytes):
    header = b"MZ" + bytes(4094)
    data = header + code + resource
    pe = {"status": "ok", "sections": [
        {"name": ".text", "raw_offset": 4096, "raw_data_length": len(code), "executable": True},
        {"name": ".rsrc", "raw_offset": 4096 + len(code), "raw_data_length": len(resource), "executable": False},
    ]}
    return data, pe


def test_random_bytes_are_foreign_in_code_but_not_in_resources(tmp_path):
    rng = np.random.default_rng(1)
    benign = [_program_bytes(_code_like(rng, 4096 * 8), rng.bytes(4096 * 8)) for _ in range(20)]
    profile = surprise_map.fit(iter(benign), "synthetic", second_pass=iter(benign))
    path = tmp_path / "surprise.json"
    loaded = surprise_map.load_profile(path, surprise_map.save_profile(profile, path))

    packed = _program_bytes(_code_like(rng, 4096 * 4) + rng.bytes(4096 * 4), rng.bytes(4096 * 8))
    result = surprise_map.surprise_map(*packed, loaded)

    assert result["status"] == "ok"
    code_regions = [region for region in result["regions"] if region["role"] == "code"]
    assert code_regions and code_regions[0]["offset_start"] >= 4096 + 4096 * 4
    assert all(region["role"] != "resource" for region in result["regions"])

    honest = surprise_map.surprise_map(*_program_bytes(_code_like(rng, 4096 * 8), rng.bytes(4096 * 8)), loaded)
    assert [region for region in honest["regions"] if region["role"] == "code"] == []


def test_surprise_map_skips_non_programs_and_rejects_unapproved_profiles(tmp_path):
    assert surprise_map.surprise_map(b"hello", {"status": "not_pe"}, None)["status"] == "not_applicable"
    path = tmp_path / "p.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError):
        surprise_map.load_profile(path, "0" * 64)


def test_shipped_default_profile_matches_its_pinned_digest():
    digest = hashlib.sha256(surprise_map.DEFAULT_PROFILE.read_bytes()).hexdigest()
    assert digest == surprise_map.DEFAULT_PROFILE_SHA256
    profile = surprise_map.load_profile()
    assert "code" in profile.quantiles


def test_structure_view_places_surprise_regions():
    from ui.structure import build_structure

    position = {"surprise_regions": [{"offset_start": 4096, "offset_end": 8192, "severity": "medium"}]}
    structure = build_structure(bytes(16384), None, {}, position)

    assert any(region.offset_start == 4096 for region in structure.regions)
    assert structure.flags.max() == 2


# -- conformal abstention ----------------------------------------------------------------------

def test_conformal_threshold_and_sets():
    scores = np.array([[0.9, 0.05, 0.05]] * 18 + [[0.4, 0.3, 0.3]] * 2)
    calibration = conformal.calibrate(scores, [0] * 20, alpha=0.1)

    # ceil(21 * 0.9) = 19th smallest nonconformity of eighteen 0.1s and two 0.6s.
    assert calibration.qhat == pytest.approx(0.6)
    assert conformal.prediction_set([0.95, 0.03, 0.02], calibration, CLASS_LABELS) == ["clean"]
    assert len(conformal.prediction_set([0.45, 0.45, 0.1], calibration, CLASS_LABELS)) == 2


def test_too_few_calibration_examples_means_always_abstain():
    calibration = conformal.calibrate(np.array([[1.0, 0.0, 0.0]] * 5), [0] * 5, alpha=0.1)

    assert not calibration.sufficient
    assert conformal.prediction_set([1.0, 0.0, 0.0], calibration, CLASS_LABELS) == list(CLASS_LABELS)
    report = conformal.evaluate(np.array([[1.0, 0.0, 0.0]]), [0], calibration)
    assert report["abstention_rate"] == 1.0 and math.isnan(report["committed_accuracy"])


def test_classifier_abstains_and_keeps_its_calibration_across_save_and_load(tmp_path):
    rng = np.random.default_rng(0)
    X = rng.normal(size=(90, 4096)).astype(np.float32)
    y = list(CLASS_LABELS) * 30
    for index, label in enumerate(y):
        block = CLASS_LABELS.index(label) * 1000
        X[index, block:block + 1000] += 6.0  # wide enough for sqrt(4096)-feature splits to find
    classifier = StructuralClassifier()
    classifier.train(X[:60], y[:60], n_estimators=30)
    calibration = classifier.calibrate_conformal(X[60:], y[60:], alpha=0.1)
    path = classifier.save(tmp_path / "model.json")
    loaded = StructuralClassifier()
    assert loaded.load(path, expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest())

    assert loaded.conformal == calibration
    clear = loaded.predict(X[60])
    assert clear["abstained"] is False and clear["prediction_set"] == [y[60]]
    noise = loaded.predict(np.zeros(4096, dtype=np.float32))
    assert noise["abstained"] == (len(noise["prediction_set"]) != 1)


# -- orbit invariance and counterfactual audit -------------------------------------------------

def test_orbit_members_stay_well_formed_programs():
    data, facts = build_pe()
    layout = parse_layout(data)
    assert [(s.raw_start, s.raw_end) for s in layout.sections] == facts["sections"]

    members = dict(orbit.orbit(data))
    assert {"overlay_zeros", "overlay_random", "overlay_text", "timestamp", "section_names"} <= set(members)
    for name, variant in members.items():
        moved = parse_layout(variant)
        assert moved is not None, name
        # The loader-visible bytes (section contents) are untouched.
        for before, after in zip(layout.sections, moved.sections):
            assert variant[after.raw_start:after.raw_end] == data[before.raw_start:before.raw_end]
    assert orbit.orbit(b"#!/bin/sh\necho hi\n") == []


def _overlay_reader(X):
    # A deliberately bad model: "malware" whenever the embedding's overlay marker is present.
    labels = ["malware" if row[0] > 0 else "clean" for row in X]
    scores = np.array([[0.0, 0.0, 1.0] if row[0] > 0 else [1.0, 0.0, 0.0] for row in X])
    return labels, scores


def _marker_embedding(data: bytes):
    return [1.0 if data.endswith(b"MARKER") else 0.0]


def test_orbit_stability_exposes_a_model_that_reads_the_overlay():
    data, _ = build_pe(overlay=b"MARKER")
    report = orbit.stability([data], _overlay_reader, _marker_embedding)

    assert report["fragile_samples"] == 1
    assert report["per_transform"]["overlay_zeros"] == 0.0
    assert report["per_transform"]["timestamp"] == 1.0


def test_counterfactual_audit_finds_an_incidental_basis():
    data, _ = build_pe(overlay=b"MARKER")
    result = counterfactual.audit(data, _overlay_reader, _marker_embedding, CLASS_LABELS)

    assert result["verdict_basis"] == "incidental"
    assert result["flip"]["kind"] == "overlay"
    assert counterfactual.incidental_indices([data], ["malware"], _overlay_reader, _marker_embedding, CLASS_LABELS) == [0]


def test_counterfactual_audit_reports_a_section_basis_as_substantive():
    data, facts = build_pe(overlay=b"padding")
    start, end = facts["sections"][1]  # .data holds the fixture's placeholder text

    def embed(blob):
        return [1.0 if blob[start:end] == data[start:end] else 0.0]

    result = counterfactual.audit(data, _overlay_reader, embed, CLASS_LABELS)

    assert result["verdict_basis"] == "substantive"
    assert result["flip"]["region"] == ".data"
    # Smaller regions (overlay, timestamp) were tried first and changed nothing.
    assert [r["kind"] for r in result["regions_tried"]][0] in {"timestamp", "overlay"}


# -- shared embedding and the safe IsolationForest ---------------------------------------------

def test_classifier_embeds_with_the_same_embedding_it_is_trained_and_scanned_with():
    data = b"MZ" + bytes(range(256)) * 8
    assert np.allclose(StructuralClassifier().embed_bytes(data), HighDimensionalEmbedding().embed_bytes(data))


def test_json_isolation_forest_matches_scikit_learn_and_needs_a_digest(tmp_path):
    rng = np.random.default_rng(3)
    dataset = [{"file_size": float(rng.integers(1_000, 1_000_000)), "entropy": float(rng.uniform(3, 7)),
                "section_count": int(rng.integers(1, 8)), "extension_category": ".exe"} for _ in range(40)]
    detector = AnomalyDetector(tmp_path / "forest.json")
    digest = detector.train(dataset, training_metadata={
        "training_data_type": "curated_benign_manifest", "benign_sample_count": 40, "manifest_sha256": "a" * 64})
    X = np.array([serialize_feature_vector(item) for item in dataset[:8]])
    expected = -detector.model.score_samples(X)

    loaded = AnomalyDetector(tmp_path / "forest.json")
    assert not loaded.load()
    assert not loaded.load(expected_sha256="0" * 64)
    assert loaded.load(expected_sha256=digest)
    assert np.allclose(loaded._anomaly_scores(X), expected)
    outlier = loaded.anomaly_percentage({"file_size": 9e9, "entropy": 8.0, "section_count": 90})
    typical = loaded.anomaly_percentage(dataset[0])
    assert outlier > typical
    assert b"pickle" not in (tmp_path / "forest.json").read_bytes()
