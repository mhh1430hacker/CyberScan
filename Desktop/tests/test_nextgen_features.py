from __future__ import annotations

import csv
import asyncio
import math

import pytest

from ml.anomaly_detector import AnomalyDetector
from core.deep_embedding import HighDimensionalEmbedding
from ml.feature_schema import FEATURE_ORDER, serialize_feature_vector
from ml.training.train import train_from_manifest
import core.global_intelligence as global_intelligence
from core.global_intelligence import GlobalIntelligenceEngine


def test_embedding_is_deterministic_normalized_and_4096_dimensional():
    engine = HighDimensionalEmbedding()
    content = b"MZ" + bytes(range(256)) * 2
    first = engine.embed_bytes(content)
    second = engine.embed_bytes(content)

    assert len(first) == 4096
    assert first == second
    assert math.sqrt(math.fsum(value * value for value in first)) == pytest.approx(1.0)
    assert engine.compare(first)["status"] == "untrained"


def test_incremental_knn_classifies_only_with_neighbor_agreement():
    engine = HighDimensionalEmbedding(neighbors=2, confidence_threshold=0.999)
    vector = engine.embed_bytes(b"reviewed structural fixture")
    engine.partial_fit([vector, vector], ["benign", "benign"])

    prediction = engine.classify(vector)
    assert prediction["status"] == "classified"
    assert prediction["label"] == "benign"
    assert prediction["confidence"] == 1.0
    assert prediction["confidence_is_calibrated"] is False


def test_global_intelligence_rejects_invalid_indicator_without_network():
    async def exercise():
        result = await GlobalIntelligenceEngine().query_indicator("not-an-ioc")
        assert result["status"] == "invalid_indicator"
        assert all(feed["status"] == "skipped" for feed in result["feeds"].values())

    asyncio.run(exercise())


def test_global_intelligence_reports_missing_optional_http_client(monkeypatch):
    monkeypatch.setattr(global_intelligence, "aiohttp", None)

    async def exercise():
        result = await GlobalIntelligenceEngine().query_indicator("a" * 64)
        assert result["status"] == "unavailable"
        assert all(feed["status"] == "dependency_missing" for feed in result["feeds"].values())

    asyncio.run(exercise())


class _StubAiohttp:
    """Just enough of aiohttp for query_indicator when feed methods are monkeypatched."""

    class ClientTimeout:
        def __init__(self, total=None):
            self.total = total

    class TCPConnector:
        def __init__(self, **_kwargs):
            pass

    class ClientSession:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False


def test_global_intelligence_merges_concurrent_feed_results(monkeypatch):
    monkeypatch.setattr(global_intelligence, "aiohttp", _StubAiohttp)
    engine = GlobalIntelligenceEngine(timeout_seconds=0.5)
    durations: list[float] = []

    async def fake_query(session, indicator, *_args):
        started = asyncio.get_running_loop().time()
        await asyncio.sleep(0.05)
        durations.append(asyncio.get_running_loop().time() - started)
        return engine._feed_result(
            "matched",
            records=[engine._normalize_record("fixture", {"ioc": indicator, "adversary": "fixture-actor"})],
        )

    monkeypatch.setattr(engine, "_query_threatfox", fake_query)
    monkeypatch.setattr(engine, "_query_urlhaus", fake_query)
    monkeypatch.setattr(engine, "_query_otx", fake_query)

    async def exercise():
        result = await engine.query_indicator("a" * 64)
        assert result["status"] == "matched"
        assert set(result["feeds"]) == {"ThreatFox", "URLhaus", "AlienVault OTX"}
        assert all(feed["status"] == "matched" for feed in result["feeds"].values())
        assert result["attributions"] == ["fixture-actor"]
        assert result["elapsed_ms"] < 350

    asyncio.run(exercise())
    assert len(durations) == 3


def test_otx_uses_extended_timeout_without_extending_fast_feed_timeouts():
    aiohttp = pytest.importorskip("aiohttp")
    from aiohttp import web

    async def main():
        async def slow_fast_feed(_request):
            await asyncio.sleep(0.3)
            return web.json_response({"query_status": "no_results"})

        async def slower_otx(_request):
            await asyncio.sleep(0.3)
            return web.json_response({"pulse_info": {"count": 0, "pulses": []}})

        app = web.Application()
        app.router.add_post("/threatfox", slow_fast_feed)
        app.router.add_post("/urlhaus", slow_fast_feed)
        app.router.add_get("/otx/file/{indicator}/general", slower_otx)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            base_url = f"http://127.0.0.1:{port}"
            engine = GlobalIntelligenceEngine(
                timeout_seconds=0.12,
                otx_timeout_seconds=0.7,
                api_keys={"threatfox": "test-key", "urlhaus": "test-key", "otx": "test-key"},
            )
            engine.THREATFOX_URL = f"{base_url}/threatfox"
            engine.URLHAUS_PAYLOAD_ENDPOINT = f"{base_url}/urlhaus"
            engine.OTX_BASE_URL = f"{base_url}/otx"
            result = await engine.query_indicator("a" * 64)
            assert result["feeds"]["ThreatFox"]["status"] == "timeout"
            assert result["feeds"]["URLhaus"]["status"] == "timeout"
            assert result["feeds"]["AlienVault OTX"]["status"] == "no_match"
            assert result["latency_budget_ms"] == 700.0
            assert result["elapsed_ms"] < 600
        finally:
            await runner.cleanup()

    asyncio.run(main())


def test_extension_categories_are_encoded_and_have_current_schema_width():
    exe_vector = serialize_feature_vector({"extension_category": ".exe"})
    text_vector = serialize_feature_vector({"extension_category": ".txt"})

    assert len(exe_vector) == len(FEATURE_ORDER)
    assert len(exe_vector) == 46
    assert exe_vector != text_vector


def test_model_loading_rejects_synthetic_or_unprovenance_metadata(tmp_path):
    model_path = tmp_path / "anomaly.joblib"
    model_path.write_bytes(b"not-loaded-because-metadata-is-rejected")
    model_path.with_suffix(".json").write_text(
        '{"schema_version": 2, "feature_order": ' + str(FEATURE_ORDER).replace("'", '"') + ', "training_data_type": "synthetic_demo"}',
        encoding="utf-8",
    )
    detector = AnomalyDetector(model_path)

    assert detector.load() is False
    assert "provenance" in detector.metadata["load_error"]


def test_training_rejects_unverified_synthetic_dataset(tmp_path):
    detector = AnomalyDetector(tmp_path / "model.joblib")

    with pytest.raises(ValueError, match="curated benign manifest"):
        detector.train(
            [{"entropy": 1.0}] * 30,
            training_metadata={"training_data_type": "synthetic_demo", "benign_sample_count": 30, "manifest_sha256": "0" * 64},
        )


def test_curated_manifest_training_writes_a_schema_valid_model_in_temp_path(tmp_path):
    manifest_path = tmp_path / "curated.csv"
    rows = []
    for index in range(40):
        file_path = tmp_path / f"benign-{index}.txt"
        file_path.write_bytes(f"benign fixture {index} ".encode("ascii") * 8)
        rows.append({"path": file_path.name, "label": "benign", "source": "unit-test fixture only"})
    for index in range(20):
        file_path = tmp_path / f"malicious-{index}.bin"
        file_path.write_bytes(b"MZ" + bytes([index]) * (64 + index))
        rows.append({"path": file_path.name, "label": "malicious", "source": "unit-test fixture only"})
    with manifest_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("path", "label", "source"))
        writer.writeheader()
        writer.writerows(rows)

    model_path = tmp_path / "trained.joblib"
    result = train_from_manifest(manifest_path, model_path)
    detector = AnomalyDetector(model_path)

    assert result["training_examples"] >= 30
    assert result["validation_metrics"]["sample_count"] > 0
    assert detector.load()
    assert detector.metadata["feature_order"] == FEATURE_ORDER
    assert detector.metadata["label_provenance"].startswith("user-provided")
    assert len(detector.metadata["model_sha256"]) == 64