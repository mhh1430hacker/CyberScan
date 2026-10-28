from __future__ import annotations

import asyncio
import math

import pytest

from core.deep_embedding import HighDimensionalEmbedding
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


def test_global_intelligence_merges_concurrent_feed_results(monkeypatch):
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
        cached = await GlobalIntelligenceEngine().query_indicator("a" * 64)
        assert cached["cache"] == "hit"

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
                api_keys={"urlhaus": "local-test-key", "otx": "local-test-key"},
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
