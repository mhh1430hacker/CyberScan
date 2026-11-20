from __future__ import annotations

import asyncio
import copy
import hashlib
import ipaddress
import json
import os
import re
import threading
import time
from typing import Any
from urllib.parse import quote, urlsplit

try:
    import aiohttp
except (ImportError, OSError):  # pragma: no cover - optional dependency
    aiohttp = None

class GlobalIntelligenceEngine:
    """Concurrent, time-bounded lookups for a supplied IOC.

    This performs reputation lookups against public services; it does not
    discover zero-days or prove an artifact malicious. Results only describe
    the requested indicator and the feed responses received during the lookup.
    """

    MAX_FAST_FEED_TIMEOUT_SECONDS = 2.5   # opt-in lookups: long enough for a real network round trip
    DEFAULT_OTX_TIMEOUT_SECONDS = 2.5
    MAX_OTX_TIMEOUT_SECONDS = 5.0
    CACHE_TTL_SECONDS = 300.0
    MAX_CACHE_ENTRIES = 2048
    THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
    URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
    URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
    URLHAUS_PAYLOAD_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/payload/"
    OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"
    _shared_cache: dict[str, tuple[float, dict[str, Any]]] = {}
    _shared_cache_lock = threading.Lock()

    def __init__(
        self,
        *,
        timeout_seconds: float = MAX_FAST_FEED_TIMEOUT_SECONDS,
        otx_timeout_seconds: float = DEFAULT_OTX_TIMEOUT_SECONDS,
        api_keys: dict[str, str] | None = None,
    ) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive number")
        if isinstance(otx_timeout_seconds, bool) or not isinstance(otx_timeout_seconds, (int, float)) or otx_timeout_seconds <= 0:
            raise ValueError("otx_timeout_seconds must be a positive number")
        self.timeout_seconds = min(float(timeout_seconds), self.MAX_FAST_FEED_TIMEOUT_SECONDS)
        self.otx_timeout_seconds = min(float(otx_timeout_seconds), self.MAX_OTX_TIMEOUT_SECONDS)
        supplied = api_keys or {}
        self.api_keys = {
            "threatfox": supplied.get("threatfox") or os.getenv("THREATFOX_API_KEY") or os.getenv("ABUSECH_AUTH_KEY", ""),
            "urlhaus": supplied.get("urlhaus") or os.getenv("URLHAUS_API_KEY") or os.getenv("ABUSECH_AUTH_KEY", ""),
            "otx": supplied.get("otx") or os.getenv("OTX_API_KEY", ""),
        }

    @property
    def total_timeout_seconds(self) -> float:
        return max(self.timeout_seconds, self.otx_timeout_seconds)

    @staticmethod
    def _infer_indicator_type(indicator: str) -> str | None:
        value = indicator.strip()
        if not value:
            return None
        if re.fullmatch(r"(?i)[a-f0-9]{64}", value):
            return "sha256"
        if re.fullmatch(r"(?i)[a-f0-9]{40}", value):
            return "sha1"
        if re.fullmatch(r"(?i)[a-f0-9]{32}", value):
            return "md5"
        try:
            parsed_ip = ipaddress.ip_address(value.strip("[]"))
            return "ipv4" if parsed_ip.version == 4 else "ipv6"
        except ValueError:
            pass
        parsed_url = urlsplit(value if "://" in value else "")
        if parsed_url.scheme.lower() in {"http", "https"} and parsed_url.hostname:
            return "url"
        candidate = value.rstrip(".").lower()
        if len(candidate) <= 253 and re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", candidate):
            return "domain"
        return None

    @staticmethod
    def _feed_result(status: str, *, error: str | None = None, records: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        return {"status": status, "error": error, "records": records or [], "match_count": len(records or [])}

    @staticmethod
    def _normalize_record(source: str, record: dict[str, Any]) -> dict[str, Any]:
        tags = record.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]
        elif not isinstance(tags, list):
            tags = []
        actor_values = [
            record.get("malware_printable"),
            record.get("threat_type_desc"),
            record.get("name"),
        ]
        actors: list[str] = []
        classifications: list[str] = []
        campaigns: list[str] = []
        for value in actor_values:
            if not isinstance(value, str) or not value.strip():
                continue
            normalized = value.strip()[:200]
            classifications.append(normalized)
        adversary = record.get("adversary")
        if isinstance(adversary, str) and adversary.strip():
            actors.append(adversary.strip()[:200])
        reporter = record.get("reporter")
        if isinstance(reporter, str) and reporter.strip():
            reporter = reporter.strip()[:200]
        else:
            reporter = None
        pulse_info = record.get("pulse_info")
        if isinstance(pulse_info, dict):
            pulses = pulse_info.get("pulses", [])
            if isinstance(pulses, list):
                for pulse in pulses:
                    if not isinstance(pulse, dict):
                        continue
                    for field in ("name", "author_name"):
                        value = pulse.get(field)
                        if isinstance(value, str) and value.strip():
                            campaigns.append(value.strip()[:200])
                    value = pulse.get("adversary")
                    if isinstance(value, str) and value.strip():
                        actors.append(value.strip()[:200])
                    pulse_tags = pulse.get("tags", [])
                    if isinstance(pulse_tags, list):
                        tags.extend(tag for tag in pulse_tags if isinstance(tag, str))
        return {
            "source": source,
            "indicator": str(record.get("ioc") or record.get("url") or record.get("host") or record.get("indicator") or "")[:2048],
            "classification": sorted(set(classifications)),
            "attributions": sorted(set(actors)),
            "campaigns": sorted(set(campaigns)),
            "reported_by": reporter,
            "tags": sorted({tag.strip()[:100] for tag in tags if isinstance(tag, str) and tag.strip()}),
            "reference": str(record.get("urlhaus_reference") or record.get("reference") or "")[:2048],
            "first_seen": str(record.get("first_seen") or record.get("date_added") or "")[:100],
            "confidence": record.get("confidence_level") if isinstance(record.get("confidence_level"), (int, float)) else None,
        }

    async def _request_json(
        self,
        session: Any,
        method: str,
        url: str,
        *,
        source: str,
        json_body: dict[str, Any] | None = None,
        form_body: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        request_timeout_seconds: float,
    ) -> tuple[int, Any]:
        timeout = aiohttp.ClientTimeout(total=request_timeout_seconds)
        async with session.request(method, url, json=json_body, data=form_body, headers=headers, timeout=timeout) as response:
            status_code = response.status
            if status_code >= 400:
                body = (await response.text())[:400]
                raise RuntimeError(f"HTTP {status_code}: {body or response.reason}")
            try:
                payload = await response.json(content_type=None)
            except (json.JSONDecodeError, ValueError) as exc:
                raise RuntimeError("Feed returned a non-JSON response") from exc
            return status_code, payload

    async def _query_threatfox(self, session: Any, indicator: str) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if self.api_keys["threatfox"]:
            headers["Auth-Key"] = self.api_keys["threatfox"]
        try:
            _, payload = await self._request_json(
                session,
                "POST",
                self.THREATFOX_URL,
                source="ThreatFox",
                json_body={"query": "search_ioc", "search_term": indicator},
                headers=headers,
                request_timeout_seconds=self.timeout_seconds,
            )
            if not isinstance(payload, dict):
                return self._feed_result("invalid_response", error="Expected a JSON object")
            query_status = str(payload.get("query_status", "")).lower()
            if query_status in {"no_result", "no_results"}:
                return self._feed_result("no_match")
            data = payload.get("data", [])
            rows = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
            records = [self._normalize_record("ThreatFox", row) for row in rows if isinstance(row, dict)]
            return self._feed_result("matched" if records or query_status in {"ok", "success"} and data else "no_match", records=records)
        except asyncio.TimeoutError:
            return self._feed_result("timeout", error="ThreatFox request exceeded the time budget")
        except Exception as exc:
            return self._feed_result("error", error=f"{type(exc).__name__}: {exc}")

    async def _query_urlhaus(self, session: Any, indicator: str, indicator_type: str) -> dict[str, Any]:
        if not self.api_keys["urlhaus"]:
            return self._feed_result("authentication_required", error="Set URLHAUS_API_KEY or ABUSECH_AUTH_KEY to query URLhaus")
        headers = {"Auth-Key": self.api_keys["urlhaus"]}
        if indicator_type == "url":
            url = self.URLHAUS_URL_ENDPOINT
            body = {"url": indicator}
        elif indicator_type == "sha256":
            url = self.URLHAUS_PAYLOAD_ENDPOINT
            body = {"sha256_hash": indicator}
        elif indicator_type in {"domain", "ipv4", "ipv6"}:
            url = self.URLHAUS_HOST_ENDPOINT
            body = {"host": indicator}
        else:
            return self._feed_result("unsupported_indicator", error=f"URLhaus lookup is unsupported for {indicator_type}")
        try:
            _, payload = await self._request_json(
                session,
                "POST",
                url,
                source="URLhaus",
                form_body=body,
                headers=headers,
                request_timeout_seconds=self.timeout_seconds,
            )
            if not isinstance(payload, dict):
                return self._feed_result("invalid_response", error="Expected a JSON object")
            query_status = str(payload.get("query_status", "")).lower()
            if query_status in {"no_results", "no_result"}:
                return self._feed_result("no_match")
            rows: list[dict[str, Any]] = []
            for key in ("urls", "payloads"):
                values = payload.get(key)
                if isinstance(values, list):
                    rows.extend(value for value in values if isinstance(value, dict))
            if not rows and query_status in {"ok", "found"}:
                rows = [payload]
            records = [self._normalize_record("URLhaus", row) for row in rows]
            return self._feed_result("matched" if records else "no_match", records=records)
        except asyncio.TimeoutError:
            return self._feed_result("timeout", error="URLhaus request exceeded the time budget")
        except Exception as exc:
            return self._feed_result("error", error=f"{type(exc).__name__}: {exc}")

    async def _query_otx(self, session: Any, indicator: str, indicator_type: str) -> dict[str, Any]:
        api_key = self.api_keys["otx"]
        if not api_key:
            return self._feed_result("authentication_required", error="Set OTX_API_KEY to query AlienVault OTX")
        otx_type = {"sha256": "file", "sha1": "file", "md5": "file", "ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "url": "url"}.get(indicator_type)
        if not otx_type:
            return self._feed_result("unsupported_indicator", error=f"AlienVault OTX lookup is unsupported for {indicator_type}")
        endpoint = f"{self.OTX_BASE_URL}/{otx_type}/{quote(indicator, safe='')}/general"
        try:
            _, payload = await self._request_json(
                session,
                "GET",
                endpoint,
                source="AlienVault OTX",
                headers={"X-OTX-API-KEY": api_key},
                request_timeout_seconds=self.otx_timeout_seconds,
            )
            if not isinstance(payload, dict):
                return self._feed_result("invalid_response", error="Expected a JSON object")
            pulse_info = payload.get("pulse_info")
            count = pulse_info.get("count", 0) if isinstance(pulse_info, dict) else 0
            record = self._normalize_record("AlienVault OTX", payload)
            records = [record] if count or record["classification"] or record["attributions"] else []
            return self._feed_result("matched" if records else "no_match", records=records)
        except asyncio.TimeoutError:
            return self._feed_result("timeout", error="AlienVault OTX request exceeded the time budget")
        except Exception as exc:
            return self._feed_result("error", error=f"{type(exc).__name__}: {exc}")

    async def query_indicator(self, indicator: str) -> dict[str, Any]:
        """Query feeds concurrently, each bounded by its timeout."""
        started = time.perf_counter()
        value = indicator.strip() if isinstance(indicator, str) else ""
        indicator_type = self._infer_indicator_type(value)
        if not indicator_type:
            return {
                "status": "invalid_indicator",
                "indicator": value[:2048],
                "indicator_type": None,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "latency_budget_ms": round(self.total_timeout_seconds * 1000, 3),
                "feeds": {name: self._feed_result("skipped", error="Indicator format is unsupported") for name in ("ThreatFox", "URLhaus", "AlienVault OTX")},
                "matches": [],
                "attributions": [],
                "classifications": [],
            }
        feed_context = "|".join((
            self.THREATFOX_URL,
            self.URLHAUS_URL_ENDPOINT,
            self.URLHAUS_HOST_ENDPOINT,
            self.URLHAUS_PAYLOAD_ENDPOINT,
            self.OTX_BASE_URL,
            *(self.api_keys[name] for name in ("threatfox", "urlhaus", "otx")),
        ))
        context_digest = hashlib.blake2b(
            feed_context.encode("utf-8"),
            digest_size=12,
            person=b"CSOSINTCache",
        ).hexdigest()
        cache_key = f"{context_digest}:{indicator_type}:{value.casefold()}"
        with self._shared_cache_lock:
            cached_entry = self._shared_cache.get(cache_key)
            if cached_entry and time.monotonic() - cached_entry[0] < self.CACHE_TTL_SECONDS:
                cached_result = copy.deepcopy(cached_entry[1])
                cached_result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
                cached_result["cache"] = "hit"
                return cached_result
            if cached_entry:
                del self._shared_cache[cache_key]
        if aiohttp is None:
            feeds = {name: self._feed_result("dependency_missing", error="aiohttp is not installed") for name in ("ThreatFox", "URLhaus", "AlienVault OTX")}
            return self._build_result(value, indicator_type, started, feeds)

        request_timeout = aiohttp.ClientTimeout(total=self.total_timeout_seconds)
        connector = aiohttp.TCPConnector(limit=3, ttl_dns_cache=60)
        try:
            async with aiohttp.ClientSession(timeout=request_timeout, connector=connector) as session:
                tasks = {
                    "ThreatFox": asyncio.create_task(self._query_threatfox(session, value)),
                    "URLhaus": asyncio.create_task(self._query_urlhaus(session, value, indicator_type)),
                    "AlienVault OTX": asyncio.create_task(self._query_otx(session, value, indicator_type)),
                }
                done, pending = await asyncio.wait(tuple(tasks.values()), timeout=self.total_timeout_seconds)
                feeds: dict[str, dict[str, Any]] = {}
                task_names = {task: name for name, task in tasks.items()}
                for task in done:
                    name = task_names[task]
                    try:
                        feeds[name] = task.result()
                    except Exception as exc:
                        feeds[name] = self._feed_result("error", error=f"{type(exc).__name__}: {exc}")
                for task in pending:
                    task.cancel()
                    feeds[task_names[task]] = self._feed_result("timeout", error="Overall OSINT deadline reached")
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
        except Exception as exc:
            feeds = {name: self._feed_result("error", error=f"{type(exc).__name__}: {exc}") for name in ("ThreatFox", "URLhaus", "AlienVault OTX")}
        result = self._build_result(value, indicator_type, started, feeds)
        feed_statuses = [feed.get("status") for feed in result["feeds"].values()]
        if result["status"] == "matched" or (
            feed_statuses and all(status == "no_match" for status in feed_statuses)
        ):
            with self._shared_cache_lock:
                expired = [
                    key for key, (timestamp, _) in self._shared_cache.items()
                    if time.monotonic() - timestamp >= self.CACHE_TTL_SECONDS
                ]
                for key in expired:
                    del self._shared_cache[key]
                if cache_key not in self._shared_cache and len(self._shared_cache) >= self.MAX_CACHE_ENTRIES:
                    oldest_key = next(iter(self._shared_cache))
                    del self._shared_cache[oldest_key]
                self._shared_cache[cache_key] = (time.monotonic(), copy.deepcopy(result))
        result["cache"] = "miss"
        return result

    def _build_result(
        self,
        indicator: str,
        indicator_type: str,
        started: float,
        feeds: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        matches = [record for result in feeds.values() for record in result.get("records", [])]
        attributions = sorted({actor for record in matches for actor in record.get("attributions", [])})
        classifications = sorted({label for record in matches for label in record.get("classification", [])})
        if any(result.get("status") == "matched" for result in feeds.values()):
            status = "matched"
        elif all(result.get("status") in {"authentication_required", "unsupported_indicator", "dependency_missing"} for result in feeds.values()):
            status = "unavailable"
        elif any(result.get("status") == "timeout" for result in feeds.values()):
            status = "partial_timeout"
        else:
            status = "no_match"
        return {
            "status": status,
            "indicator": indicator[:2048],
            "indicator_type": indicator_type,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "latency_budget_ms": round(self.total_timeout_seconds * 1000, 3),
            "feeds": feeds,
            "matches": matches,
            "attributions": attributions,
            "classifications": classifications,
            "interpretation": "Feed lookup only; a match is an external report, and no match is not proof of safety.",
        }

    async def lookup(self, indicator: str) -> dict[str, Any]:
        """Alias for ``query_indicator``."""
        return await self.query_indicator(indicator)
