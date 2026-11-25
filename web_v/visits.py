"""The site's real visit counter (shown on the landing page).

A visit is one browser session on the site: js/visits.js sends POST /api/visit once per session
(sessionStorage), so a reload or moving between pages doesn't count twice, and crawlers that don't
run scripts aren't counted at all; obvious bot user agents are dropped here as well.

Storage: one small JSON object, {"count": n, "since": "YYYY-MM-DD"}.
  - online (AWS Lambda): s3://<CYBERSCAN_STATS_BUCKET>/stats/visits.json, shared by every Lambda
    instance. Each instance adds its visits in batches (every FLUSH_S seconds) with a conditional
    write (If-Match on the ETag), retrying on a conflict, so concurrent instances never overwrite
    each other. Visits still waiting in an instance that is recycled are lost: the number can only
    undercount, never overcount.
  - local: data/visits.json next to the project.
GET /api/visits returns {"count", "since"}; the count includes this instance's unsaved visits.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from datetime import date
from pathlib import Path
from typing import Any

PUBLIC = os.environ.get("CYBERSCAN_PUBLIC") == "1"
BUCKET = os.environ.get("CYBERSCAN_STATS_BUCKET", "cyberscan-assets")
KEY = "stats/visits.json"
LOCAL = Path(__file__).resolve().parent.parent / "data" / "visits.json"
FLUSH_S = 20          # how often an instance writes its batch
READ_S = 60           # how often an instance refreshes the shared total
BOT = re.compile(r"bot|crawl|spider|slurp|headless|preview|monitor|curl|wget|python-requests|httpclient", re.I)

_lock = threading.Lock()
_pending = 0
_stored = {"count": 0, "since": date.today().isoformat()}
_read_at = 0.0
_flushed_at = time.monotonic()
_conditional = True   # off if this botocore can't send If-Match / If-None-Match


def _s3():
    import boto3  # noqa: PLC0415  (present in the Lambda runtime)
    from botocore.config import Config  # noqa: PLC0415
    return boto3.client("s3", config=Config(connect_timeout=2, read_timeout=3, retries={"max_attempts": 2}))


def _read() -> tuple[dict[str, Any], str | None]:
    """The stored total and its ETag (None when nothing is stored yet)."""
    fresh = {"count": 0, "since": date.today().isoformat()}
    if not PUBLIC:
        try:
            return json.loads(LOCAL.read_text("utf-8")), None
        except (OSError, ValueError):
            return fresh, None
    try:
        obj = _s3().get_object(Bucket=BUCKET, Key=KEY)
        return json.loads(obj["Body"].read()), obj.get("ETag")
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "404", "NotFound"):
            return fresh, None
        raise


def _write(data: dict[str, Any], etag: str | None) -> bool:
    """Store the total; False when another instance wrote first (then read again and retry)."""
    global _conditional
    body = json.dumps(data).encode()
    if not PUBLIC:
        LOCAL.parent.mkdir(parents=True, exist_ok=True)
        LOCAL.write_bytes(body)
        return True
    s3 = _s3()
    extra = {"ContentType": "application/json", "CacheControl": "no-store"}
    if _conditional:
        cond = {"IfMatch": etag} if etag else {"IfNoneMatch": "*"}
        try:
            s3.put_object(Bucket=BUCKET, Key=KEY, Body=body, **extra, **cond)
            return True
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code in ("PreconditionFailed", "ConditionalRequestConflict", "412", "409"):
                return False
            if type(exc).__name__ != "ParamValidationError":
                raise
            _conditional = False   # an older botocore: fall through to a plain write
    s3.put_object(Bucket=BUCKET, Key=KEY, Body=body, **extra)
    return True


def _flush() -> None:
    """Add this instance's waiting visits to the stored total (called with _lock held)."""
    global _pending, _stored, _read_at, _flushed_at
    _flushed_at = time.monotonic()
    if not _pending:
        return
    for _ in range(4):
        data, etag = _read()
        data = {"count": int(data.get("count", 0)) + _pending, "since": data.get("since") or date.today().isoformat()}
        if _write(data, etag):
            _stored, _pending, _read_at = data, 0, time.monotonic()
            return
    # still conflicting: keep the visits for the next flush


def record(user_agent: str) -> None:
    global _pending
    if not user_agent or BOT.search(user_agent):
        return
    with _lock:
        _pending += 1
        if time.monotonic() - _flushed_at >= FLUSH_S:
            try:
                _flush()
            except Exception as exc:  # noqa: BLE001 - counting must never break the site
                print(f"visits: flush failed: {exc}", flush=True)


def total() -> dict[str, Any]:
    global _stored, _read_at
    with _lock:
        now = time.monotonic()
        try:
            if _pending and now - _flushed_at >= FLUSH_S:
                _flush()
            elif now - _read_at >= READ_S:
                _stored, _ = _read()
                _read_at = now
        except Exception as exc:  # noqa: BLE001
            print(f"visits: read failed: {exc}", flush=True)
        return {"count": int(_stored.get("count", 0)) + _pending, "since": _stored.get("since")}
