"""Passive HTTPS retrieval for tools that read a URL the user names (HSTS, MTA-STS, storage checks).

One GET (or HEAD) to the given URL, certificate verification always on, a hard size cap, no cookies,
no credentials, redirects reported rather than followed. Tests replace ``fetch``.
"""
from __future__ import annotations

import http.client
import socket
import ssl
import urllib.parse
from dataclasses import dataclass, field

from security_toolkit.core import ToolInputError

USER_AGENT = "CyberScan-SecurityTools/1.0 (passive configuration check)"
MAX_BODY = 256 * 1024


@dataclass
class Response:
    url: str
    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    tls_error: str | None = None

    def header_values(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]


class FetchFailed(Exception):
    """Connection, DNS or TLS failure."""


def parse_url(url: str, *, schemes: tuple[str, ...] = ("https",)) -> urllib.parse.SplitResult:
    parts = urllib.parse.urlsplit((url or "").strip())
    if parts.scheme not in schemes or not parts.hostname:
        raise ToolInputError(f"Provide an absolute {' or '.join(schemes)} URL.")
    if parts.username or parts.password:
        raise ToolInputError("URLs with embedded credentials are not accepted.")
    return parts


def fetch(url: str, *, method: str = "GET", timeout: float = 10.0, max_body: int = MAX_BODY) -> Response:
    parts = parse_url(url, schemes=("https", "http"))
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    if parts.scheme == "https":
        context = ssl.create_default_context()
        try:
            import certifi

            context.load_verify_locations(certifi.where())
        except Exception:  # noqa: BLE001 - system store only
            pass
        connection = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout, context=context)
    else:
        connection = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    try:
        connection.request(method, path, headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
        reply = connection.getresponse()
        body = reply.read(max_body + 1) if method != "HEAD" else b""
        return Response(url, reply.status, list(reply.getheaders()), body[:max_body])
    except ssl.SSLCertVerificationError as exc:
        raise FetchFailed(f"certificate verification failed: {exc.verify_message}") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise FetchFailed(type(exc).__name__) from exc
    finally:
        connection.close()


def post_json(url: str, payload: dict, *, timeout: float = 15.0, max_body: int = 4 * 1024 * 1024) -> dict:
    """POST a JSON body to an https URL (used only for opt-in public APIs such as OSV.dev). Tests replace this."""
    import json

    parts = parse_url(url)
    context = ssl.create_default_context()
    try:
        import certifi

        context.load_verify_locations(certifi.where())
    except Exception:  # noqa: BLE001
        pass
    connection = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout, context=context)
    body = json.dumps(payload).encode()
    try:
        connection.request("POST", parts.path or "/", body=body,
                           headers={"User-Agent": USER_AGENT, "Content-Type": "application/json", "Connection": "close"})
        reply = connection.getresponse()
        data = reply.read(max_body + 1)
        if reply.status != 200:
            raise FetchFailed(f"HTTP {reply.status}")
        return json.loads(data[:max_body].decode("utf-8"))
    except ssl.SSLCertVerificationError as exc:
        raise FetchFailed(f"certificate verification failed: {exc.verify_message}") from exc
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise FetchFailed(type(exc).__name__) from exc
    finally:
        connection.close()


def fetch_tls_chain(host: str, port: int, timeout: float) -> list[bytes]:
    """DER certificates as presented by the server (no trust decision here). Tests replace this."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # we validate ourselves and report the failure instead of aborting
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            if hasattr(tls, "get_unverified_chain"):  # Python 3.13+: list of DER bytes, leaf first
                return list(tls.get_unverified_chain() or [])
            return [tls.getpeercert(binary_form=True)]
