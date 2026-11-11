from __future__ import annotations

import importlib
import multiprocessing
from importlib.util import find_spec
from io import BytesIO
from multiprocessing.connection import Connection
from typing import Any
from urllib.parse import urlsplit

from PIL import Image, ImageOps, UnidentifiedImageError

MAX_QR_IMAGE_BYTES = 8 * 1024 * 1024
MAX_QR_IMAGE_PIXELS = 16_000_000
MAX_QR_CODES = 10
MAX_QR_PAYLOAD_LENGTH = 8192
QR_DECODE_TIMEOUT_SECONDS = 5.0
SUPPORTED_IMAGE_FORMATS = {"BMP", "GIF", "JPEG", "PNG", "TIFF", "WEBP"}


def _decode_worker(data: bytes, sender: Connection) -> None:
    try:
        zxingcpp = importlib.import_module("zxingcpp")
        with Image.open(BytesIO(data)) as source:
            image = ImageOps.exif_transpose(source).convert("RGB")
            decoded = zxingcpp.read_barcodes(image, formats=zxingcpp.BarcodeFormat.QRCode)
        sender.send(("ok", [(code.text, str(code.format)) for code in decoded[:MAX_QR_CODES + 1]]))
    except Exception as exc:
        sender.send(("error", type(exc).__name__))
    finally:
        sender.close()


def _decode_in_process(data: bytes) -> tuple[str, Any]:
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_decode_worker, args=(data, sender), daemon=True)
    try:
        process.start()
    except Exception as exc:
        receiver.close()
        sender.close()
        return "error", type(exc).__name__
    sender.close()
    try:
        if not receiver.poll(QR_DECODE_TIMEOUT_SECONDS):
            if process.is_alive():
                process.terminate()
            process.join()
            return "timeout", None
        outcome = receiver.recv()
        process.join(timeout=0.25)
        if process.is_alive():
            process.terminate()
            process.join()
        return outcome
    except EOFError:
        process.join(timeout=0.25)
        return "error", f"Worker exited with code {process.exitcode}."
    finally:
        receiver.close()


def analyze_qr_image(data: bytes, file_name: str = "") -> dict[str, Any]:
    if not isinstance(data, bytes):
        raise TypeError("QR image data must be bytes.")
    if not data:
        raise ValueError("QR image data is empty.")
    if len(data) > MAX_QR_IMAGE_BYTES:
        raise ValueError(f"QR image exceeds the {MAX_QR_IMAGE_BYTES}-byte limit.")
    if find_spec("zxingcpp") is None:
        return {
            "status": "decoder_unavailable", "file_name": file_name, "codes": [],
            "limitations": ["Install zxing-cpp to decode QR images."],
        }

    try:
        with Image.open(BytesIO(data)) as source:
            image_format = (source.format or "").upper()
            width, height = source.size
            if image_format not in SUPPORTED_IMAGE_FORMATS:
                raise ValueError(f"Unsupported QR image format: {image_format or 'unknown'}.")
            if width <= 0 or height <= 0 or width * height > MAX_QR_IMAGE_PIXELS:
                raise ValueError(f"QR image exceeds the {MAX_QR_IMAGE_PIXELS}-pixel limit.")
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError(f"QR input is not a readable image ({type(exc).__name__}).") from exc

    status, decoded = _decode_in_process(data)
    if status == "timeout":
        return {
            "status": "decoder_timeout", "file_name": file_name, "codes": [],
            "limitations": [f"QR decoding exceeded the {QR_DECODE_TIMEOUT_SECONDS:g}-second limit."],
        }
    if status != "ok":
        return {
            "status": "decoder_error", "file_name": file_name, "codes": [],
            "limitations": [f"QR decoder failed: {decoded}."],
        }

    codes: list[dict[str, Any]] = []
    seen: set[str] = set()
    limitations: list[str] = []
    for payload, barcode_format in decoded[:MAX_QR_CODES]:
        if not payload or payload in seen:
            continue
        seen.add(payload)
        if len(payload) > MAX_QR_PAYLOAD_LENGTH:
            limitations.append(f"A decoded payload exceeded {MAX_QR_PAYLOAD_LENGTH} characters and was omitted.")
            continue
        try:
            parts = urlsplit(payload.strip())
            is_url = parts.scheme.lower() in {"http", "https"} and bool(parts.hostname)
        except ValueError:
            is_url = False
        code: dict[str, Any] = {
            "format": barcode_format,
            "payload": payload,
            "kind": "url" if is_url else "text",
            "recommendation": (
                "Review the destination and domain before opening this link."
                if is_url else "Review the decoded text before following instructions or sharing information."
            ),
        }
        if is_url:
            from core.url_analyzer import analyze_url

            assessment = analyze_url(payload)
            code["risk"] = {
                "score": assessment["score"],
                "classification": assessment["classification"],
                "findings": assessment["findings"],
            }
        codes.append(code)

    if len(decoded) > MAX_QR_CODES:
        limitations.append(f"Only the first {MAX_QR_CODES} QR codes were considered.")
    return {
        "status": "decoded" if codes else "no_qr_found",
        "file_name": file_name,
        "image_format": image_format,
        "image_dimensions": {"width": width, "height": height},
        "codes": codes,
        "limitations": limitations + (
            ["Only the first frame was decoded; additional animation/pages were not inspected."]
            if image_format in {"GIF", "TIFF"} else []
        ),
    }
