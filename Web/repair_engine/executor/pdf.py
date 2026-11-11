"""PDF repair: undo the last incremental update when it holds nothing but the
flagged objects (and a catalog that only gained references to them).

Anything else in that update, or a catalog that changed in other ways,
means the update carries real edits too, and the action refuses.
"""
from __future__ import annotations

import re

from repair_engine.executor.common import Refused, Removed
from repair_engine.parsers import parse
from repair_engine.parsers.pdf import _ENDOBJ, _OBJECT

_ROOT = re.compile(rb"/Root\s+(\d+)\s+(\d+)\s+R")
_TOKEN = re.compile(rb"/[^\s/<>\[\]()]+|<<|>>|\[|\]|\((?:\\.|[^\\)])*\)|[-+]?\d+(?:\.\d+)?|\bR\b|true|false|null")
_REFERENCE = re.compile(rb"(\d+)\s+(\d+)\s+R")
_MAY_ADD = {b"/OpenAction", b"/AA", b"/Names", b"/EmbeddedFiles", b"/JavaScript"}


def _body(data: bytes, number: int, before: int) -> bytes | None:
    body = None
    for match in _OBJECT.finditer(data, 0, before):
        if int(match.group(1)) == number:
            end = _ENDOBJ.search(data, match.end())
            if end and end.start() <= before:
                body = data[match.end():end.start()].strip()
    return body


def _only_gained_references(old: bytes, new: bytes, flagged: set[int]) -> bool:
    old_tokens, new_tokens = _TOKEN.findall(old), _TOKEN.findall(new)
    extras, cursor = [], 0
    for token in new_tokens:  # old must be a subsequence of new
        if cursor < len(old_tokens) and token == old_tokens[cursor]:
            cursor += 1
        else:
            extras.append(token)
    if cursor != len(old_tokens):
        return False
    for token in extras:
        if token.startswith(b"/") and token not in _MAY_ADD:
            return False
    references = {int(n) for n, _g in _REFERENCE.findall(b" ".join(extras))}
    return references <= flagged and bool(references)


def remove_last_update(data: bytes, objects: list[int]) -> tuple[bytes, list[Removed]]:
    flagged = {int(n) for n in objects}
    if not flagged:
        raise Refused("no flagged objects")
    regions = parse(data)
    markers = regions.of_kind("pdf_eof_marker")
    if len(markers) < 2:
        raise Refused("there is no earlier revision to return to")
    previous_end = markers[-2].end
    last = [r for r in regions.of_kind("pdf_object") if r.start >= previous_end]
    numbers = {r.metadata["number"] for r in last}
    roots = _ROOT.findall(data[previous_end:])
    root = int(roots[-1][0]) if roots else None
    if not flagged <= numbers:
        raise Refused("the flagged objects are not all in the last update")
    if numbers - flagged - ({root} if root is not None else set()):
        raise Refused("the last update also changes other objects")
    if root in numbers and root not in flagged:
        old, new = _body(data, root, previous_end), _body(data, root, len(data))
        if old is None or new is None or not _only_gained_references(old, new, flagged):
            raise Refused("the catalog changed in more ways than referencing the flagged objects")
    covered = sorted((r.start, r.end) for r in regions.regions if r.start >= previous_end and r.kind != "file")
    cursor = previous_end
    for start, end in covered:
        if start > cursor and data[cursor:start].strip():
            raise Refused("the last update holds bytes outside objects and cross-reference data")
        cursor = max(cursor, end)
    if data[cursor:].strip():
        raise Refused("unexpected bytes after the last update")
    return data[:previous_end], [Removed(previous_end, len(data), "pdf_incremental_update", data[previous_end:])]
