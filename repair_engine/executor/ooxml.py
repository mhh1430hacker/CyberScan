"""Office Open XML (docx/xlsx/pptx and their macro twins): remove parts cleanly.

Cutting a member out of the zip is not enough for Office: the part is still
named in ``[Content_Types].xml`` and still targeted by a relationship, and
Word then reports "unreadable content". This rebuilds the package without
the parts, and removes exactly the references that pointed to them: the
content-type override for each part, and every relationship whose target
resolves to a removed part. A removed part's own ``.rels`` goes with it.

Unlike the byte-exact routines, the result is a re-written package (members
are recompressed); every other part's content is kept unchanged.
"""
from __future__ import annotations

import io
import posixpath
import re
import zipfile

from repair_engine.executor.common import Refused, Removed

_RELATIONSHIP = re.compile(rb"<Relationship\b[^>]*?/>", re.IGNORECASE)
_TARGET = re.compile(rb'Target="([^"]*)"')
_EXTERNAL = re.compile(rb'TargetMode="External"', re.IGNORECASE)


def _source_dir(rels_name: str) -> str:
    """``word/_rels/document.xml.rels`` -> ``word`` (where its targets are relative to)."""
    folder = posixpath.dirname(posixpath.dirname(rels_name))
    return folder


def _resolve(rels_name: str, target: str) -> str:
    if target.startswith("/"):
        return target.lstrip("/")
    return posixpath.normpath(posixpath.join(_source_dir(rels_name), target)).lstrip("./")


def _own_rels(part: str) -> str:
    return posixpath.join(posixpath.dirname(part), "_rels", posixpath.basename(part) + ".rels")


def remove_parts(data: bytes, parts: list[str]) -> tuple[bytes, list[Removed]]:
    try:
        source = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise Refused(f"not a readable package: {exc}") from exc
    with source:
        infos = source.infolist()
        names = {info.filename for info in infos}
        if "[Content_Types].xml" not in names:
            raise Refused("not an Office Open XML package")
        targets = {part for part in parts if part in names}
        if not targets:
            raise Refused("none of the parts are in the package")
        if targets & {"[Content_Types].xml", "_rels/.rels"}:
            raise Refused("the package's own index can't be removed")
        targets |= {_own_rels(part) for part in list(targets) if _own_rels(part) in names}
        removed: list[Removed] = []
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as package:
            for info in infos:
                content = source.read(info)
                if info.filename in targets:
                    removed.append(Removed(info.header_offset, info.header_offset + info.compress_size, f"ooxml_part:{info.filename}", content))
                    continue
                if info.filename == "[Content_Types].xml":
                    for part in targets:
                        pattern = rb'<Override\b[^>]*?PartName="/' + re.escape(part.encode()) + rb'"[^>]*?/>'
                        content = re.sub(pattern, b"", content, flags=re.IGNORECASE)
                elif info.filename.endswith(".rels"):
                    def keep(match: re.Match, rels=info.filename) -> bytes:
                        element = match.group(0)
                        if _EXTERNAL.search(element):
                            return element
                        target = _TARGET.search(element)
                        if target and _resolve(rels, target.group(1).decode("utf-8", "replace")) in targets:
                            return b""
                        return element
                    content = _RELATIONSHIP.sub(keep, content)
                clone = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                clone.compress_type = info.compress_type
                clone.external_attr = info.external_attr
                clone.create_system = info.create_system
                package.writestr(clone, content)
    return output.getvalue(), removed
