from __future__ import annotations

import hashlib
from dataclasses import dataclass
from html import escape
from html.parser import HTMLParser
from pathlib import Path


_ALLOWED_TAGS = {
    "a",
    "b",
    "blockquote",
    "br",
    "code",
    "div",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "i",
    "li",
    "ol",
    "p",
    "pre",
    "span",
    "strong",
    "ul",
}
_VOID_TAGS = {"br", "hr"}
_BLOCKED_CONTENT_TAGS = {
    "embed",
    "iframe",
    "math",
    "object",
    "script",
    "style",
    "svg",
    "template",
}
_MAX_INPUT_BYTES = 2_000_000


@dataclass(frozen=True)
class DisarmResult:
    output_html: str
    source_sha256: str
    output_sha256: str
    removed_active_elements: tuple[str, ...]
    stripped_attribute_count: int


class _AllowlistRebuilder(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.output: list[str] = []
        self.open_tags: list[str] = []
        self.blocked_tags: list[str] = []
        self.removed_active_elements: list[str] = []
        self.stripped_attribute_count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.blocked_tags:
            if tag in _BLOCKED_CONTENT_TAGS:
                self.blocked_tags.append(tag)
                self.removed_active_elements.append(tag)
            return

        self.stripped_attribute_count += len(attrs)
        if tag in _BLOCKED_CONTENT_TAGS:
            self.blocked_tags.append(tag)
            self.removed_active_elements.append(tag)
        elif tag in _ALLOWED_TAGS:
            self.output.append(f"<{tag}>")
            if tag not in _VOID_TAGS:
                self.open_tags.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.blocked_tags:
            return
        self.stripped_attribute_count += len(attrs)
        if tag in _BLOCKED_CONTENT_TAGS:
            self.removed_active_elements.append(tag)
        elif tag in _ALLOWED_TAGS:
            self.output.append(f"<{tag}>")
            if tag not in _VOID_TAGS:
                self.output.append(f"</{tag}>")

    def handle_endtag(self, tag: str) -> None:
        if self.blocked_tags:
            if tag in self.blocked_tags:
                matching_index = len(self.blocked_tags) - 1 - self.blocked_tags[::-1].index(tag)
                del self.blocked_tags[matching_index:]
            return

        if tag in self.open_tags:
            matching_index = len(self.open_tags) - 1 - self.open_tags[::-1].index(tag)
            for open_tag in reversed(self.open_tags[matching_index:]):
                self.output.append(f"</{open_tag}>")
            del self.open_tags[matching_index:]

    def handle_data(self, data: str) -> None:
        if not self.blocked_tags:
            self.output.append(escape(data, quote=False))

    def close(self) -> None:
        super().close()
        while self.open_tags:
            self.output.append(f"</{self.open_tags.pop()}>")


def disarm_html_bytes(source: bytes) -> DisarmResult:
    if len(source) > _MAX_INPUT_BYTES:
        raise ValueError(f"Input exceeds the {_MAX_INPUT_BYTES}-byte prototype limit.")
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Refusing to transform HTML that is not valid UTF-8.") from exc

    parser = _AllowlistRebuilder()
    parser.feed(text)
    parser.close()
    output = "".join(parser.output)
    output_bytes = output.encode("utf-8")
    return DisarmResult(
        output_html=output,
        source_sha256=hashlib.sha256(source).hexdigest(),
        output_sha256=hashlib.sha256(output_bytes).hexdigest(),
        removed_active_elements=tuple(parser.removed_active_elements),
        stripped_attribute_count=parser.stripped_attribute_count,
    )


def disarm_html_file(source_path: str | Path, output_path: str | Path) -> DisarmResult:
    source = Path(source_path)
    output = Path(output_path)
    if not source.is_file():
        raise FileNotFoundError(f"HTML input is missing: {source}")
    if source.suffix.lower() not in {".html", ".htm"}:
        raise ValueError("This prototype only accepts .html or .htm inputs.")
    if source.resolve() == output.resolve():
        raise ValueError("Refusing to overwrite the original input.")
    if not output.parent.is_dir():
        raise ValueError(f"Output directory does not exist: {output.parent}")

    result = disarm_html_bytes(source.read_bytes())
    output_bytes = result.output_html.encode("utf-8")
    with output.open("xb") as handle:
        handle.write(output_bytes)

    written_bytes = output.read_bytes()
    if hashlib.sha256(written_bytes).hexdigest() != result.output_sha256:
        output.unlink()
        raise OSError("Output verification failed; the generated file was removed.")
    return result
