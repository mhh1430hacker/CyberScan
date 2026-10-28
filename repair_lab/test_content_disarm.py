import hashlib

import pytest

from content_disarm import disarm_html_bytes, disarm_html_file


def test_rebuilds_static_content_and_drops_active_content():
    source = (
        b'<h1 onclick="run()">Hello</h1>'
        b'<script>synthetic-dangerous-content()</script>'
        b'<p style="behavior:active">Safe &amp; readable</p>'
    )

    result = disarm_html_bytes(source)

    assert result.output_html == "<h1>Hello</h1><p>Safe &amp; readable</p>"
    assert result.removed_active_elements == ("script",)
    assert result.stripped_attribute_count == 2
    assert result.source_sha256 == hashlib.sha256(source).hexdigest()
    assert result.output_sha256 == hashlib.sha256(result.output_html.encode()).hexdigest()


def test_active_subtree_and_embedded_markup_are_removed():
    source = b"<p>Before</p><iframe><p>Hidden</p></iframe><p>After</p>"

    result = disarm_html_bytes(source)

    assert result.output_html == "<p>Before</p><p>After</p>"
    assert result.removed_active_elements == ("iframe",)


def test_file_operation_preserves_original_and_writes_verified_new_file(tmp_path):
    source = tmp_path / "sample.html"
    output = tmp_path / "sample.disarmed.html"
    original = b'<p onload="x()">Keep</p><script>synthetic</script>'
    source.write_bytes(original)

    result = disarm_html_file(source, output)

    assert source.read_bytes() == original
    assert output.read_bytes() == result.output_html.encode("utf-8")
    assert result.output_html == "<p>Keep</p>"


def test_refuses_to_overwrite_existing_output(tmp_path):
    source = tmp_path / "sample.html"
    output = tmp_path / "existing.html"
    source.write_text("<p>Input</p>", encoding="utf-8")
    output.write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError):
        disarm_html_file(source, output)

    assert source.read_text(encoding="utf-8") == "<p>Input</p>"
    assert output.read_text(encoding="utf-8") == "keep"


def test_invalid_utf8_is_refused():
    with pytest.raises(ValueError, match="valid UTF-8"):
        disarm_html_bytes(b"<p>\xff</p>")
