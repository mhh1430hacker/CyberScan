from core.file_analyzer import analyze_file

EICAR_TEST_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_structural_finding_cannot_be_reported_as_safe(tmp_path):
    sample = tmp_path / "spoofed.txt"
    sample.write_bytes(b"MZ" + b"\x00" * 64)

    result = analyze_file(str(sample))

    assert any(item.evidence == "Header mismatch" for item in result.evidence)
    assert result.heuristic_score >= 25
    assert result.classification != "SAFE"


def test_eicar_is_reported_as_a_detection_and_explained_as_harmless(tmp_path):
    """Every antivirus reports EICAR: it is how people check that protection reacts."""
    sample = tmp_path / "eicar.txt"
    sample.write_bytes(EICAR_TEST_SIGNATURE)

    result = analyze_file(str(sample))

    marker = [item for item in result.evidence if item.category == "test_marker"]
    assert marker and "harmless" in marker[0].explanation
    assert result.heuristic_score >= 50
    assert result.classification == "SUSPICIOUS"


def test_compressed_formats_and_signed_programs_raise_no_warning(tmp_path):
    import os
    from pathlib import Path

    from core.file_analyzer import hidden_tail_findings, injection_chain

    jpeg = tmp_path / "photo.jpg"
    jpeg.write_bytes(b"\xFF\xD8\xFF\xE0" + os.urandom(200_000) + b"\xFF\xD9")
    assert analyze_file(str(jpeg)).heuristic_score == 0  # compressed by design
    notepad = Path(r"C:\Windows\System32\notepad.exe")
    if notepad.is_file():
        result = analyze_file(str(notepad))
        assert any(item.evidence == "Signed program" for item in result.evidence)
        assert result.heuristic_score == 0
    assert not injection_chain(["IsDebuggerPresent", "OpenProcess", "CreateProcessW", "VirtualAlloc"])
    assert injection_chain(["OpenProcess", "WriteProcessMemory", "CreateRemoteThread"])
    from repair_fixtures import build_png

    png = build_png()[0]
    assert hidden_tail_findings(png + b"PK\x03\x04" + bytes(40), "a.png")[0].contribution == 45
    assert hidden_tail_findings(png, "a.png") == []


def test_indicators_hidden_by_encoding_are_still_found():
    import base64

    from core.heuristic_engine import evaluate_heuristics

    plain = "vssadmin delete shadows /all /quiet"
    for hidden in (plain.encode("utf-16-le").decode("latin-1"), "^".join(plain), " ".join(plain),
                   base64.b64encode(("cmd /c " + plain).encode()).decode()):
        labels = [f["label"] for f in evaluate_heuristics(hidden)["findings"]]
        assert any("backup copies" in label for label in labels), hidden[:40]
        assert "Indicator hidden by encoding" in labels
    assert evaluate_heuristics("Visit chat.com or https://t.co/abc")["findings"][0]["label"] == "URL shortener domain"
    assert not evaluate_heuristics("Visit chat.com and connect.com today")["findings"]
