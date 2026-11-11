from core.heuristic_engine import evaluate_heuristics


def test_heuristic_rules_flag_encoded_powershell():
    result = evaluate_heuristics("powershell -enc ZgBpAGcA")
    assert result["score"] > 0
    assert any("PowerShell" in item["label"] for item in result["findings"])


def test_heuristic_rules_clean_input_yields_low_score():
    result = evaluate_heuristics("hello world")
    assert result["score"] < 25
