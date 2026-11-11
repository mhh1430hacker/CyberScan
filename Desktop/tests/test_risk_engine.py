from core.risk_engine import combine_scores


def test_combine_scores_stays_within_bounds():
    score = combine_scores(70, 90, heuristic_weight=0.7, ml_weight=0.3)
    assert 0 <= score <= 100
    assert score > 70
