from scoring.threat_scorer import ThreatScorer


def test_threat_scorer_output_shape_and_level():
    scorer = ThreatScorer()
    result = scorer.score(
        log_data={
            "severity": "high",
            "source": "auth",
            "event_type": "failed_login",
            "timestamp": "2026-03-31T17:00:00+00:00",
            "user": "admin",
            "host": "web-01",
        },
        rule_matches=[{"severity": "critical", "confidence": 0.9}],
        anomaly_score=0.8,
        threat_intel_hits=[{"score": 90}],
    )
    assert set(result.keys()) == {"score", "level", "factors", "weights", "explanation"}
    assert 0 <= result["score"] <= 100
    assert result["level"] in {"Low", "Medium", "High", "Critical"}
