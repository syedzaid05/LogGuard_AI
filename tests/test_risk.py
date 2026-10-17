"""Risk & Findings Engine tests."""
from logguard import risk_engine
from logguard.models import Finding, ScanResult, Severity


def make_finding(rule_id="CQ001", severity="High", confidence="High", line=1, file="a.py"):
    return Finding(
        rule_id=rule_id,
        detector="test",
        category="Code Quality",
        severity=severity,
        confidence=confidence,
        title=f"{rule_id} title",
        message="msg",
        file=file,
        line=line,
    )


def test_deduplicate_collapses_identical():
    findings = [make_finding(line=5), make_finding(line=5), make_finding(line=6)]
    assert len(risk_engine.deduplicate(findings)) == 2


def test_rank_orders_by_severity():
    findings = [
        make_finding(rule_id="A", severity="Low", line=1),
        make_finding(rule_id="B", severity="Critical", line=2),
        make_finding(rule_id="C", severity="Medium", line=3),
    ]
    ranked = risk_engine.rank(findings)
    assert [f.severity for f in ranked] == ["Critical", "Medium", "Low"]


def test_risk_score_empty():
    assert risk_engine.risk_score([]) == 0.0
    assert risk_engine.risk_rating(0.0) == "Clean"


def test_risk_score_bounded_and_sublinear_for_repeats():
    single = risk_engine.risk_score([make_finding()])
    many = risk_engine.risk_score([make_finding(line=i) for i in range(200)])
    assert 0 < single < many <= 100
    # A single noisy rule must not fully saturate the score.
    assert many < 100


def test_risk_rating_thresholds():
    assert risk_engine.risk_rating(80) == "Critical"
    assert risk_engine.risk_rating(60) == "High"
    assert risk_engine.risk_rating(30) == "Medium"
    assert risk_engine.risk_rating(5) == "Low"


def test_scan_result_summary():
    result = ScanResult(findings=[make_finding(severity="High"), make_finding(severity="High", line=2)])
    assert result.summary["High"] == 2
    assert result.summary["Total"] == 2
