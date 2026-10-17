"""Risk & Findings Engine: deduplication, scoring and ranking."""
from __future__ import annotations

from .models import Finding, Severity

SEVERITY_WEIGHT = {
    "Critical": 10.0,
    "High": 6.0,
    "Medium": 3.0,
    "Low": 1.0,
    "Info": 0.2,
}
CONFIDENCE_FACTOR = {"High": 1.0, "Medium": 0.7, "Low": 0.4}


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse exact duplicate findings, keeping the highest severity."""
    best: dict[str, Finding] = {}
    for finding in findings:
        key = finding.fingerprint
        current = best.get(key)
        if current is None or _score(finding) > _score(current):
            best[key] = finding
    return list(best.values())


def rank(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity, then score, then file/line."""
    return sorted(
        findings,
        key=lambda f: (
            -Severity(f.severity).rank,
            -_score(f),
            f.file,
            f.line,
        ),
    )


def risk_score(findings: list[Finding]) -> float:
    """Aggregate 0-100 risk score.

    Each rule contributes its worst instance plus a logarithmic bonus for
    repeats, so one noisy rule cannot saturate the score on its own.
    """
    import math

    if not findings:
        return 0.0
    groups: dict[str, list[float]] = {}
    for f in findings:
        groups.setdefault(f.rule_id, []).append(_score(f))

    total = 0.0
    for scores in groups.values():
        scores.sort(reverse=True)
        total += scores[0] * (1.0 + math.log(len(scores)))

    scaled = 100.0 * (1.0 - math.exp(-total / 60.0))
    return round(min(scaled, 100.0), 1)


def risk_rating(score: float) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    if score > 0:
        return "Low"
    return "Clean"


def _score(finding: Finding) -> float:
    base = SEVERITY_WEIGHT.get(finding.severity, 1.0)
    return base * CONFIDENCE_FACTOR.get(finding.confidence, 0.7)
