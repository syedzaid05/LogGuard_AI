"""Reporting and GitHub URL parsing tests."""
import json

import pytest

from logguard import github_scanner, reporting
from logguard.models import Finding, ScanResult
from logguard.secure_processing import ValidationError


def _result() -> ScanResult:
    finding = Finding(
        rule_id="CQ001",
        detector="Code Quality Rules",
        category="Code Quality",
        severity="High",
        confidence="High",
        title="Use of eval()",
        message="danger <script>",
        file="app.py",
        line=3,
        code="eval('1')",
    )
    return ScanResult(target="demo", findings=[finding], files_scanned=1, lines_scanned=10)


def test_to_json_roundtrip():
    data = json.loads(reporting.to_json(_result()))
    assert data["target"] == "demo"
    assert data["summary"]["High"] == 1
    assert data["findings"][0]["rule_id"] == "CQ001"
    assert "risk_score" in data and "risk_rating" in data


def test_to_html_contains_and_escapes():
    html = reporting.to_html(_result())
    assert "demo" in html
    assert "Use of eval()" in html
    assert "<script>" not in html  # message is HTML-escaped
    assert "&lt;script&gt;" in html


@pytest.mark.parametrize(
    "url,expected",
    [
        ("psf/requests", ("psf", "requests", None)),
        ("https://github.com/psf/requests", ("psf", "requests", None)),
        ("https://github.com/psf/requests.git", ("psf", "requests", None)),
        ("https://github.com/psf/requests/tree/main", ("psf", "requests", "main")),
    ],
)
def test_parse_repo_url_valid(url, expected):
    assert github_scanner.parse_repo_url(url) == expected


def test_parse_repo_url_invalid():
    with pytest.raises(ValidationError):
        github_scanner.parse_repo_url("not a repo")
