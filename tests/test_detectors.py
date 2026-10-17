"""Rule-level tests for all four detectors."""
import textwrap

import pytest

from logguard.models import Severity


# --------------------------------------------------------------------- Logging
def test_lg001_print(rules):
    assert "LG001" in rules("print('hello')\n")


def test_lg002_fstring_log(rules):
    code = "import logging\nlogger = logging.getLogger(__name__)\nlogger.info(f'x={1}')\n"
    assert "LG002" in rules(code)


def test_lg003_broad_handler_without_log(rules):
    code = textwrap.dedent(
        """
        import logging
        logger = logging.getLogger(__name__)
        def f():
            try:
                risky()
            except Exception:
                return None
        """
    )
    found = rules(code)
    assert "LG003" in found
    assert "EX003" in found


def test_lg003_not_for_silent_handler(rules):
    code = textwrap.dedent(
        """
        def f():
            try:
                risky()
            except Exception:
                pass
        """
    )
    assert "LG003" not in rules(code)


def test_lg004_sensitive_log(rules):
    code = (
        "import logging\nlogger = logging.getLogger(__name__)\n"
        "logger.info('token=%s', password)\n"
    )
    assert "LG004" in rules(code)


# ------------------------------------------------------------------- Exception
def test_ex001_bare_except(rules):
    code = "try:\n    risky()\nexcept:\n    handle()\n"
    assert "EX001" in rules(code)


def test_ex002_swallowed_broad_is_high(scan_code):
    code = "try:\n    risky()\nexcept Exception:\n    pass\n"
    findings = [f for f in scan_code(code).findings if f.rule_id == "EX002"]
    assert findings and findings[0].severity == Severity.HIGH.value


def test_ex002_specific_is_medium(scan_code):
    code = "try:\n    risky()\nexcept ValueError:\n    pass\n"
    result = scan_code(code)
    ex002 = [f for f in result.findings if f.rule_id == "EX002"]
    assert ex002 and ex002[0].severity == Severity.MEDIUM.value
    assert "EX003" not in {f.rule_id for f in result.findings}


def test_ex003_broad(rules):
    code = "try:\n    risky()\nexcept Exception:\n    recover()\n"
    assert "EX003" in rules(code)


def test_ex003_suppressed_when_reraising(rules):
    code = "try:\n    risky()\nexcept BaseException:\n    cleanup()\n    raise\n"
    found = rules(code)
    assert "EX003" not in found
    assert "LG003" not in found


def test_ex004_reraises_caught_name(rules):
    code = "try:\n    risky()\nexcept ValueError as e:\n    raise e\n"
    assert "EX004" in rules(code)


def test_ex005_generic_raise(rules):
    assert "EX005" in rules("raise Exception('boom')\n")


# ---------------------------------------------------------------------- Secret
def test_sc001_known_pattern(rules):
    assert "SC001" in rules('AWS = "AKIAIOSFODNN7EXAMPLE"\n')


def test_sc002_generic_credential(rules):
    assert "SC002" in rules('password = "hunter2SuperSecret"\n')


def test_secret_ignores_env_lookup(rules):
    code = 'import os\npassword = os.getenv("PASSWORD")\n'
    assert "SC002" not in rules(code)
    assert "SC001" not in rules(code)


def test_secret_ignores_placeholder(rules):
    assert "SC002" not in rules('password = "your_password_here"\n')


# --------------------------------------------------------------- Code quality
@pytest.mark.parametrize(
    "code,rule",
    [
        ("eval('1+1')\n", "CQ001"),
        ("exec('x=1')\n", "CQ001"),
        ("import subprocess\nsubprocess.run(cmd, shell=True)\n", "CQ002"),
        ("import os\nos.system('ls')\n", "CQ003"),
        ("import pickle\npickle.loads(data)\n", "CQ004"),
        ("import yaml\nyaml.load(s)\n", "CQ005"),
        ("def f(items=[]):\n    return items\n", "CQ007"),
        ("def f():\n    if x == None:\n        return 1\n", "CQ008"),
        ('import requests\nrequests.get("http://x")\n', "CQ009"),
        ('import uvicorn\nuvicorn.run(app, host="0.0.0.0")\n', "CQ010"),
        ('import hashlib\nhashlib.md5(b"x")\n', "CQ011"),
        ("import tempfile\ntempfile.mktemp()\n", "CQ013"),
    ],
)
def test_code_quality_rules(rules, code, rule):
    assert rule in rules(code)


def test_cq009_no_finding_with_timeout(rules):
    code = 'import requests\nrequests.get("http://x", timeout=5)\n'
    assert "CQ009" not in rules(code)


def test_cq011_suppressed_when_not_security(rules):
    code = 'import hashlib\nhashlib.md5(b"x", usedforsecurity=False)\n'
    assert "CQ011" not in rules(code)


# ----------------------------------------------------------------- noqa / parse
def test_noqa_suppresses_finding(rules):
    assert "CQ001" not in rules("x = eval('1')  # noqa\n")


def test_syntax_error_is_reported_not_fatal(scan_code):
    result = scan_code("def broken(:\n    pass\n")
    assert result.errors
    assert result.findings == [] or all(isinstance(f.line, int) for f in result.findings)
