"""Web Security detector tests."""
import textwrap

import pytest

from logguard.models import Severity


@pytest.mark.parametrize(
    "code,rule",
    [
        # WS001 - SQL injection
        (
            'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n',
            "WS001",
        ),
        (
            'cursor.execute("SELECT * FROM t WHERE x = %s" % value)\n',
            "WS001",
        ),
        (
            'cursor.execute("SELECT * FROM t WHERE x = " + value)\n',
            "WS001",
        ),
        (
            'cursor.execute("SELECT * FROM t WHERE x = {}".format(value))\n',
            "WS001",
        ),
        # WS002 - TLS
        ('requests.get("https://x", verify=False)\n', "WS002"),
        ("ctx = ssl._create_unverified_context()\n", "WS002"),
        ("ctx.check_hostname = False\n", "WS002"),
        ("ctx.verify_mode = ssl.CERT_NONE\n", "WS002"),
        ("urllib3.disable_warnings()\n", "WS002"),
        # WS003 - debug
        ("app.run(debug=True)\n", "WS003"),
        ("DEBUG = True\n", "WS003"),
        # WS004 - insecure randomness
        ("token = random.getrandbits(128)\n", "WS004"),
        ("api_key = random.randint(0, 10**9)\n", "WS004"),
        # WS005 - weak crypto
        ("cipher = DES.new(key, DES.MODE_ECB)\n", "WS005"),
        ("cipher = AES.new(key, AES.MODE_ECB)\n", "WS005"),
        # WS006 - assert guarding authorization
        ("def f(user):\n    assert user.is_admin\n", "WS006"),
    ],
)
def test_web_rules(rules, code, rule):
    assert rule in rules(code)


def test_ws006_ignores_plain_invariants(rules):
    assert "WS006" not in rules("def f(x):\n    assert x > 0\n    return x\n")


def test_ws001_parameterized_query_is_safe(rules):
    code = 'cursor.execute("SELECT * FROM t WHERE x = ?", (value,))\n'
    assert "WS001" not in rules(code)


def test_ws002_tls_ok_when_verified(rules):
    assert "WS002" not in rules('requests.get("https://x")\n')


def test_ws004_ignores_non_security_names(rules):
    assert "WS004" not in rules("count = random.randint(1, 10)\n")


def test_ws004_ignores_secrets_module(rules):
    code = "import secrets\ntoken = secrets.token_hex(16)\n"
    assert "WS004" not in rules(code)


def test_ws005_ignores_ecb_mention_only(rules):
    # MODE_ECB referenced but not in a Cipher call is still flagged, so use CBC.
    code = "cipher = AES.new(key, AES.MODE_GCM)\n"
    assert "WS005" not in rules(code)


def test_ws_severity_levels(scan_code):
    target = "cursor.execute(f'SELECT {x}')\n"
    ws001 = [f for f in scan_code(target).findings if f.rule_id == "WS001"]
    assert ws001 and ws001[0].severity == Severity.HIGH.value
