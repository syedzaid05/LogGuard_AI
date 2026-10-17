"""Secret Scanner: potential hard-coded credential leaks."""
from __future__ import annotations

import ast
import math
import re

from ..models import Category, Severity
from .base import Context, Detector, DetectorResult

# name, regex, severity, confidence, title
PATTERNS: list[tuple[str, re.Pattern, Severity, str, str]] = [
    (
        "AWS Access Key ID",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
        "High",
        "Hard-coded AWS access key",
    ),
    (
        "AWS Secret Key",
        re.compile(
            r"(?i)aws_secret_access_key\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        Severity.CRITICAL,
        "High",
        "Hard-coded AWS secret key",
    ),
    (
        "Google API Key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        Severity.HIGH,
        "High",
        "Hard-coded Google API key",
    ),
    (
        "Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "High",
        "Embedded private key",
    ),
    (
        "GitHub Token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        Severity.HIGH,
        "High",
        "Hard-coded GitHub token",
    ),
    (
        "Slack Token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        Severity.HIGH,
        "High",
        "Hard-coded Slack token",
    ),
    (
        "Stripe Secret Key",
        re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
        Severity.CRITICAL,
        "High",
        "Hard-coded Stripe secret key",
    ),
    (
        "JWT Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        Severity.MEDIUM,
        "Medium",
        "Embedded JWT token",
    ),
]

GENERIC_ASSIGN = re.compile(
    r"""(?i)\b(passwd|password|pwd|secret|token|api[_-]?key|apikey|
        access[_-]?key|auth[_-]?token|client[_-]?secret)\b
        \s*[:=]\s*
        (['"])(?P<val>[^'"\s]{6,})\2""",
    re.VERBOSE,
)

PLACEHOLDERS = (
    "your_", "changeme", "change_me", "example", "placeholder", "dummy",
    "xxxx", "<", ">", "****", "redacted", "none", "null", "todo",
)
SAFE_LOOKUPS = ("os.getenv", "os.environ", "getenv", "environ", "config[",
                "settings.", "secrets.", "vault", "decouple")


class SecretScanner(Detector):
    name = "Secret Scanner"
    category = Category.SECRET.value

    def run(self, tree: ast.AST, source: str, filename: str) -> DetectorResult:
        ctx = Context(tree, source, filename, self.name, self.category)
        result = DetectorResult()
        seen_lines: set[tuple[str, int]] = set()

        for lineno, text in enumerate(source.splitlines(), start=1):
            if self._is_comment_or_safe(text):
                continue

            for label, pattern, sev, conf, title in PATTERNS:
                if pattern.search(text):
                    key = (label, lineno)
                    if key in seen_lines:
                        continue
                    seen_lines.add(key)
                    result.findings.append(
                        ctx.make(
                            rule_id="SC001",
                            severity=sev,
                            confidence=conf,
                            title=title,
                            message=f"Detected a pattern matching {label}.",
                            lineno=lineno,
                            evidence=self._redact(text),
                            recommendation=(
                                "Move the secret into an environment variable or "
                                "secret manager and rotate the exposed value."
                            ),
                            cwe="CWE-798",
                        )
                    )

            m = GENERIC_ASSIGN.search(text)
            if m:
                value = m.group("val")
                if self._looks_like_secret(value):
                    key = ("generic", lineno)
                    if key not in seen_lines:
                        seen_lines.add(key)
                        result.findings.append(
                            ctx.make(
                                rule_id="SC002",
                                severity=Severity.HIGH,
                                confidence="Medium",
                                title="Possible hard-coded credential",
                                message=(
                                    f"Variable '{m.group(1)}' is assigned a "
                                    "literal value that may be a credential."
                                ),
                                lineno=lineno,
                                evidence=self._redact(text),
                                recommendation=(
                                    "Load credentials from configuration or a "
                                    "secret store rather than source code."
                                ),
                                cwe="CWE-798",
                            )
                        )
        return result

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _is_comment_or_safe(text: str) -> bool:
        stripped = text.strip()
        if stripped.startswith("#"):
            return True
        return any(tok in text for tok in SAFE_LOOKUPS)

    @staticmethod
    def _looks_like_secret(value: str) -> bool:
        low = value.lower()
        if any(p in low for p in PLACEHOLDERS):
            return False
        if value.isdigit() or value.isalpha() and low in {"true", "false"}:
            return False
        if len(value) < 8:
            return False
        return _entropy(value) >= 2.5

    @staticmethod
    def _redact(text: str) -> str:
        return re.sub(r"(['\"])([^'\"]{4,})\1", lambda m: m.group(1) + "*" * min(len(m.group(2)), 12) + m.group(1), text)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())
