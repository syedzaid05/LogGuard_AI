"""Web Security Detector: injection, TLS, debug mode, crypto and randomness."""
from __future__ import annotations

import ast

from ..models import Category, Severity
from .base import (
    Context,
    Detector,
    DetectorResult,
    dotted_name as _dotted,
    is_false as _is_false,
    is_true as _is_true,
    keyword_value as _kwarg,
)

SQL_EXEC_METHODS = {"execute", "executemany", "executescript"}
RANDOM_FUNCS = {
    "random", "randint", "randrange", "choice", "choices",
    "getrandbits", "sample", "shuffle", "uniform",
}
SECURITY_NAME_WORDS = (
    "token", "secret", "password", "passwd", "salt", "nonce", "otp",
    "csrf", "session", "api_key", "apikey", "auth", "credential",
)
WEAK_CIPHERS = {"DES", "ARC4", "ARC2", "Blowfish", "XOR"}
ASSERT_CONTEXT_WORDS = (
    "admin", "auth", "perm", "role", "staff", "access", "privilege",
    "token", "password", "secret", "credential", "owner", "superuser",
)


class WebSecurityDetector(Detector):
    name = "Web Security"
    category = Category.WEB.value

    def run(self, tree: ast.AST, source: str, filename: str) -> DetectorResult:
        ctx = Context(tree, source, filename, self.name, self.category)
        result = DetectorResult()

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_call(ctx, node, result)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                self._check_assign(ctx, node, result)
            elif isinstance(node, ast.Assert):
                self._check_assert(ctx, node, result)
        return result

    # ------------------------------------------------------------------ rules
    def _check_call(self, ctx: Context, node: ast.Call, result: DetectorResult) -> None:
        name = _dotted(node.func)
        parts = name.split(".")

        # WS001 - SQL built with string interpolation.
        if parts[-1] in SQL_EXEC_METHODS and node.args and _is_dynamic_sql(node.args[0]):
            result.findings.append(
                ctx.make(
                    rule_id="WS001",
                    severity=Severity.HIGH,
                    confidence="High",
                    title="Possible SQL injection",
                    message=(
                        "A SQL statement is built with string formatting/"
                        "concatenation instead of bound parameters."
                    ),
                    node=node,
                    recommendation=(
                        "Use parameterized queries: cursor.execute("
                        '"... WHERE x = ?", (value,)).'
                    ),
                    cwe="CWE-89",
                )
            )

        # WS002 - TLS certificate verification disabled.
        if _is_false(_kwarg(node, "verify")):
            result.findings.append(
                ctx.make(
                    rule_id="WS002",
                    severity=Severity.MEDIUM,
                    confidence="High",
                    title="TLS verification disabled (verify=False)",
                    message=(
                        "Disabling certificate verification allows "
                        "man-in-the-middle attacks."
                    ),
                    node=node,
                    recommendation="Keep verify=True and trust a proper CA bundle.",
                    cwe="CWE-295",
                )
            )
        if parts[-1] in {"_create_unverified_context", "wrap_socket"}:
            result.findings.append(
                ctx.make(
                    rule_id="WS002",
                    severity=Severity.HIGH,
                    confidence="High",
                    title="Unverified SSL context",
                    message="An SSL context that skips certificate verification is created.",
                    node=node,
                    recommendation="Use ssl.create_default_context() instead.",
                    cwe="CWE-295",
                )
            )
        if parts[-1] == "disable_warnings":
            result.findings.append(
                ctx.make(
                    rule_id="WS002",
                    severity=Severity.MEDIUM,
                    confidence="Medium",
                    title="TLS warnings suppressed",
                    message="Suppressing urllib3 TLS warnings can hide insecure connections.",
                    node=node,
                    recommendation="Fix the underlying certificate issue instead of silencing it.",
                    cwe="CWE-295",
                )
            )

        # WS003 - debug mode enabled at runtime.
        if parts[-1] == "run" and _is_true(_kwarg(node, "debug")):
            result.findings.append(
                ctx.make(
                    rule_id="WS003",
                    severity=Severity.MEDIUM,
                    confidence="High",
                    title="Debug mode enabled",
                    message=(
                        "Running with debug=True exposes a debugger and stack "
                        "traces in production."
                    ),
                    node=node,
                    recommendation="Drive debug from configuration and keep it off in production.",
                    cwe="CWE-489",
                )
            )

        # WS005 - weak cipher.
        if parts[-1] == "new" and len(parts) >= 2 and parts[-2] in WEAK_CIPHERS:
            result.findings.append(
                ctx.make(
                    rule_id="WS005",
                    severity=Severity.MEDIUM,
                    confidence="High",
                    title=f"Weak cipher ({parts[-2]})",
                    message=f"{parts[-2]} is a deprecated, insecure cipher.",
                    node=node,
                    recommendation="Use an authenticated cipher such as AES-GCM or ChaCha20-Poly1305.",
                    cwe="CWE-327",
                )
            )
        if any(
            isinstance(n, ast.Attribute) and n.attr == "MODE_ECB"
            for n in ast.walk(node)
        ):
            result.findings.append(
                ctx.make(
                    rule_id="WS005",
                    severity=Severity.MEDIUM,
                    confidence="Medium",
                    title="Insecure ECB block mode",
                    message="ECB mode leaks plaintext patterns and should not be used.",
                    node=node,
                    recommendation="Use an authenticated mode such as GCM or CBC with a MAC.",
                    cwe="CWE-327",
                )
            )

    def _check_assign(self, ctx: Context, node, result: DetectorResult) -> None:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]

        # WS002 - certificate verification disabled via context attributes.
        for target in targets:
            if not isinstance(target, ast.Attribute):
                continue
            if target.attr == "check_hostname" and _is_false(node.value):
                result.findings.append(
                    ctx.make(
                        rule_id="WS002",
                        severity=Severity.HIGH,
                        confidence="High",
                        title="SSL hostname checking disabled",
                        message="Setting check_hostname = False disables certificate hostname validation.",
                        node=node,
                        recommendation="Leave hostname checking enabled.",
                        cwe="CWE-295",
                    )
                )
            if target.attr == "verify_mode" and isinstance(node.value, ast.Attribute) \
                    and node.value.attr == "CERT_NONE":
                result.findings.append(
                    ctx.make(
                        rule_id="WS002",
                        severity=Severity.HIGH,
                        confidence="High",
                        title="SSL verify_mode set to CERT_NONE",
                        message="CERT_NONE accepts any certificate, defeating TLS.",
                        node=node,
                        recommendation="Use CERT_REQUIRED with a trusted CA bundle.",
                        cwe="CWE-295",
                    )
                )

        # WS003 - Django-style DEBUG = True.
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "DEBUG" and _is_true(node.value):
                result.findings.append(
                    ctx.make(
                        rule_id="WS003",
                        severity=Severity.MEDIUM,
                        confidence="Medium",
                        title="Debug flag enabled in settings",
                        message="DEBUG = True must never be committed for production.",
                        node=node,
                        recommendation="Default DEBUG to False and enable it only via env.",
                        cwe="CWE-489",
                    )
                )

        # WS004 - non-cryptographic randomness for secrets.
        if node.value is not None:
            for target in targets:
                if isinstance(target, ast.Name) and _is_security_name(target.id) \
                        and _contains_random_call(node.value):
                    result.findings.append(
                        ctx.make(
                            rule_id="WS004",
                            severity=Severity.MEDIUM,
                            confidence="Medium",
                            title="Insecure randomness for security value",
                            message=(
                                f"'{target.id}' looks security-sensitive but is "
                                "generated with the random module."
                            ),
                            node=node,
                            recommendation="Use the secrets module for tokens and keys.",
                            cwe="CWE-338",
                        )
                    )

    def _check_assert(self, ctx: Context, node: ast.Assert, result: DetectorResult) -> None:
        # Only flag asserts that guard authorization/authentication, which are
        # silently removed under `python -O`. Plain invariant asserts are ignored.
        if not _has_security_context(node.test):
            return
        result.findings.append(
            ctx.make(
                rule_id="WS006",
                severity=Severity.MEDIUM,
                confidence="Medium",
                title="assert used for an authorization check",
                message=(
                    "Assertions are removed when Python runs with -O, so they "
                    "must not guard security or access checks."
                ),
                node=node,
                recommendation="Raise an explicit exception for access control.",
                cwe="CWE-617",
            )
        )


def _is_dynamic_sql(query: ast.AST) -> bool:
    if isinstance(query, ast.JoinedStr):  # f-string
        return True
    if isinstance(query, ast.BinOp) and isinstance(query.op, (ast.Mod, ast.Add)):
        return True
    if isinstance(query, ast.Call) and isinstance(query.func, ast.Attribute) \
            and query.func.attr == "format":
        return True
    return False


def _contains_random_call(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _dotted(child.func)
            if name.startswith("random.") and name.split(".")[-1] in RANDOM_FUNCS:
                return True
    return False


def _is_security_name(name: str) -> bool:
    lowered = name.lower()
    return any(word in lowered for word in SECURITY_NAME_WORDS)


def _has_security_context(node: ast.AST) -> bool:
    for child in ast.walk(node):
        name = ""
        if isinstance(child, ast.Name):
            name = child.id
        elif isinstance(child, ast.Attribute):
            name = child.attr
        if name and any(word in name.lower() for word in ASSERT_CONTEXT_WORDS):
            return True
    return False
