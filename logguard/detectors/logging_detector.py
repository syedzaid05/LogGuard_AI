"""Logging Detector: missing or weak logging practices."""
from __future__ import annotations

import ast

from ..models import Category, Finding, Severity
from .base import Context, Detector, DetectorResult

LOG_METHODS = {
    "debug", "info", "warning", "warn", "error",
    "exception", "critical", "fatal", "log",
}
SENSITIVE_WORDS = (
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_key", "private_key", "credential", "auth", "session", "cookie",
    "credit_card", "ssn", "social_security", "pin",
)
LOG_TARGETS = {"logging", "logger", "log", "logr"}


def _has_main_guard(tree: ast.AST) -> bool:
    """True if the module has an `if __name__ == "__main__":` block."""
    for node in getattr(tree, "body", []):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if not isinstance(test, ast.Compare):
            continue
        operands = [test.left, *test.comparators]
        names = {o.id for o in operands if isinstance(o, ast.Name)}
        consts = {o.value for o in operands if isinstance(o, ast.Constant)}
        if "__name__" in names and "__main__" in consts:
            return True
    return False


class LoggingDetector(Detector):
    name = "Logging Detector"
    category = Category.LOGGING.value

    def run(self, tree: ast.AST, source: str, filename: str) -> DetectorResult:
        ctx = Context(tree, source, filename, self.name, self.category)
        result = DetectorResult()
        # Track handlers that contain at least one logging call.
        logging_handlers = self._log_bearing_handlers(tree)
        # Executable modules (with an `if __name__ == "__main__"` guard) are
        # expected to write to stdout, so print() is not flagged there.
        allow_print = _has_main_guard(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_call(ctx, node, result, allow_print)
            if isinstance(node, ast.ExceptHandler) and node not in logging_handlers:
                if self._worth_flagging(node):
                    result.findings.append(self._missing_log(ctx, node))
        return result

    @staticmethod
    def _worth_flagging(node: ast.ExceptHandler) -> bool:
        """Only flag missing logs for broad/bare or truly silent handlers."""
        # A handler that re-raises is propagating the error, not hiding it.
        if any(
            isinstance(stmt, ast.Raise) and stmt.exc is None for stmt in node.body
        ):
            return False
        if node.type is None:
            return True
        broad = False
        if isinstance(node.type, ast.Name):
            broad = node.type.id in {"Exception", "BaseException"}
        elif isinstance(node.type, ast.Tuple):
            broad = any(
                isinstance(e, ast.Name) and e.id in {"Exception", "BaseException"}
                for e in node.type.elts
            )
        if not broad:
            return False
        # Silent handlers are already reported by the Exception Analyzer.
        body = [
            n for n in node.body
            if not (
                isinstance(n, ast.Expr)
                and isinstance(n.value, ast.Constant)
                and isinstance(n.value.value, str)
            )
        ]
        return bool(body) and not all(isinstance(s, ast.Pass) for s in body)

    # ------------------------------------------------------------------ rules
    def _check_call(
        self, ctx: Context, node: ast.Call, result: DetectorResult, allow_print: bool = False
    ) -> None:
        func = node.func

        # LG001 - print() instead of a logger.
        if isinstance(func, ast.Name) and func.id == "print" and not allow_print:
            result.findings.append(
                ctx.make(
                    rule_id="LG001",
                    severity=Severity.LOW,
                    confidence="High",
                    title="print() used instead of a logger",
                    message=(
                        "print() writes to stdout without levels, timestamps or "
                        "routing, making operational debugging and auditing hard."
                    ),
                    node=node,
                    recommendation=(
                        "Replace print() with an appropriate logging call, e.g. "
                        "logger.info(...) / logger.debug(...)."
                    ),
                )
            )
            return

        method = self._log_method(func)
        if method is None:
            return

        # LG002 - f-string / %s interpolation prevents lazy formatting.
        if node.args and isinstance(node.args[0], ast.JoinedStr):
            result.findings.append(
                ctx.make(
                    rule_id="LG002",
                    severity=Severity.LOW,
                    confidence="High",
                    title="Eager log message formatting",
                    message=(
                        "The log message is built with an f-string, so it is "
                        "formatted even when the level is disabled."
                    ),
                    node=node,
                    recommendation=(
                        f'Use lazy logging parameters: logger.{method}('
                        '"value=%s", value).'
                    ),
                )
            )

        # LG004 - sensitive data written to logs.
        self._check_sensitive(ctx, node, result)

    def _check_sensitive(self, ctx: Context, node: ast.Call, result: DetectorResult) -> None:
        text = ast.get_source_segment(ctx.source, node) or ""
        lowered = text.lower()
        for word in SENSITIVE_WORDS:
            if word in lowered:
                result.findings.append(
                    ctx.make(
                        rule_id="LG004",
                        severity=Severity.HIGH,
                        confidence="Medium",
                        title="Possible sensitive data in log message",
                        message=(
                            f"Log statement references '{word}', which may leak "
                            "secrets or PII into log files."
                        ),
                        node=node,
                        evidence=text.splitlines()[0][:200],
                        recommendation=(
                            "Never log raw secrets or PII. Redact or hash the "
                            "value before logging."
                        ),
                        cwe="CWE-532",
                    )
                )
                return

    def _missing_log(self, ctx: Context, node: ast.ExceptHandler) -> Finding:
        return ctx.make(
            rule_id="LG003",
            severity=Severity.MEDIUM,
            confidence="Medium",
            title="Exception handled without logging",
            message=(
                "This except block does not log the error, so failures become "
                "invisible in production."
            ),
            node=node,
            recommendation=(
                "Log the exception with full context, e.g. "
                "logger.exception('Failed to ...') inside the handler."
            ),
            cwe="CWE-390",
        )

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _log_method(func: ast.AST) -> str | None:
        if isinstance(func, ast.Attribute) and func.attr in LOG_METHODS:
            base = func.value
            if isinstance(base, ast.Name) and base.id in LOG_TARGETS:
                return func.attr
        return None

    @staticmethod
    def _log_bearing_handlers(tree: ast.AST) -> set[ast.ExceptHandler]:
        handlers: set[ast.ExceptHandler] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Attribute) and child.func.attr in LOG_METHODS:
                        handlers.add(node)
                        break
        return handlers
