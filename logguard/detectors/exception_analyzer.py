"""Exception Analyzer: swallowed / overly-broad exception handling."""
from __future__ import annotations

import ast

from ..models import Category, Severity
from .base import Context, Detector, DetectorResult

BROAD_EXCEPTIONS = {"Exception", "BaseException"}
PASS_LIKE = (ast.Pass,)


class ExceptionAnalyzer(Detector):
    name = "Exception Analyzer"
    category = Category.EXCEPTION.value

    def run(self, tree: ast.AST, source: str, filename: str) -> DetectorResult:
        ctx = Context(tree, source, filename, self.name, self.category)
        result = DetectorResult()

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                self._check_handler(ctx, node, result)
            elif isinstance(node, ast.Raise):
                self._check_raise(ctx, node, result)
        return result

    # ------------------------------------------------------------------ rules
    def _check_handler(self, ctx: Context, node: ast.ExceptHandler, result: DetectorResult) -> None:
        exc_name = self._exception_name(node)

        if node.type is None:
            result.findings.append(
                ctx.make(
                    rule_id="EX001",
                    severity=Severity.HIGH,
                    confidence="High",
                    title="Bare 'except:' clause",
                    message=(
                        "A bare except catches everything, including SystemExit "
                        "and KeyboardInterrupt, and hides real defects."
                    ),
                    node=node,
                    recommendation=(
                        "Catch specific exception types, e.g. "
                        "except (ValueError, KeyError) as exc."
                    ),
                    cwe="CWE-396",
                )
            )
        elif exc_name in BROAD_EXCEPTIONS and not self._propagates(node):
            result.findings.append(
                ctx.make(
                    rule_id="EX003",
                    severity=Severity.MEDIUM,
                    confidence="Medium",
                    title=f"Overly broad 'except {exc_name}'",
                    message=(
                        "Catching every exception can mask unexpected failures "
                        "and make root-cause analysis difficult."
                    ),
                    node=node,
                    recommendation="Catch only the exception types you can handle.",
                    cwe="CWE-396",
                )
            )

        if self._is_silent(node):
            broad = node.type is None or exc_name in BROAD_EXCEPTIONS
            result.findings.append(
                ctx.make(
                    rule_id="EX002",
                    severity=Severity.HIGH if broad else Severity.MEDIUM,
                    confidence="High",
                    title="Swallowed exception",
                    message=(
                        "This handler does nothing with the error (pass / return), "
                        "permanently hiding the failure."
                    ),
                    node=node,
                    recommendation=(
                        "Log the exception, handle it meaningfully, or re-raise it."
                    ),
                    cwe="CWE-390",
                )
            )

        # EX004 - re-raising the caught name loses the original traceback context.
        for child in node.body:
            if (
                isinstance(child, ast.Raise)
                and isinstance(child.exc, ast.Name)
                and node.name
                and child.exc.id == node.name
            ):
                result.findings.append(
                    ctx.make(
                        rule_id="EX004",
                        severity=Severity.LOW,
                        confidence="Medium",
                        title="Re-raise loses original traceback",
                        message=(
                            f"'raise {node.name}' re-raises the exception but "
                            "appends a new traceback frame and hides the origin."
                        ),
                        node=child,
                        recommendation=(
                            "Use a bare 'raise' to preserve the traceback, or "
                            "'raise NewError(...) from exc' to chain explicitly."
                        ),
                        cwe="CWE-755",
                    )
                )

    def _check_raise(self, ctx: Context, node: ast.Raise, result: DetectorResult) -> None:
        exc = node.exc
        if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
            if exc.func.id in {"Exception", "BaseException"}:
                result.findings.append(
                    ctx.make(
                        rule_id="EX005",
                        severity=Severity.LOW,
                        confidence="High",
                        title="Raising generic Exception",
                        message=(
                            f"raise {exc.func.id}(...) makes it hard for callers "
                            "to catch specific failure modes."
                        ),
                        node=node,
                        recommendation=(
                            "Raise a specific, meaningful exception type, or a "
                            "custom exception subclass."
                        ),
                    )
                )

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _propagates(node: ast.ExceptHandler) -> bool:
        """True if the handler ends by re-raising (bare 'raise')."""
        return any(
            isinstance(stmt, ast.Raise) and stmt.exc is None for stmt in node.body
        )

    @staticmethod
    def _exception_name(node: ast.ExceptHandler) -> str:
        t = node.type
        if t is None:
            return ""
        if isinstance(t, ast.Name):
            return t.id
        if isinstance(t, ast.Attribute):
            return t.attr
        if isinstance(t, ast.Tuple):
            return ",".join(
                e.id for e in t.elts if isinstance(e, ast.Name)
            )
        return ""

    @staticmethod
    def _is_silent(node: ast.ExceptHandler) -> bool:
        # "Swallowed" means the handler takes no action at all. A return/raise
        # is considered deliberate handling, not swallowing.
        body = [
            n for n in node.body
            if not (
                isinstance(n, ast.Expr)
                and isinstance(n.value, ast.Constant)
                and isinstance(n.value.value, str)
            )
        ]
        if not body:
            return True
        return all(isinstance(stmt, ast.Pass) for stmt in body)
