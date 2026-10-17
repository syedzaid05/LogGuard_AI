"""Base classes and helpers shared by all detectors."""
from __future__ import annotations

import ast
from dataclasses import dataclass, field

from ..models import Category, Finding, Severity


@dataclass
class DetectorResult:
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


class Detector:
    """A single rule group that inspects one Python module at a time."""

    name: str = "detector"
    category: str = Category.QUALITY.value

    def run(self, tree: ast.AST, source: str, filename: str) -> DetectorResult:
        raise NotImplementedError


class Context:
    """Convenience wrapper around a parsed module."""

    def __init__(
        self,
        tree: ast.AST,
        source: str,
        filename: str,
        detector_name: str = "",
        category: str = "",
    ) -> None:
        self.tree = tree
        self.source = source
        self.filename = filename
        self.lines = source.splitlines()
        self.detector_name = detector_name
        self.category = category

    def line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def make(
        self,
        *,
        rule_id: str,
        severity: Severity,
        confidence: str,
        title: str,
        message: str,
        node: ast.AST | None = None,
        lineno: int | None = None,
        column: int = 0,
        evidence: str = "",
        recommendation: str = "",
        cwe: str = "",
        category: str | None = None,
    ) -> Finding:
        line_no = lineno or (getattr(node, "lineno", 0) if node else 0)
        col = column or (getattr(node, "col_offset", 0) if node else 0)
        code = self.line(line_no)
        return Finding(
            rule_id=rule_id,
            detector=getattr(self, "detector_name", ""),
            category=category or self.category,
            severity=severity.value,
            confidence=confidence,
            title=title,
            message=message,
            file=self.filename,
            line=line_no,
            column=col,
            code=code,
            evidence=evidence or code,
            recommendation=recommendation,
            cwe=cwe,
        )
