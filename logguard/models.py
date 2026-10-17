"""Shared data models."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def rank(self) -> int:
        return {
            "Critical": 5,
            "High": 4,
            "Medium": 3,
            "Low": 2,
            "Info": 1,
        }[self.value]


class Category(str, Enum):
    LOGGING = "Logging"
    EXCEPTION = "Exception Handling"
    SECRET = "Secrets"
    QUALITY = "Code Quality"


@dataclass
class Finding:
    rule_id: str
    detector: str
    category: str
    severity: str
    confidence: str
    title: str
    message: str
    file: str
    line: int
    column: int = 0
    code: str = ""
    evidence: str = ""
    recommendation: str = ""
    cwe: str = ""
    ai_explanation: str = ""
    ai_fix: str = ""

    @property
    def fingerprint(self) -> str:
        raw = f"{self.rule_id}:{self.file}:{self.line}:{(self.evidence or self.title)}"
        return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["id"] = self.fingerprint
        return data


@dataclass
class ScanResult:
    target: str = ""
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        counts["Total"] = len(self.findings)
        return counts
