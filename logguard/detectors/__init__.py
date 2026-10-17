"""Detector registry (Static Analysis Engine)."""
from __future__ import annotations

from .base import Detector, DetectorResult
from .code_quality import CodeQualityDetector
from .exception_analyzer import ExceptionAnalyzer
from .logging_detector import LoggingDetector
from .secret_scanner import SecretScanner
from .web_security import WebSecurityDetector

DETECTORS: list[type[Detector]] = [
    LoggingDetector,
    ExceptionAnalyzer,
    SecretScanner,
    CodeQualityDetector,
    WebSecurityDetector,
]

__all__ = [
    "Detector",
    "DetectorResult",
    "LoggingDetector",
    "ExceptionAnalyzer",
    "SecretScanner",
    "CodeQualityDetector",
    "WebSecurityDetector",
    "DETECTORS",
]
