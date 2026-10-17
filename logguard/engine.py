"""Static Analysis Engine: orchestrates detectors across a SourceBundle."""
from __future__ import annotations

import ast
from pathlib import Path

from . import risk_engine
from .detectors import DETECTORS, SecretScanner
from .input_manager import SourceBundle
from .models import Finding, ScanResult
from .secure_processing import PYTHON_EXTENSIONS


def scan(bundle: SourceBundle, progress=None) -> ScanResult:
    """Run the full analysis over a bundle and return a ranked ScanResult."""
    result = ScanResult(target=bundle.name)
    raw: list[Finding] = []

    files = list(bundle.files.items())
    for index, (rel_path, content) in enumerate(files):
        if progress is not None:
            progress(index, len(files), rel_path)

        if Path(rel_path).suffix.lower() in PYTHON_EXTENSIONS:
            raw.extend(_scan_python(rel_path, content, result))
            result.lines_scanned += len(content.splitlines())
        else:
            # Non-Python files: only secret scanning applies.
            raw.extend(_scan_text(rel_path, content))
        result.files_scanned += 1

    result.findings = risk_engine.rank(risk_engine.deduplicate(raw))
    return result


def _scan_python(rel_path: str, content: str, result: ScanResult) -> list[Finding]:
    try:
        tree = ast.parse(content, filename=rel_path)
    except SyntaxError as exc:
        result.errors.append(
            f"{rel_path}:{exc.lineno or '?'}: {exc.msg} (file skipped)"
        )
        # Still run secret scanning on unparseable files.
        return _scan_text(rel_path, content)

    findings: list[Finding] = []
    for detector_cls in DETECTORS:
        detector = detector_cls()
        try:
            findings.extend(detector.run(tree, content, rel_path).findings)
        except Exception as exc:  # noqa: BLE001 - keep scanning other detectors
            result.errors.append(f"{rel_path}: {detector.name} failed: {exc}")
    return _apply_noqa(findings)


def _scan_text(rel_path: str, content: str) -> list[Finding]:
    scanner = SecretScanner()
    found = scanner.run(ast.Module(body=[], type_ignores=[]), content, rel_path).findings
    return _apply_noqa(found)


def _apply_noqa(findings: list[Finding]) -> list[Finding]:
    """Drop findings on lines carrying a '# noqa' suppression comment."""
    kept: list[Finding] = []
    for f in findings:
        if "noqa" in f.code.lower():
            continue
        kept.append(f)
    return kept
