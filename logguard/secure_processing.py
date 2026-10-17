"""Secure Processing Layer: input validation and safe file discovery."""
from __future__ import annotations

import os
from pathlib import Path

from . import config

ALLOWED_EXTENSIONS = {".py", ".txt", ".cfg", ".ini", ".env", ".yaml", ".yml", ".json", ".toml"}
PYTHON_EXTENSIONS = {".py"}

# Paths that are almost always noise / third-party / generated / non-production.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".venv", "venv", "env", "node_modules",
    "site-packages", "dist", "build", ".eggs", "*.egg-info",
    "tests", "test", "testing", "docs", "doc", "examples", "example",
    "samples", "sample", "fixtures", "migration", "migrations", "vendor",
    "vendored", "third_party", "thirdparty", "scripts", "benchmarks",
}
SKIP_FILES = {"setup.py", "conftest.py"}
# Test/example file name patterns that are skipped even outside SKIP_DIRS.
SKIP_FILE_PATTERNS = ("test_", "tests_", "conftest", "example_", "sample_")
SKIP_FILE_SUFFIXES = ("_test.py", "_example.py", "_sample.py")


def should_skip_path(rel_path: str) -> bool:
    """True if a relative path is test/example/vendored scaffolding."""
    parts = [p for p in rel_path.replace("\\", "/").split("/") if p]
    for part in parts[:-1]:
        if part in SKIP_DIRS or part.endswith(".egg-info"):
            return True
    if not parts:
        return False
    name = parts[-1]
    if name in SKIP_FILES:
        return True
    if name.startswith(SKIP_FILE_PATTERNS):
        return True
    if name.endswith(SKIP_FILE_SUFFIXES):
        return True
    return False


class ValidationError(Exception):
    pass


def validate_upload(filename: str, size: int) -> None:
    """Validate a single uploaded artifact before processing."""
    if size <= 0:
        raise ValidationError(f"'{filename}' is empty.")
    if size > config.MAX_TOTAL_BYTES:
        raise ValidationError(
            f"'{filename}' is too large ({size} bytes). "
            f"Limit is {config.MAX_TOTAL_BYTES} bytes."
        )
    ext = Path(filename).suffix.lower()
    if ext not in {".py", ".zip", ".txt", ".md", ""}:
        raise ValidationError(f"Unsupported upload type: '{ext or filename}'.")


def is_safe_relative_path(path: str) -> bool:
    """Reject absolute paths and path traversal escapes."""
    if not path:
        return False
    normalized = os.path.normpath(path).replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith(".."):
        return False
    if os.path.isabs(path):
        return False
    return ".." not in normalized.split("/")


def _is_skipped_dir(name: str) -> bool:
    if name in SKIP_DIRS:
        return True
    return name.endswith(".egg-info")


def discover_files(root: Path) -> list[Path]:
    """Walk a directory tree and return candidate files (safe, bounded)."""
    found: list[Path] = []
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not _is_skipped_dir(d)]
        for fname in filenames:
            if Path(fname).suffix.lower() not in ALLOWED_EXTENSIONS:
                continue
            full = Path(dirpath) / fname
            if not str(full.resolve()).startswith(str(root)):
                continue
            if should_skip_path(str(full.relative_to(root))):
                continue
            found.append(full)
            if len(found) >= config.MAX_FILES:
                return found
    return found


def read_source(path: Path) -> str | None:
    """Read a file as text with size/line guards. Returns None if unusable."""
    try:
        if path.stat().st_size > config.MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:2048]:  # binary
        return None
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if len(lines) > config.MAX_FILE_LINES:
        text = "\n".join(lines[: config.MAX_FILE_LINES])
    return text
