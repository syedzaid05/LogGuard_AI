import pytest

from logguard.engine import scan
from logguard.input_manager import from_text


@pytest.fixture
def scan_code():
    """Scan a Python source string and return the ScanResult."""
    def _scan(code: str, name: str = "module.py"):
        return scan(from_text(code, name))

    return _scan


@pytest.fixture
def rules(scan_code):
    """Scan a Python source string and return the set of rule IDs."""
    def _rules(code: str):
        return {f.rule_id for f in scan_code(code).findings}

    return _rules
