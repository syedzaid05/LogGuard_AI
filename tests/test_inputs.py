"""Input Manager and Secure Processing tests."""
import io
import zipfile

import pytest

from logguard import input_manager, secure_processing
from logguard.secure_processing import ValidationError


def test_from_text_empty_raises():
    with pytest.raises(ValidationError):
        input_manager.from_text("   ")


def test_from_text_ok():
    bundle = input_manager.from_text("x = 1\n", "a.py")
    assert bundle.files == {"a.py": "x = 1\n"}


def _make_zip(entries: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buffer.getvalue()


def test_from_zip_keeps_python_skips_tests():
    data = _make_zip(
        {
            "proj/app.py": "x = 1\n",
            "proj/tests/test_app.py": "def test_x():\n    assert True\n",
            "proj/README.md": "# hi\n",
        }
    )
    bundle = input_manager.from_uploaded_file("proj.zip", data)
    assert "app.py" in bundle.files
    assert all("test_" not in name for name in bundle.files)


def test_from_zip_rejects_traversal():
    data = _make_zip({"../evil.py": "x = 1\n"})
    with pytest.raises(ValidationError):
        input_manager.from_uploaded_file("evil.zip", data)


def test_upload_rejects_bad_extension():
    with pytest.raises(ValidationError):
        input_manager.from_uploaded_file("image.png", b"\x89PNG")


def test_upload_rejects_empty():
    with pytest.raises(ValidationError):
        input_manager.from_uploaded_file("a.py", b"")


def test_from_directory_relative_path(tmp_path, monkeypatch):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "pkg" / "tests").mkdir()
    (tmp_path / "pkg" / "tests" / "test_mod.py").write_text("y = 2\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    bundle = input_manager.from_directory("pkg")
    assert "mod.py" in bundle.files
    assert "tests/test_mod.py" not in bundle.files


@pytest.mark.parametrize(
    "path,safe",
    [
        ("a/b.py", True),
        ("../b.py", False),
        ("/abs.py", False),
        ("a/../../b.py", False),
        ("", False),
    ],
)
def test_is_safe_relative_path(path, safe):
    assert secure_processing.is_safe_relative_path(path) is safe


@pytest.mark.parametrize(
    "path,skip",
    [
        ("pkg/tests/test_x.py", True),
        ("pkg/app.py", False),
        ("node_modules/x/y.py", True),
        ("pkg/__pycache__/x.py", True),
        ("pkg/example_demo.py", True),
        ("pkg/conftest.py", True),
    ],
)
def test_should_skip_path(path, skip):
    assert secure_processing.should_skip_path(path) is skip
