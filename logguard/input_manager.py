"""Input Manager: normalises single files, ZIP projects, pasted code and repos
into a common ``SourceBundle`` (relative path -> source text)."""
from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import config, secure_processing
from .secure_processing import ValidationError


@dataclass
class SourceBundle:
    name: str = "input"
    files: dict[str, str] = field(default_factory=dict)

    def add(self, rel_path: str, content: str) -> None:
        rel_path = rel_path.replace("\\", "/").lstrip("/")
        self.files[rel_path] = content

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def byte_size(self) -> int:
        return sum(len(v.encode("utf-8", "ignore")) for v in self.files.values())


def from_text(code: str, filename: str = "pasted_code.py") -> SourceBundle:
    if not code or not code.strip():
        raise ValidationError("No code was provided.")
    bundle = SourceBundle(name=filename)
    bundle.add(filename, code)
    return bundle


def from_uploaded_file(filename: str, data: bytes) -> SourceBundle:
    secure_processing.validate_upload(filename, len(data))
    suffix = Path(filename).suffix.lower()

    if suffix == ".zip":
        return _from_zip(filename, data)

    if suffix == ".py":
        bundle = SourceBundle(name=filename)
        bundle.add(filename, data.decode("utf-8", errors="replace"))
        return bundle

    # Generic text upload: keep as-is, marked non-python.
    bundle = SourceBundle(name=filename)
    bundle.add(filename, data.decode("utf-8", errors="replace"))
    return bundle


def from_directory(root: str | Path) -> SourceBundle:
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValidationError(f"Not a directory: {root}")
    bundle = SourceBundle(name=root.name or "local")
    total = 0
    for path in secure_processing.discover_files(root):
        content = secure_processing.read_source(path)
        if content is None:
            continue
        total += len(content.encode("utf-8", "ignore"))
        if total > config.MAX_TOTAL_BYTES:
            break
        bundle.add(str(path.relative_to(root)), content)
    return bundle


def _from_zip(filename: str, data: bytes) -> SourceBundle:
    bundle = SourceBundle(name=Path(filename).stem or "archive")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ValidationError("Uploaded file is not a valid ZIP archive.") from exc

    total = 0
    for info in zf.infolist():
        if info.is_dir():
            continue
        if not secure_processing.is_safe_relative_path(info.filename):
            continue
        if secure_processing.should_skip_path(info.filename):
            continue
        if info.file_size > config.MAX_FILE_BYTES:
            continue
        if Path(info.filename).suffix.lower() not in secure_processing.ALLOWED_EXTENSIONS:
            continue
        try:
            raw = zf.read(info)
        except (zipfile.BadZipFile, OSError):
            continue
        if b"\x00" in raw[:2048]:
            continue
        content = raw.decode("utf-8", errors="replace")
        total += len(content.encode("utf-8", "ignore"))
        if total > config.MAX_TOTAL_BYTES:
            break
        # Strip a single common top-level folder (GitHub-style archives).
        bundle.add(info.filename, content)
        if bundle.file_count >= config.MAX_FILES:
            break

    if bundle.file_count == 0:
        raise ValidationError("ZIP archive contained no analysable files.")
    _strip_common_prefix(bundle)
    return bundle


def _strip_common_prefix(bundle: SourceBundle) -> None:
    """Remove a shared leading directory so paths stay readable."""
    keys = list(bundle.files)
    if len(keys) < 1:
        return
    first_parts = keys[0].split("/")
    if len(first_parts) < 2:
        return
    prefix = first_parts[0] + "/"
    if all(k.startswith(prefix) for k in keys):
        bundle.files = {k[len(prefix):]: v for k, v in bundle.files.items()}
