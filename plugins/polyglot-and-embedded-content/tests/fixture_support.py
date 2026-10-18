"""Synthetic, deterministic fixture builders for polyglot regression tests."""

from __future__ import annotations

import io
import struct
import sys
import types
import importlib.util
import zipfile
import zlib
from pathlib import Path

import pytest

PLUGIN = Path(__file__).parents[1]
package = types.ModuleType("polyglot_test_plugin")
package.__path__ = [str(PLUGIN)]
sys.modules.setdefault("polyglot_test_plugin", package)


def load_module(name: str):
    """Load a plugin module under a package name so relative imports work."""
    qualified = f"polyglot_test_plugin.{name}"
    path = PLUGIN / (name.replace(".", "/") + ".py")
    spec = importlib.util.spec_from_file_location(qualified, path)
    module = importlib.util.module_from_spec(spec); sys.modules[qualified] = module; spec.loader.exec_module(module)
    return module


def zip_bytes(entries: dict[str, bytes], stored: bool = False) -> bytes:
    """Build a valid ZIP entirely in memory for immutable test fixtures."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items(): archive.writestr(name, data)
    return output.getvalue()


def png_bytes(custom: tuple[bytes, bytes] | None = None) -> bytes:
    """Build a 1×1 RGB PNG with valid chunk CRCs and optional custom chunk."""
    def chunk(kind, data): return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
    parts = [b"\x89PNG\r\n\x1a\n", chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))]
    if custom: parts.append(chunk(*custom))
    parts.extend([chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")), chunk(b"IEND", b"")])
    return b"".join(parts)


def jpeg_bytes(app_payload: bytes = b"") -> bytes:
    """Build a minimal marker-valid JPEG envelope with optional APP1 payload."""
    app = b"\xff\xe1" + struct.pack(">H", len(app_payload) + 2) + app_payload if app_payload else b""
    return b"\xff\xd8" + app + b"\xff\xdb\x00\x02" + b"\xff\xd9"


def pdf_bytes(extra_stream: bytes = b"") -> bytes:
    """Build a small PDF whose startxref points to a real xref table."""
    head = b"%PDF-1.4\n1 0 obj\n<< /Length 0 >>\nstream\n" + extra_stream + b"\nendstream\nendobj\n"
    xref = len(head)
    return head + b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n" + str(xref).encode() + b"\n%%EOF\n"


@pytest.fixture
def fixture_factory(tmp_path):
    """Return a writer that places generated evidence in a temporary directory."""
    def write(name: str, data: bytes) -> Path:
        path = tmp_path / name; path.write_bytes(data); return path
    return write

