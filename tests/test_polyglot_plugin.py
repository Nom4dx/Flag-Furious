"""End-to-end hub contract test for the polyglot plugin."""

import hashlib
import io
import struct
import zipfile
import zlib
from pathlib import Path

from test_hub import start, upload


def _png() -> bytes:
    """Return a valid one-pixel PNG with correct CRCs."""
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk(b"IEND", b"")


def test_polyglot_plugin_end_to_end(client, case):
    """A PNG→ZIP job validates both ranges and links an internal flag."""
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr("evidence/flag.txt", b"BVAULT{polyglot_fixture}")
    evidence = _png() + archive.getvalue()
    asset = upload(client, case, evidence, "polyglot.png")
    original = Path(client.app.state.store.get("asset", asset["id"])["path"])
    before = hashlib.sha256(original.read_bytes()).hexdigest()
    job = start(client, case, asset, ["polyglot-and-embedded-content"], prefixes=["BVAULT"], recursive=False)
    results = client.get(f"/api/jobs/{job['id']}/results").json()
    result = next(item for item in results if item["plugin_id"] == "polyglot-and-embedded-content")
    assert result["status"] == "completed", result["warnings"]
    validated = next(x for x in result["sections"] if x["id"] == "validated_formats")["items"]
    assert {x["format"] for x in validated} == {"png", "zip"}
    assert any(x["value"] == "BVAULT{polyglot_fixture}" and "flag.txt" in x["source"] for x in result["flags"])
    assert {x["type"] for x in result["visualizations"]} == {"offset_map", "graph"}
    assert result["artifacts"] and result["presentation"]["groups"]
    assert client.get(f"/api/artifacts/{result['artifacts'][0]['id']}/preview").status_code == 200
    assert hashlib.sha256(original.read_bytes()).hexdigest() == before

