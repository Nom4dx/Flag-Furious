from __future__ import annotations

import hashlib
import json
import struct
import zlib
from pathlib import Path

import pytest

import app


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    body = kind + payload
    return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body))


def minimal_png(*, signature: bytes = b"\x89PNG\r\n\x1a\n") -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    pixels = zlib.compress(b"\x00\x00\x00\x00")
    return signature + png_chunk(b"IHDR", ihdr) + png_chunk(b"IDAT", pixels) + png_chunk(b"IEND", b"")


def test_hash_normalization_and_matching(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"forensic evidence")
    report = app.calculate_hashes(evidence, ("sha256",))
    expected = hashlib.sha256(b"forensic evidence").hexdigest()
    decorated = "0x" + ":".join(expected[index:index + 2] for index in range(0, len(expected), 2))
    assert app.find_hash_matches(decorated, report.digests) == ("sha256",)


def test_empty_file_is_supported(tmp_path: Path) -> None:
    evidence = tmp_path / "empty"
    evidence.write_bytes(b"")
    report = app.analyze_file(evidence)
    assert report.size == 0
    assert report.magic_preview == ""
    assert report.detections == ()


def test_damaged_png_is_detected_and_repaired_to_copy(tmp_path: Path) -> None:
    source = tmp_path / "damaged.png"
    destination = tmp_path / "repaired.png"
    damaged = minimal_png(signature=b"BROKEN!!")
    source.write_bytes(damaged)

    report = app.analyze_file(source)
    assert report.structures[0].name == "png"
    assert app.needs_magic_repair(source, report.structures)

    result = app.repair_magic_bytes(source, report.structures, destination)
    assert Path(result.output) == destination
    assert source.read_bytes() == damaged
    assert destination.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert app.check_png_raw_structure(destination.read_bytes())


def test_repair_refuses_existing_destination(tmp_path: Path) -> None:
    source = tmp_path / "damaged.png"
    destination = tmp_path / "existing.png"
    source.write_bytes(minimal_png(signature=b"BROKEN!!"))
    destination.write_bytes(b"keep me")
    structures = app.analyze_file(source).structures

    with pytest.raises(FileExistsError):
        app.repair_magic_bytes(source, structures, destination)
    assert destination.read_bytes() == b"keep me"


def test_cli_json_and_hash_mismatch_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    evidence = tmp_path / "sample.bin"
    evidence.write_bytes(b"sample")
    assert app.main([str(evidence), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["size"] == 6
    assert app.main([str(evidence), "--expect", "00"]) == 1
