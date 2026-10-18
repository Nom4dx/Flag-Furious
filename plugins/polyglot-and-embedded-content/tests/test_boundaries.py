"""Boundary tests distinguish random markers from validated structures."""

from fixture_support import load_module, png_bytes, zip_bytes


def test_png_zip_boundaries_and_random_zip_rejection(fixture_factory):
    signatures = load_module("src.signatures"); boundaries = load_module("src.boundary_detector")
    png = png_bytes(); archive = zip_bytes({"flag.txt": b"FLAG{nested}"})
    path = fixture_factory("poly.png", png + archive + b"random PK\x03\x04 noise")
    candidates, _ = signatures.scan_signatures(path, path.stat().st_size)
    valid, rejected = boundaries.detect_boundaries(path, candidates, path.stat().st_size)
    assert [(x["format"], x["start_offset"]) for x in valid] == [("png", 0), ("zip", len(png))]
    assert any(x["format"] == "zip" and "EOCD" in x["rejection_reason"] for x in rejected)


def test_damaged_central_directory_uses_partial_recovery(fixture_factory):
    """Local headers are inventoried but never promoted after EOCD corruption."""
    raw = bytearray(zip_bytes({"recover.txt": b"passive"}))
    eocd = raw.rfind(b"PK\x05\x06")
    raw[eocd + 16:eocd + 20] = (0xFFFFFF00).to_bytes(4, "little")
    path = fixture_factory("damaged.zip", bytes(raw))
    signatures = load_module("src.signatures"); boundaries = load_module("src.boundary_detector")
    candidates, _ = signatures.scan_signatures(path, len(raw)); valid, rejected = boundaries.detect_boundaries(path, candidates, len(raw))
    assert not any(x["format"] == "zip" for x in valid)
    root = next(x for x in rejected if x["format"] == "zip")
    recovery = load_module("src.archive_analyzer").recover_zip_local_headers(path, root, len(raw))
    assert recovery["status"] == "partial" and recovery["entries"][0]["name"] == "recover.txt"


def test_overlay_distinguishes_padding(fixture_factory):
    """Uniform bytes after a logical PNG end are labeled padding, not a format."""
    raw = png_bytes() + b"\x00" * 128; path = fixture_factory("padding.png", raw)
    signatures = load_module("src.signatures"); boundaries = load_module("src.boundary_detector")
    candidates, _ = signatures.scan_signatures(path, len(raw)); valid, _ = boundaries.detect_boundaries(path, candidates, len(raw))
    overlay = load_module("src.overlay_analyzer").analyze_overlay(len(raw), valid, candidates, path)
    assert overlay[0]["content_nature"] == "padding"
