"""Polyglot classification tests cover required suffix and SFX arrangements."""

from fixture_support import load_module, pdf_bytes, zip_bytes


def test_pdf_zip_and_script_zip_are_classified(fixture_factory):
    sig = load_module("src.signatures"); bounds = load_module("src.boundary_detector"); detector = load_module("src.polyglot_detector")
    for name, data, expected in [
        ("document.pdf", pdf_bytes() + zip_bytes({"image.jpg": b"\xff\xd8\xff\xdb\x00\x02\xff\xd9"}), "suffix_polyglot"),
        ("run.sh", b"#!/bin/sh\n# passive fixture\n" + zip_bytes({"x.txt": b"x"}), "sfx"),
    ]:
        path = fixture_factory(name, data); candidates, _ = sig.scan_signatures(path, len(data)); valid, _ = bounds.detect_boundaries(path, candidates, len(data))
        result = detector.classify_polyglot(len(data), valid)
        if expected == "sfx":
            assert "sfx" in load_module("src.sfx_analyzer").analyze_sfx(valid)[0]["type"]
        else: assert expected in result["classifications"]

