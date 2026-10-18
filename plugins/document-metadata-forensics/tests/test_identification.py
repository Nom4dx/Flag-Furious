"""Identification tests prove magic-first, bounded matching."""

from src.identification import identify


def test_magic_and_polyglot_identification(pdf_fixture):
    result = identify(pdf_fixture + b"PK\x03\x04", "wrong.bin")
    assert result.items[0]["format"] == "pdf"
    assert result.findings[0]["type"] == "format_inconsistency"


def test_png_identification(png_fixture):
    assert identify(png_fixture, "image.png").items[0]["format"] == "png"
