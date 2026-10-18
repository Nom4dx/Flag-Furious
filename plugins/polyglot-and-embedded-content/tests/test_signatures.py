"""Signature inventory tests prove block scanning and secondary markers."""

from fixture_support import load_module, png_bytes, zip_bytes


def test_multiple_signatures_are_inventory_only(fixture_factory):
    module = load_module("src.signatures")
    path = fixture_factory("mixed.bin", png_bytes() + zip_bytes({"x": b"data"}))
    found, truncated = module.scan_signatures(path, path.stat().st_size)
    assert not truncated
    assert {x["format"] for x in found} >= {"png", "zip", "zip_central_directory", "zip_eocd"}

