"""Regression cases for the required common polyglot arrangements."""

from fixture_support import jpeg_bytes, load_module, png_bytes, zip_bytes


def _validated(path):
    """Return validated boundaries and rejected candidates for a fixture."""
    sig = load_module("src.signatures"); bd = load_module("src.boundary_detector")
    candidates, _ = sig.scan_signatures(path, path.stat().st_size)
    return bd.detect_boundaries(path, candidates, path.stat().st_size)


def test_jpeg_followed_by_zip(fixture_factory):
    jpeg = jpeg_bytes(); path = fixture_factory("misleading.txt", jpeg + zip_bytes({"inside.py": b"print('passive')"}))
    valid, _ = _validated(path)
    assert [(x["format"], x["start_offset"]) for x in valid] == [("jpeg", 0), ("zip", len(jpeg))]


def test_zip_contains_script_and_nested_archive(fixture_factory):
    inner = zip_bytes({"flag.txt": b"FLAG{deep}"})
    path = fixture_factory("outer.zip", zip_bytes({"run.js": b"const x = 'never execute';", "inner.zip": inner}))
    valid, _ = _validated(path)
    assert len(valid) == 1 and valid[0]["format"] == "zip"
    # Member types are intentionally analyzed as derived assets by the hub; the
    # outer validator proves the archive before any extraction takes place.
    assert {x["name"] for x in valid[0]["details"]["members"]} == {"run.js", "inner.zip"}


def test_corrupt_png_crc_is_signature_not_format(fixture_factory):
    data = bytearray(png_bytes()); data[-1] ^= 0xFF
    path = fixture_factory("bad.png", bytes(data)); valid, rejected = _validated(path)
    assert not any(x["format"] == "png" for x in valid)
    assert any(x["format"] == "png" and "CRC" in x["rejection_reason"] for x in rejected)


def test_python_and_javascript_without_shebang_are_recognized(fixture_factory):
    for name, raw, expected in [
        ("a.py", b"import base64\ndef main():\n    return 1\n", "python_script"),
        ("a.js", b"const value = 'passive';\nfunction f() { return value; }\n", "javascript"),
    ]:
        path = fixture_factory(name, raw); valid, _ = _validated(path)
        assert any(x["format"] == expected for x in valid)

