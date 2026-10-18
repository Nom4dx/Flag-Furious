"""OLE tests verify safe fallback and optional stream parsing."""

from src.ole_analyzer import OLE_MAGIC, analyze_ole


def test_malformed_ole_is_partial_not_exception():
    result = analyze_ole(OLE_MAGIC + b"\x00" * 512, "fixture.doc")
    assert result.status == "partial"
    assert result.warnings
