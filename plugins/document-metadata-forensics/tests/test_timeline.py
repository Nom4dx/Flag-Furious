"""Timeline and inconsistency tests retain raw values and normalized dates."""

from src.inconsistencies import find_inconsistencies
from src.timeline import build_timeline


def test_timeline_and_conflicting_authors():
    items = [
        {"field": "Created", "normalized_value": "2026-09-12T10:00:00Z", "source": "xmp", "confidence": 0.9},
        {"field": "Author", "normalized_value": "Alice", "namespace": "XMP"},
        {"field": "Creator", "normalized_value": "Bob", "namespace": "PDF"},
    ]
    timeline = build_timeline(items, "x.pdf").timeline
    assert timeline[0]["timestamp"].endswith("+00:00") and timeline[0]["raw_value"].endswith("Z")
    assert find_inconsistencies(items, "x.pdf").findings[0]["type"] == "metadata_inconsistency"
