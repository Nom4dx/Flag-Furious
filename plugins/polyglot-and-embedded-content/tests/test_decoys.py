"""Decoy ranking preserves rejected markers and weak duplicate origins."""

from fixture_support import load_module


def test_rejected_signature_is_decoy():
    result = load_module("src.decoy_detector").detect_decoys([], [{"format": "zip", "offset": 9, "rejection_reason": "CRC errato", "confidence": .2}])
    assert result[0]["type"] == "unvalidated_signature" and result[0]["confidence"] < .5

