"""Payload tests verify bounded Base64, hex and Brainfuck transformations."""

import base64
from src.flag_hunter import hunt_flags
from src.payload_decoder import decode_payloads


def test_base64_hex_and_flag_provenance():
    flag = "BVAULT{decoded}"
    items = [
        {
            "normalized_value": base64.b64encode(flag.encode()).decode(),
            "source": "xmp",
            "offset": 12,
            "confidence": 0.9,
        },
        {"normalized_value": flag.encode().hex(), "source": "comment", "offset": 30},
    ]
    decoded = decode_payloads(items, "x.pdf").items
    assert sum(x["normalized_value"] == flag for x in decoded) == 2
    flags = hunt_flags(decoded, ["BVAULT"], "x.pdf").items
    assert flags and all(x["classification"] == "high_confidence" for x in flags)


def test_brainfuck_decoder():
    # A bounded program that emits ASCII A.
    result = decode_payloads([{"normalized_value": "+" * 65 + ".", "source": "exif"}], "x.jpg")
    assert result.items[0]["normalized_value"] == "A"
