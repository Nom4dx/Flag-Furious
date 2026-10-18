"""Bounded IPTC-IIM scanner for JPEG/Photoshop resource payloads."""

from __future__ import annotations

from .reporting import ModuleResult


FIELDS = {5: "ObjectName", 25: "Keywords", 55: "DateCreated", 80: "Byline", 90: "City", 105: "Headline", 110: "Credit", 115: "Source", 116: "CopyrightNotice", 120: "Caption"}


def parse_iptc(data: bytes, source: str) -> ModuleResult:
    """Scan IPTC dataset markers.

    Input: bounded bytes/source. Output: known dataset values and offsets.
    Malformed lengths stop safely. Limits: 500 records, 64 KiB each. Security:
    passive byte parsing only. Example: ``parse_iptc(jpeg, "a.jpg")``.
    """
    result = ModuleResult("iptc")
    cursor = 0
    while len(result.items) < 500:
        cursor = data.find(b"\x1c\x02", cursor)
        if cursor < 0 or cursor + 5 > len(data):
            break
        dataset = data[cursor + 2]
        size = int.from_bytes(data[cursor + 3 : cursor + 5], "big")
        if size > 65536 or cursor + 5 + size > len(data):
            cursor += 2
            continue
        raw = data[cursor + 5 : cursor + 5 + size]
        value = raw.decode("utf-8", "replace").strip()
        if value:
            result.items.append({"type": "metadata_value", "namespace": "IPTC", "field": FIELDS.get(dataset, f"Dataset-{dataset}"), "raw_value": value, "normalized_value": value, "source": source, "internal_path": "iptc", "offset": cursor, "size": size, "hash": None, "parser": "iptc-iim", "decoder": None, "timestamp": value if dataset == 55 else None, "confidence": 0.85, "flag_relation": None})
        cursor += 5 + size
    result.metrics = {"values": len(result.items)}
    return result
