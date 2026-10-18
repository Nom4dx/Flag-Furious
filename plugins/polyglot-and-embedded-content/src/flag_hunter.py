"""Provenance-aware flag discovery and confidence classification."""

from __future__ import annotations

import re


def hunt_flags(sources: list[dict], prefixes: list[str], max_results: int = 256) -> list[dict]:
    """Search raw/decoded sources using configured prefixes and generic CTF syntax.

    Each source must include bytes, provenance and structural confidence. Output
    is deduplicated by value plus origin and classified by chain validity. Regex
    lengths are capped to prevent runaway matches; bytes remain passive.
    """
    escaped = [re.escape(p.encode()) for p in prefixes if p]
    patterns = [re.compile(part + rb"\{[^\x00\r\n{}]{1,512}\}", 0) for part in escaped]
    if not patterns:
        patterns = [re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,31}\{[^\x00\r\n{}]{1,512}\}")]
    found, seen = [], set()
    for source in sources:
        data = source.get("data", b"")
        if not isinstance(data, bytes): continue
        for encoding, view in (("utf-8/raw", data), ("utf-16le", data[::2] if data[1::2].count(0) > len(data) // 8 else b"")):
            for pattern in patterns:
                for match in pattern.finditer(view):
                    value = match.group().decode("utf-8", "replace")
                    key = (value, source.get("source"), match.start())
                    if key in seen: continue
                    seen.add(key)
                    structural = float(source.get("confidence", .4))
                    decoded = bool(source.get("decoder"))
                    classification = "confirmed" if structural >= .98 and not decoded else "high_confidence" if structural >= .85 else "candidate" if structural >= .55 else "suspicious"
                    confidence = min(.99, structural + (.04 if decoded and structural >= .7 else 0))
                    found.append({
                        "value": value, "classification": classification, "confidence": round(confidence, 3),
                        "source": source.get("source", "input"), "artifact_id": source.get("artifact_id"),
                        "format": source.get("format"), "offset": source.get("base_offset", 0) + match.start() * (2 if encoding == "utf-16le" else 1),
                        "decoder": source.get("decoder", encoding), "extraction_chain": source.get("chain", []),
                        "context": view[max(0, match.start() - 24):match.end() + 24].decode("utf-8", "replace"),
                        "reasons": ["prefisso e parentesi coerenti", "origine strutturalmente validata" if structural >= .85 else "origine non pienamente validata"],
                    })
                    if len(found) >= max_results: return found
    return found

