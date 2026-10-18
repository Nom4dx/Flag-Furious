"""Cross-format hidden-content heuristics with exact provenance."""

from __future__ import annotations

import re

from .reporting import ModuleResult

TEXT_SCAN_LIMIT = 8 * 1024**2


def analyze_hidden(data: bytes, source: str) -> ModuleResult:
    """Detect zero-width channels, appended containers and suspicious whitespace.

    Input: bounded bytes/source. Output: decoded zero-width candidates and offset
    findings. Limits: 1 MiB decoded text, 1,000 signatures. Security: extracted
    bytes remain passive. Example: ``analyze_hidden(text.encode(), "a.txt")``.
    """
    result = ModuleResult("hidden_content")
    text_view = data[:TEXT_SCAN_LIMIT]
    text = text_view.decode("utf-8", "replace")
    if len(data) > len(text_view):
        result.status = "partial"
        result.warnings.append(
            f"Controlli testo invisibile e whitespace limitati a {len(text_view)} byte su {len(data)}."
        )
    bits = "".join("0" if c == "\u200b" else "1" for c in text if c in "\u200b\u200c")
    if len(bits) >= 8:
        decoded = bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits) - 7, 8))
        result.items.append({"type": "hidden_payload", "encoding": "zero-width U+200B/U+200C", "raw_value": bits, "normalized_value": decoded.decode("utf-8", "replace"), "source": source, "offset": next((i for i, c in enumerate(text) if c in "\u200b\u200c"), 0), "size": len(bits), "parser": "zero-width", "decoder": "binary", "confidence": 0.98})
    for signature, name in ((b"PK\x03\x04", "ZIP"), (b"%PDF-", "PDF"), (b"\xff\xd8\xff", "JPEG")):
        offsets = [m.start() for m in re.finditer(re.escape(signature), data)][:1000]
        for offset in offsets[1:] if data.startswith(signature) else offsets:
            result.findings.append({"type": "embedded_signature", "severity": "medium", "title": f"Firma {name} incorporata", "description": "Possibile documento o payload annidato", "source": source, "offset": offset, "confidence": 0.82})
    trailing_spaces = len(re.findall(rb"[ \t]+(?=\r?$)", text_view, re.M))
    if trailing_spaces > 16:
        result.findings.append({"type": "whitespace_channel", "severity": "low", "title": "Pattern di whitespace", "description": f"{trailing_spaces} sequenze a fine riga", "source": source, "offset": 0, "confidence": 0.55, "classification": "suspicious"})
    result.metrics = {
        "zero_width_bits": len(bits), "items": len(result.items), "findings": len(result.findings),
        "text_scan_bytes": len(text_view), "text_scan_limit": TEXT_SCAN_LIMIT,
        "text_scan_truncated": len(text_view) < len(data),
        "signature_scan_bytes": len(data),
    }
    return result
