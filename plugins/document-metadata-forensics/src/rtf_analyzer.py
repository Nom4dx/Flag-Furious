"""Static RTF control-word and hidden-text analyzer."""

from __future__ import annotations

import re

from .reporting import ModuleResult


def analyze_rtf(data: bytes, source: str) -> ModuleResult:
    """Find hidden RTF text and active field indicators.

    Input: RTF bytes/source. Output: extracted hidden groups and findings. Limits:
    1,000 groups of 64 KiB. Security: fields, DDE and objects are not executed.
    Example: ``analyze_rtf(b'{\\rtf1 {\\v secret}}', "a.rtf")``.
    """
    result = ModuleResult("rtf", status="skipped")
    if not data.startswith(b"{\\rtf"):
        return result
    result.status = "completed"
    for match in list(re.finditer(rb"\{\\v\s+(.{1,65536}?)\}", data, re.S))[:1000]:
        text = re.sub(rb"\\[a-z]+-?\d* ?", b"", match.group(1)).decode("latin-1", "replace")
        result.items.append({"type": "hidden_text", "text": text, "source": source, "internal_path": "rtf:hidden", "offset": match.start(), "confidence": 0.92})
    for pattern, title in ((rb"\\field|DDEAUTO", "Campo/DDE RTF"), (rb"\\object|\\objdata", "Oggetto RTF incorporato")):
        for match in list(re.finditer(pattern, data, re.I))[:100]:
            result.findings.append({"type": "active_content", "severity": "high", "title": title, "description": "Rilevato staticamente; non eseguito", "source": source, "offset": match.start(), "confidence": 0.9})
    result.metrics = {"hidden_groups": len(result.items)}
    return result
