"""PDF incremental revision and trailing-data analysis."""

from __future__ import annotations

import re

from .reporting import ModuleResult


def analyze_revisions(data: bytes, source: str) -> ModuleResult:
    """Locate PDF EOF/startxref markers and post-EOF bytes.

    Input: bounded PDF bytes/source. Output: revision markers and suspicious
    trailing data. Limits: 256 revisions. Security: bytes are never repaired or
    rendered. Example: ``analyze_revisions(pdf, "a.pdf")``.
    """
    result = ModuleResult("pdf_revisions")
    eof = [m.start() for m in re.finditer(rb"%%EOF", data)][-256:]
    starts = [m.start() for m in re.finditer(rb"startxref\s+(\d+)", data)][-256:]
    for index, offset in enumerate(eof):
        result.items.append({"revision": index + 1, "eof_offset": offset, "source": source})
    if len(eof) > 1:
        result.findings.append({"type": "incremental_revisions", "severity": "info", "title": "Revisioni PDF incrementali", "description": f"Rilevati {len(eof)} marcatori %%EOF", "source": source, "offset": eof[1], "confidence": 0.95})
    if eof:
        tail = data[eof[-1] + 5 :]
        meaningful = tail.strip(b"\x00\t\r\n ")
        if meaningful:
            offset = eof[-1] + 5 + len(tail) - len(tail.lstrip(b"\x00\t\r\n "))
            result.findings.append({"type": "post_eof_data", "severity": "high", "title": "Dati dopo %%EOF", "description": f"{len(meaningful)} byte non vuoti dopo l'ultimo EOF", "source": source, "offset": offset, "size": len(meaningful), "confidence": 0.98})
    result.metrics = {"eof_markers": len(eof), "startxref_markers": len(starts)}
    return result
