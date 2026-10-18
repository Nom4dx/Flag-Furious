"""PDF layer and visually hidden text heuristics."""

from __future__ import annotations

import re

from .reporting import ModuleResult


def analyze_layers(data: bytes, source: str) -> ModuleResult:
    """Find optional-content groups, clipping and invisible text states.

    Input: PDF bytes/source. Output: heuristic findings with exact offsets.
    Limits: 1,000 matches. Security: no rendering. False positives remain
    ``suspicious`` findings. Example: ``analyze_layers(pdf, "x.pdf")``.
    """
    result = ModuleResult("pdf_layers")
    rules = [
        (rb"/OCG\b|/OCProperties\b", "optional_content", "Layer PDF / contenuto opzionale"),
        (rb"\b3\s+Tr\b", "invisible_render_mode", "Testo con rendering invisibile"),
        (rb"(?:^|\s)0(?:\.0+)?\s+0(?:\.0+)?\s+0(?:\.0+)?\s+0(?:\.0+)?\s+k\b", "transparent_color", "Possibile colore trasparente"),
        (rb"(?:^|\s)1(?:\.0+)?\s+1(?:\.0+)?\s+1(?:\.0+)?\s+(?:rg|g)\b", "white_text", "Testo/riempimento bianco"),
    ]
    for pattern, kind, title in rules:
        for match in list(re.finditer(pattern, data, re.M))[:1000]:
            result.findings.append({"type": kind, "severity": "medium", "title": title, "description": "Indicatore visuale statico; verificare il contesto grafico", "source": source, "offset": match.start(), "confidence": 0.65, "classification": "suspicious"})
    result.metrics = {"indicators": len(result.findings)}
    return result
