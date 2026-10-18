"""Coordinator for PDF structure, revisions, layers and static content."""

from __future__ import annotations

import re

from .pdf_layers import analyze_layers
from .pdf_objects import analyze_objects
from .pdf_revisions import analyze_revisions
from .reporting import ModuleResult


def analyze_pdf(data: bytes, source: str) -> ModuleResult:
    """Analyze a PDF without execution or rendering.

    Input: bytes/source. Output: merged PDF evidence. Non-PDF input is skipped.
    Limits and exceptions are documented by child parsers. Security: active PDF
    actions are only inventoried. Example: ``analyze_pdf(data, "a.pdf")``.
    """
    result = ModuleResult("pdf", status="skipped")
    if not data.startswith(b"%PDF-"):
        return result
    result.status = "completed"
    version = data[5:8].decode("ascii", "replace")
    result.items.append({"type": "pdf_header", "version": version, "source": source, "offset": 0})
    if re.search(rb"pdfaid:(?:part|conformance)", data, re.I):
        result.items.append({"type": "pdf_profile", "profile": "PDF/A metadata present", "source": source})
    for child in (analyze_revisions(data, source), analyze_objects(data, source), analyze_layers(data, source)):
        result.items.extend(child.items)
        result.findings.extend(child.findings)
        result.artifacts.extend(child.artifacts)
        result.warnings.extend(child.warnings)
        result.metrics[child.name] = child.metrics
    return result
