"""Static HTML, MHTML, XML and JSON metadata inventory."""

from __future__ import annotations

import json
import re

from .reporting import ModuleResult


def analyze_structured(data: bytes, source: str) -> ModuleResult:
    """Extract passive metadata from text-based document formats.

    Input: bytes/source. Output: title/meta/comment/JSON values and active-content
    findings. Limits: first 16 MiB and 2,000 records. Security: HTML/XML is never
    rendered and URLs are not visited. Example: ``analyze_structured(html, "a.html")``.
    """
    result = ModuleResult("structured_text", status="skipped")
    text = data[:16 * 1024**2].decode("utf-8", "replace")
    lower = text[:65536].lower()
    if "<html" in lower or "<!doctype html" in lower or "content-type: multipart/related" in lower:
        result.status = "completed"
        for match in list(re.finditer(r"<(title|meta)\b([^>]*)>(?:([^<]*)</title>)?", text, re.I | re.S))[:2000]:
            value = match.group(3) or match.group(2)
            result.items.append(_item("HTML", match.group(1), value, source, match.start()))
        if re.search(r"<script\b|\bon\w+\s*=|javascript:", text, re.I):
            result.findings.append({"type": "active_html", "severity": "high", "title": "Contenuto HTML attivo", "description": "Script/event handler rilevato e non eseguito", "source": source, "offset": 0, "confidence": 0.9})
    elif lower.lstrip().startswith("<?xml"):
        result.status = "completed"
        for match in list(re.finditer(r"<!--(.*?)-->", text, re.S))[:1000]:
            result.items.append(_item("XML", "Comment", match.group(1).strip(), source, match.start()))
    elif text.lstrip().startswith(("{", "[")):
        try:
            value = json.loads(text)
            result.status = "completed"
            _flatten_json(value, "$", source, result)
        except json.JSONDecodeError:
            pass
    result.metrics = {"items": len(result.items)}
    return result


def _flatten_json(value, path: str, source: str, result: ModuleResult) -> None:
    """Flatten at most 2,000 JSON scalar values with JSONPath-like provenance."""
    if len(result.items) >= 2000:
        return
    if isinstance(value, dict):
        for key, child in value.items(): _flatten_json(child, f"{path}.{key}", source, result)
    elif isinstance(value, list):
        for index, child in enumerate(value): _flatten_json(child, f"{path}[{index}]", source, result)
    elif value is not None:
        result.items.append(_item("JSON", path, str(value), source, None))


def _item(namespace, field, value, source, offset):
    """Normalize a structured text scalar with safe plain-text values."""
    return {"type": "metadata_value", "namespace": namespace, "field": field, "raw_value": value, "normalized_value": str(value).strip(), "source": source, "internal_path": namespace.lower(), "offset": offset, "size": len(str(value).encode()), "hash": None, "parser": f"{namespace.lower()}-static", "decoder": None, "timestamp": None, "confidence": 0.8, "flag_relation": None}
