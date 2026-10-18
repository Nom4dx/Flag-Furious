"""Metadata coordinator for common document fields and namespaces."""

from __future__ import annotations

import re

from .exif_parser import parse_exif
from .iptc_parser import parse_iptc
from .reporting import ModuleResult
from .xmp_parser import parse_xmp


FIELDS = rb"(?:Author|Creator|CreatorTool|Producer|Title|Subject|Keywords|Company|Manager|LastModifiedBy|Description|Comment|License|Copyright)"


def extract_metadata(data: bytes, source: str) -> ModuleResult:
    """Combine EXIF, XMP, IPTC and conservative inline properties.

    Input: bytes/source. Output: deduplicated provenance records. Individual parser
    warnings are retained. Limits: 4,000 final values. Security: no active content.
    Example: ``extract_metadata(data, "briefing.pdf")``.
    """
    result = ModuleResult("metadata")
    children = [parse_exif(data, source), parse_xmp(data, source), parse_iptc(data, source)]
    for child in children:
        result.items.extend(child.items)
        result.warnings.extend(child.warnings)
    for match in re.finditer(rb"/((?:" + FIELDS + rb"))\s*(?:\((?:\\.|[^)])*\)|<[^>]{1,8192}>)", data[:32 * 1024**2], re.I):
        token = match.group(0).split(None, 1)[1]
        value = _pdf_value(token)
        result.items.append({"type": "metadata_value", "namespace": "PDF-Info", "field": match.group(1).decode("ascii", "replace"), "raw_value": value, "normalized_value": value.strip(), "source": source, "internal_path": "pdf:info", "offset": match.start(), "size": len(token), "hash": None, "parser": "pdf-info-token", "decoder": None, "timestamp": value if b"Date" in match.group(1) else None, "confidence": 0.85, "flag_relation": None})
    unique = {}
    for item in result.items:
        unique[(item.get("namespace"), item.get("field"), item.get("normalized_value"), item.get("offset"))] = item
    result.items = list(unique.values())[:4000]
    result.metrics = {"values": len(result.items), "namespaces": len({x.get('namespace') for x in result.items})}
    return result


def _pdf_value(token: bytes) -> str:
    """Decode a simple PDF literal/hex string without executing PDF actions."""
    if token.startswith(b"("):
        raw = token[1:-1]
        raw = re.sub(rb"\\([()\\])", rb"\1", raw)
    else:
        try:
            raw = bytes.fromhex(token[1:-1].decode())
        except ValueError:
            raw = token
    if raw.startswith((b"\xfe\xff", b"\xff\xfe")):
        return raw.decode("utf-16", "replace")
    return raw.decode("utf-8", "replace")
