"""Bounded XMP packet extraction and XML metadata flattening."""

from __future__ import annotations

import re
from xml.etree import ElementTree

from .reporting import ModuleResult


def parse_xmp(data: bytes, source: str) -> ModuleResult:
    """Extract XMP packets and scalar fields.

    Input: passive bytes and source label. Output: metadata items with byte
    offsets. Malformed XML becomes a warning. Limits: 8 packets, 4 MiB each,
    2,000 values. Security: stdlib XML performs no network fetches here.
    Example: ``parse_xmp(pdf_bytes, "file.pdf")``.
    """
    result = ModuleResult("xmp")
    patterns = [rb"<x:xmpmeta\b.*?</x:xmpmeta>", rb"<rdf:RDF\b.*?</rdf:RDF>"]
    seen = set()
    for pattern in patterns:
        for match in re.finditer(pattern, data, re.I | re.S):
            packet = match.group(0)
            if match.start() in seen or len(packet) > 4 * 1024**2:
                continue
            seen.add(match.start())
            try:
                root = ElementTree.fromstring(packet)
                count = 0
                for element in root.iter():
                    for field, value in element.attrib.items():
                        if value and count < 2000:
                            result.items.append(_item(field, value, source, match.start(), "xmp-attribute"))
                            count += 1
                    text = (element.text or "").strip()
                    if text and count < 2000:
                        result.items.append(_item(element.tag, text, source, match.start(), "xmp-element"))
                        count += 1
            except ElementTree.ParseError as exc:
                result.warnings.append(f"Pacchetto XMP malformato a {match.start()}: {exc}")
            if len(seen) >= 8:
                break
    result.metrics = {"packets": len(seen), "values": len(result.items)}
    return result


def _item(field: str, value: str, source: str, offset: int, parser: str) -> dict:
    """Normalize one XMP value; input/output remain text-only and JSON-safe."""
    namespace, _, local = field.rpartition("}")
    return {"type": "metadata_value", "namespace": namespace.lstrip("{") or "XMP", "field": local or field, "raw_value": value, "normalized_value": value.strip(), "source": source, "internal_path": "xmp", "offset": offset, "size": len(value.encode("utf-8")), "hash": None, "parser": parser, "decoder": None, "timestamp": None, "confidence": 0.95, "flag_relation": None}
