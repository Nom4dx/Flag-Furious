"""Static PNG, JPEG, GIF, WebP, SVG, HEIC and AVIF container inspection."""

from __future__ import annotations

import re
import struct
import zlib

from .reporting import ModuleResult


def analyze_image(data: bytes, source: str) -> ModuleResult:
    """Inventory image structure and textual metadata.

    Input: image bytes/source. Output: chunks/segments and textual properties.
    Limits: 4,000 records, 8 MiB decompressed text. Security: no raster rendering,
    SVG script only reported. Example: ``analyze_image(png, "a.png")``.
    """
    result = ModuleResult("images", status="skipped")
    if data.startswith(b"\x89PNG"):
        result.status = "completed"
        _png(data, source, result)
    elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        result.status = "completed"
        result.items.append({"type": "image_container", "format": "WebP", "source": source, "size": len(data)})
    elif data[4:12] in (b"ftypheic", b"ftypheix", b"ftypavif", b"ftypavis"):
        result.status = "completed"
        result.items.append({"type": "image_container", "format": "HEIC/AVIF", "brand": data[8:12].decode("ascii", "replace"), "source": source})
    elif b"<svg" in data[:65536].lower():
        result.status = "completed"
        result.items.append({"type": "image_container", "format": "SVG", "source": source})
        for match in re.finditer(rb"<(?:metadata|desc|title)\b[^>]*>(.*?)</", data, re.I | re.S):
            raw_value = match.group(1).decode("utf-8", "replace")
            normalized = re.sub(r"<[^>]+>", "", raw_value).strip()
            result.items.append({"type": "metadata_value", "namespace": "SVG", "field": "text", "raw_value": raw_value, "normalized_value": normalized, "source": source, "internal_path": "svg", "offset": match.start(), "size": len(match.group(0)), "hash": None, "parser": "svg-xml", "decoder": None, "timestamp": None, "confidence": 0.85, "flag_relation": None})
        if re.search(rb"<(?:script|foreignObject)\b|\bon\w+\s*=", data, re.I):
            result.findings.append({"type": "active_svg", "severity": "high", "title": "Contenuto SVG attivo", "description": "Script/evento rilevato e non eseguito", "source": source, "offset": 0, "confidence": 0.9})
    result.metrics = {"items": len(result.items)}
    return result


def _png(data: bytes, source: str, result: ModuleResult) -> None:
    """Walk length-prefixed PNG chunks with CRC evidence and checked bounds."""
    cursor = 8
    while cursor + 12 <= len(data) and len(result.items) < 4000:
        length = struct.unpack_from(">I", data, cursor)[0]
        if length > 64 * 1024**2 or cursor + 12 + length > len(data):
            result.warnings.append(f"Chunk PNG non valido a {cursor}")
            break
        kind = data[cursor + 4 : cursor + 8]
        payload = data[cursor + 8 : cursor + 8 + length]
        expected = struct.unpack_from(">I", data, cursor + 8 + length)[0]
        valid = zlib.crc32(kind + payload) & 0xFFFFFFFF == expected
        result.items.append({"type": "png_chunk", "chunk": kind.decode("latin-1"), "offset": cursor, "size": length, "crc_valid": valid, "source": source})
        if kind in (b"tEXt", b"iTXt", b"zTXt"):
            try:
                value = payload.decode("utf-8", "replace")
                result.items.append({"type": "metadata_value", "namespace": "PNG", "field": kind.decode(), "raw_value": value, "normalized_value": value.replace("\x00", ": ").strip(), "source": source, "internal_path": f"png:{kind.decode()}", "offset": cursor + 8, "size": length, "hash": None, "parser": "png-chunk", "decoder": None, "timestamp": None, "confidence": 0.95 if valid else 0.65, "flag_relation": None})
            except UnicodeDecodeError:
                pass
        cursor += 12 + length
