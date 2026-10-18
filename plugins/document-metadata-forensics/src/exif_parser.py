"""Conservative JPEG/TIFF EXIF and JPEG comment parser.

Binary offsets are decoded with explicit endian handling. Unknown tags remain
raw evidence; malformed offsets are rejected rather than followed.
"""

from __future__ import annotations

import struct

from .reporting import ModuleResult


TAGS = {0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model", 0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist", 0x8298: "Copyright", 0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized", 0x9286: "UserComment", 0x9C9B: "XPTitle", 0x9C9C: "XPComment", 0x9C9D: "XPAuthor", 0x9C9E: "XPKeywords", 0x9C9F: "XPSubject"}


def parse_exif(data: bytes, source: str) -> ModuleResult:
    """Parse bounded EXIF IFD entries and JPEG COM segments.

    Input: image bytes/source. Output: normalized metadata with offsets. Parser
    errors are warnings. Limits: 512 tags, scalar ASCII/byte values only. Security:
    no image decoder or external resource. Example: ``parse_exif(jpeg, "a.jpg")``.
    """
    result = ModuleResult("exif")
    if data.startswith(b"\xff\xd8"):
        cursor = 2
        while cursor + 4 <= len(data) and cursor < 4 * 1024**2:
            if data[cursor] != 0xFF:
                cursor += 1
                continue
            marker = data[cursor + 1]
            if marker in {0xD8, 0xD9}:
                cursor += 2
                continue
            length = int.from_bytes(data[cursor + 2 : cursor + 4], "big")
            if length < 2 or cursor + 2 + length > len(data):
                break
            payload = data[cursor + 4 : cursor + 2 + length]
            if marker == 0xFE:
                value = payload.decode("utf-8", "replace").strip("\x00")
                result.items.append(_metadata("Comment", value, source, cursor + 4, "jpeg-com"))
            if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                _parse_tiff(payload[6:], source, cursor + 10, result)
            cursor += 2 + length
    elif data.startswith((b"II*\x00", b"MM\x00*")):
        _parse_tiff(data, source, 0, result)
    result.metrics = {"values": len(result.items)}
    return result


def _parse_tiff(tiff: bytes, source: str, absolute: int, result: ModuleResult) -> None:
    """Read the first TIFF IFD with checked relative offsets; never recurses."""
    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return
    endian = "<" if tiff[:2] == b"II" else ">"
    try:
        ifd = struct.unpack_from(endian + "I", tiff, 4)[0]
        if ifd + 2 > len(tiff):
            return
        count = min(struct.unpack_from(endian + "H", tiff, ifd)[0], 512)
        widths = {1: 1, 2: 1, 3: 2, 4: 4, 7: 1}
        for index in range(count):
            pos = ifd + 2 + index * 12
            if pos + 12 > len(tiff):
                break
            tag, kind, elements = struct.unpack_from(endian + "HHI", tiff, pos)
            size = widths.get(kind, 0) * elements
            if not size or size > 65536:
                continue
            rel = pos + 8 if size <= 4 else struct.unpack_from(endian + "I", tiff, pos + 8)[0]
            if rel < 0 or rel + size > len(tiff):
                continue
            raw = tiff[rel : rel + size]
            if kind == 2:
                value = raw.rstrip(b"\x00").decode("utf-8", "replace")
            elif tag in range(0x9C9B, 0x9CA0):
                value = raw.decode("utf-16le", "replace").rstrip("\x00")
            else:
                continue
            if value:
                result.items.append(_metadata(TAGS.get(tag, f"Tag-0x{tag:04X}"), value, source, absolute + rel, "tiff-ifd"))
    except (struct.error, ValueError) as exc:
        result.warnings.append(f"EXIF/TIFF incompleto: {exc}")


def _metadata(field: str, value: str, source: str, offset: int, parser: str) -> dict:
    """Create a provenance-complete metadata record without interpreting content."""
    return {"type": "metadata_value", "namespace": "EXIF", "field": field, "raw_value": value, "normalized_value": value.strip(), "source": source, "internal_path": "image", "offset": offset, "size": len(value.encode("utf-8")), "hash": None, "parser": parser, "decoder": None, "timestamp": value if "Date" in field else None, "confidence": 0.9, "flag_relation": None}
