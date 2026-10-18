"""Bounded multi-encoding string extraction and indicator classification.

The scanner reports offsets into source bytes for ASCII/UTF-8, UTF-16LE and
UTF-16BE strings. It never interprets a string as a command or executes it.
"""

import ipaddress
import re

ASCII = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
UTF16BE = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")
URL = re.compile(r"(?i)\bhttps?://[^\s'\"<>]{4,}")
EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def extract(data: bytes, base_offset: int = 0, limit: int = 5000) -> list[dict]:
    """Extract printable strings with encoding, offset and conservative category."""
    rows = []
    for pattern, encoding in ((ASCII, "utf-8"), (UTF16LE, "utf-16le"), (UTF16BE, "utf-16be")):
        for match in pattern.finditer(data):
            try:
                value = match.group().decode(encoding)
            except UnicodeDecodeError:
                continue
            category = classify(value)
            rows.append({
                "value": value[:4096], "encoding": encoding, "offset": base_offset + match.start(),
                "length": len(match.group()), "section": None, "virtual_address": None,
                "references": [], "category": category, "confidence": 0.94 if category else 0.78,
            })
            if len(rows) >= limit:
                return sorted(rows, key=lambda item: item["offset"])
    return sorted(rows, key=lambda item: item["offset"])


def classify(value: str) -> str | None:
    """Label network, path, command, key or structured text indicators."""
    if URL.search(value):
        return "url"
    if EMAIL.search(value):
        return "email"
    for candidate in IP.findall(value):
        try:
            ipaddress.ip_address(candidate)
            return "ip_address"
        except ValueError:
            pass
    if "-----BEGIN " in value:
        return "pem_or_certificate"
    if re.search(r"(?:[A-Za-z]:\\|/(?:etc|tmp|usr|var|home)/)", value):
        return "filesystem_path"
    if re.search(r"(?i)\b(?:powershell|cmd\.exe|/bin/(?:sh|bash)|wget|curl)\b", value):
        return "command_string"
    if value.lstrip().startswith(("{", "[", "<?xml", "<html")):
        return "structured_data"
    if re.search(r"(?i)\b(?:password|token|secret|api[_-]?key)\b", value):
        return "possible_credential"
    return None


def hex_rows(data: bytes, base_offset: int = 0, width: int = 16, limit: int = 256) -> list[dict]:
    """Build a bounded hexdump table with an ASCII side column."""
    return [
        {"offset": base_offset + offset, "hex": block.hex(" "), "ascii": "".join(chr(v) if 32 <= v < 127 else "." for v in block)}
        for offset in range(0, min(len(data), width * limit), width)
        for block in (data[offset : offset + width],)
    ]
