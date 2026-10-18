"""Streaming signature inventory for binary containers and passive scripts.

The scanner only proposes candidates: callers must pass every candidate through
``validators.validate_candidate`` before presenting a format as present.  Reads
are block based, bounded and read-only; overlapping blocks preserve signatures
split across an I/O boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(frozen=True)
class Signature:
    """Describe a format marker and its structural validator.

    ``relative_offset`` converts markers such as TAR's ``ustar`` field into the
    beginning of the candidate. A negative computed start is discarded.
    """

    format: str
    value: bytes
    validator: str
    confidence: float
    relative_offset: int = 0
    root_marker: bool = True
    end_markers: tuple[bytes, ...] = ()


SIGNATURES: tuple[Signature, ...] = (
    Signature("pdf", b"%PDF-", "validate_pdf", .98, end_markers=(b"%%EOF",)),
    Signature("zip", b"PK\x03\x04", "validate_zip", .97),
    Signature("zip", b"PK\x05\x06", "validate_zip", .94),
    Signature("zip", b"PK\x07\x08", "validate_zip", .82),
    Signature("zip_central_directory", b"PK\x01\x02", "secondary_marker", .92, root_marker=False),
    Signature("zip_eocd", b"PK\x05\x06", "secondary_marker", .94, root_marker=False),
    Signature("png", b"\x89PNG\r\n\x1a\n", "validate_png", .99, end_markers=(b"IEND\xaeB`\x82",)),
    Signature("jpeg", b"\xff\xd8\xff", "validate_jpeg", .98, end_markers=(b"\xff\xd9",)),
    Signature("gif", b"GIF87a", "validate_gif", .98, end_markers=(b";",)),
    Signature("gif", b"GIF89a", "validate_gif", .98, end_markers=(b";",)),
    Signature("riff", b"RIFF", "validate_riff", .96),
    Signature("gzip", b"\x1f\x8b\x08", "validate_gzip", .96),
    Signature("bzip2", b"BZh", "validate_bzip2", .95),
    Signature("xz", b"\xfd7zXZ\x00", "validate_xz", .98),
    Signature("7z", b"7z\xbc\xaf'\x1c", "validate_7z", .99),
    Signature("rar", b"Rar!\x1a\x07\x00", "validate_rar", .98),
    Signature("rar", b"Rar!\x1a\x07\x01\x00", "validate_rar", .99),
    Signature("elf", b"\x7fELF", "validate_elf", .99),
    Signature("pe", b"MZ", "validate_pe", .80),
    Signature("macho", b"\xfe\xed\xfa\xce", "validate_macho", .98),
    Signature("macho", b"\xce\xfa\xed\xfe", "validate_macho", .98),
    Signature("macho", b"\xfe\xed\xfa\xcf", "validate_macho", .98),
    Signature("macho", b"\xcf\xfa\xed\xfe", "validate_macho", .98),
    Signature("sqlite", b"SQLite format 3\x00", "validate_sqlite", .99),
    Signature("java_class", b"\xca\xfe\xba\xbe", "validate_java", .97),
    Signature("wasm", b"\x00asm", "validate_wasm", .98),
    Signature("ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "validate_ole", .99),
    Signature("tar", b"ustar", "validate_tar", .93, relative_offset=257),
    Signature("cpio", b"070701", "validate_cpio", .94),
    Signature("cpio", b"070702", "validate_cpio", .94),
    Signature("cpio", b"070707", "validate_cpio", .90),
    Signature("iso9660", b"CD001", "validate_iso", .96, relative_offset=32769),
    Signature("xml", b"<?xml", "validate_xml", .88),
    Signature("html", b"<!DOCTYPE html", "validate_html", .90),
    Signature("html", b"<html", "validate_html", .85),
    Signature("script", b"#!/", "validate_script", .92),
    Signature("powershell", b"#requires", "validate_script", .72),
    Signature("batch", b"@echo off", "validate_script", .88),
)

TEXT_FORMAT_HINTS: tuple[tuple[str, bytes], ...] = (
    ("python_script", rb"(?m)^(?:from\s+[A-Za-z_][\w.]*\s+import\s+|import\s+[A-Za-z_]|def\s+[A-Za-z_]\w*\s*\()"),
    ("javascript", rb"(?m)^(?:(?:const|let|var)\s+[A-Za-z_$]|function\s+[A-Za-z_$]|(?:import|export)\s+.*\sfrom\s+['\"])"),
    ("powershell", rb"(?mi)^(?:param\s*\(|function\s+[\w-]+|\$[A-Za-z_]\w*\s*=|#requires\b)"),
    ("batch", rb"(?mi)^(?:@echo\s+off|setlocal\b|rem\s+|::[^:])"),
)


def scan_signatures(path: Path, byte_budget: int, max_results: int = 2048) -> tuple[list[dict], bool]:
    """Find candidate signatures across a file without loading it wholly.

    Input is a readable path, byte budget and result cap. Output is candidates
    plus a truncation flag. I/O errors propagate. Limits prevent unbounded scans;
    no candidate is asserted valid. Example: ``scan_signatures(path, 1<<20)``.
    """
    longest = max(len(item.value) + item.relative_offset for item in SIGNATURES)
    candidates: list[dict] = []
    seen: set[tuple[str, int]] = set()
    consumed = 0
    tail = b""
    truncated = False
    with path.open("rb") as source:
        text_prefix = source.read(min(byte_budget, 65536))
    if b"\x00" not in text_prefix[:4096]:
        for format_name, pattern in TEXT_FORMAT_HINTS:
            match = re.search(pattern, text_prefix)
            if match:
                seen.add((format_name, 0))
                candidates.append({
                    "id": f"candidate-{len(candidates) + 1}", "format": format_name,
                    "offset": 0, "marker_offset": match.start(), "signature": match.group()[:32].hex(),
                    "context_hex": text_prefix[max(0, match.start() - 12):match.end() + 20].hex(),
                    "validator": "validate_script", "signature_confidence": .78,
                    "possible_end_markers": [], "root_marker": True, "validated": False,
                })
    with path.open("rb") as source:
        while consumed < byte_budget:
            block = source.read(min(1024 * 1024, byte_budget - consumed))
            if not block:
                break
            window = tail + block
            window_base = consumed - len(tail)
            for signature in SIGNATURES:
                cursor = 0
                while True:
                    found = window.find(signature.value, cursor)
                    if found < 0:
                        break
                    absolute_marker = window_base + found
                    start = absolute_marker - signature.relative_offset
                    key = (signature.format, start)
                    if start >= 0 and key not in seen:
                        seen.add(key)
                        left = max(0, found - 12)
                        right = min(len(window), found + len(signature.value) + 20)
                        candidates.append({
                            "id": f"candidate-{len(candidates) + 1}",
                            "format": signature.format,
                            "offset": start,
                            "marker_offset": absolute_marker,
                            "signature": signature.value.hex(),
                            "context_hex": window[left:right].hex(),
                            "validator": signature.validator,
                            "root_marker": signature.root_marker,
                            "signature_confidence": signature.confidence,
                            "possible_end_markers": [m.hex() for m in signature.end_markers],
                            "validated": False,
                        })
                        if len(candidates) >= max_results:
                            return sorted(candidates, key=lambda x: x["offset"]), True
                    cursor = found + 1
            consumed += len(block)
            tail = window[-longest:]
        truncated = source.read(1) != b""
    return sorted(candidates, key=lambda x: (x["offset"], x["format"])), truncated
