"""Bounded signature-based document identification.

The parser combines magic bytes, container members and textual markers. It does
not trust extensions and never executes or renders the asset.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from .container_bounds import (
    MAX_CENTRAL_DIRECTORY_BYTES,
    MAX_CENTRAL_DIRECTORY_ENTRIES,
    central_directory_info,
)
from .reporting import ModuleResult


MAGIC = [
    (b"%PDF-", "pdf", "application/pdf"),
    (b"\xff\xd8\xff", "jpeg", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png", "image/png"),
    (b"GIF8", "gif", "image/gif"),
    (b"II*\x00", "tiff", "image/tiff"),
    (b"MM\x00*", "tiff", "image/tiff"),
    (bytes.fromhex("d0cf11e0a1b11ae1"), "ole", "application/x-ole-storage"),
    (b"{\\rtf", "rtf", "application/rtf"),
    (b"PK\x03\x04", "zip", "application/zip"),
]


def identify(data: bytes, name: str = "asset") -> ModuleResult:
    """Identify a document from a bounded byte view.

    Input: at most the caller's bounded bytes and a display name. Output: format
    evidence with confidence. Exceptions: malformed ZIP is reported as a warning.
    Limits: ZIP member names only, maximum 2,000. Security: no extraction.
    Example: ``identify(b"%PDF-1.7", "x.pdf")``.
    """
    result = ModuleResult("identification")
    matches = []
    for signature, kind, mime in MAGIC:
        if data.startswith(signature):
            matches.append({"format": kind, "mime": mime, "offset": 0, "evidence": "magic bytes"})
    lower = data[:65536].lower()
    if b"<svg" in lower:
        matches.append({"format": "svg", "mime": "image/svg+xml", "offset": lower.index(b"<svg"), "evidence": "root SVG"})
    if b"<html" in lower or b"<!doctype html" in lower:
        matches.append({"format": "html", "mime": "text/html", "offset": 0, "evidence": "HTML marker"})
    if data.startswith((b"{", b"[")):
        try:
            json.loads(data.decode("utf-8"))
            matches.append({"format": "json", "mime": "application/json", "offset": 0, "evidence": "valid JSON"})
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    if data.startswith(b"PK"):
        directory = central_directory_info(data)
        if directory and (
            directory[0] > MAX_CENTRAL_DIRECTORY_BYTES
            or directory[1] > MAX_CENTRAL_DIRECTORY_ENTRIES
        ):
            result.warnings.append(
                f"Indice ZIP oltre budget: {directory[0]} byte/{directory[1]} voci; "
                f"limiti {MAX_CENTRAL_DIRECTORY_BYTES} byte/{MAX_CENTRAL_DIRECTORY_ENTRIES} voci"
            )
        else:
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    names = {item.filename for item in archive.filelist[:2000]}
                kind = "zip"
                if "[Content_Types].xml" in names:
                    kind = "ooxml"
                elif "META-INF/manifest.xml" in names:
                    kind = "odf"
                elif "META-INF/container.xml" in names and "mimetype" in names:
                    kind = "epub"
                matches.append({"format": kind, "mime": "application/zip", "offset": 0, "evidence": "container inventory"})
            except zipfile.BadZipFile as exc:
                result.warnings.append(f"Contenitore ZIP non valido: {exc}")
    suffix = Path(name).suffix.lower().lstrip(".")
    detected = {item["format"] for item in matches}
    compatible_suffixes = {"jpg": "jpeg", "jpeg": "jpeg", "tif": "tiff", "docx": "ooxml", "xlsx": "ooxml", "pptx": "ooxml"}
    expected = compatible_suffixes.get(suffix, suffix)
    result.items = matches or [{"format": "unknown", "mime": "application/octet-stream", "evidence": "no known signature", "offset": None}]
    if suffix and detected and expected not in detected and not ({"zip", "ooxml", "odf", "epub"} & detected and suffix in {"zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub"}):
        result.findings.append({"type": "format_inconsistency", "severity": "medium", "title": "Estensione incoerente", "description": f"Estensione .{suffix}, formati rilevati: {', '.join(sorted(detected))}", "source": name, "offset": 0, "confidence": 0.9})
    result.metrics = {
        "bytes_examined": len(data), "formats": len(matches),
        "central_directory_bytes": directory[0] if data.startswith(b"PK") and directory else 0,
        "central_directory_entries": directory[1] if data.startswith(b"PK") and directory else 0,
    }
    return result


def bounded_match(path: str, name: str, limit: int = 65536) -> dict:
    """Return hub compatibility without reading beyond ``limit`` bytes.

    Input: sandbox path/name. Output: compatible, score and evidence reasons.
    Raises ``OSError`` for unreadable input. Security: read-only bounded access.
    """
    with open(path, "rb") as source:
        data = source.read(limit)
    result = identify(data, name)
    known = [x for x in result.items if x["format"] != "unknown"]
    return {
        "compatible": bool(known),
        "score": min(0.99, 0.72 + 0.08 * len(known)) if known else 0,
        "reasons": [f"{x['format'].upper()}: {x['evidence']}" for x in known[:5]],
    }
