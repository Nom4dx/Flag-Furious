"""Static OOXML, ODF and EPUB container analyzer."""

from __future__ import annotations

import io
import re
import stat
import zipfile
import zlib
from pathlib import PurePosixPath
from xml.etree import ElementTree

from .container_bounds import (
    MAX_CENTRAL_DIRECTORY_BYTES,
    MAX_CENTRAL_DIRECTORY_ENTRIES,
    central_directory_info,
)
from .reporting import ModuleResult


PROPERTY_FILES = {"docProps/core.xml", "docProps/app.xml", "docProps/custom.xml", "meta.xml"}
MAX_MEMBER_BYTES = 16 * 1024**2
MAX_TOTAL_MEMBER_BYTES = 64 * 1024**2


def _read_member_bounded(archive: zipfile.ZipFile, member: zipfile.ZipInfo,
                         limit: int, counter: list[int]) -> bytes:
    """Read a ZIP member incrementally and reject actual expansion beyond limit."""
    content = bytearray()
    with archive.open(member) as source:
        while True:
            block = source.read(min(64 * 1024, limit - len(content) + 1))
            if not block:
                return bytes(content)
            content.extend(block)
            counter[0] += len(block)
            if len(content) > limit:
                raise ValueError("expanded_member_limit")


def analyze_ooxml(data: bytes, source: str) -> ModuleResult:
    """Inventory and statically inspect ZIP-based document formats.

    Input: complete bounded container bytes/source. Output: properties, comments,
    revisions, hidden sheets/slides, macro indicators and embedded artifacts.
    Bad ZIP input is skipped with a warning. Limits: 5,000 members, 16 MiB/member,
    64 MiB total extraction. Security: paths and symlinks are rejected; VBA and
    embedded objects are never executed. Example: ``analyze_ooxml(docx, "a.docx")``.
    """
    result = ModuleResult("office", status="skipped")
    if not data.startswith(b"PK"):
        return result
    directory = central_directory_info(data)
    if directory and (
        directory[0] > MAX_CENTRAL_DIRECTORY_BYTES
        or directory[1] > MAX_CENTRAL_DIRECTORY_ENTRIES
    ):
        result.status = "partial"
        result.warnings.append(
            f"Indice ZIP oltre budget: {directory[0]} byte/{directory[1]} voci; "
            f"limiti {MAX_CENTRAL_DIRECTORY_BYTES} byte/{MAX_CENTRAL_DIRECTORY_ENTRIES} voci"
        )
        result.metrics.update({"central_directory_bytes": directory[0], "central_directory_entries": directory[1]})
        return result
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        result.warnings.append(f"Contenitore Office/ODF non valido: {exc}")
        return result
    result.status = "completed"
    total = 0
    with archive:
        inventory = archive.infolist()
        members = inventory[:5000]
        if len(inventory) > len(members):
            result.warnings.append("Inventario container limitato ai primi 5.000 membri")
            result.status = "partial"
        names = {m.filename for m in members}
        family = "OOXML" if "[Content_Types].xml" in names else "ODF" if "META-INF/manifest.xml" in names else "EPUB" if "META-INF/container.xml" in names else "ZIP document"
        result.items.append({"type": "container", "family": family, "members": len(members), "source": source})
        for member in members:
            name = PurePosixPath(member.filename.replace("\\", "/"))
            unsafe = name.is_absolute() or ".." in name.parts or stat.S_ISLNK(member.external_attr >> 16)
            if unsafe or member.is_dir():
                if unsafe:
                    result.warnings.append(f"Membro non sicuro ignorato: {member.filename}")
                continue
            if member.file_size > MAX_MEMBER_BYTES:
                result.warnings.append(f"Membro oltre limite dichiarato ignorato: {member.filename}")
                result.status = "partial"
                continue
            remaining = MAX_TOTAL_MEMBER_BYTES - total
            if remaining <= 0:
                result.warnings.append("Budget container 64 MiB raggiunto")
                result.status = "partial"
                break
            member_limit = min(MAX_MEMBER_BYTES, remaining)
            consumed = [0]
            try:
                raw = _read_member_bounded(archive, member, member_limit, consumed)
            except (ValueError, RuntimeError, OSError, EOFError, NotImplementedError, zlib.error, zipfile.BadZipFile) as exc:
                total += consumed[0]
                result.warnings.append(f"Lettura limitata/fallita per {member.filename}: {str(exc)[:240]}")
                result.status = "partial"
                if total >= MAX_TOTAL_MEMBER_BYTES:
                    break
                continue
            total += consumed[0]
            lower_name = member.filename.lower()
            if member.filename in PROPERTY_FILES or lower_name.endswith(("comments.xml", "commentauthors.xml")):
                _parse_xml_properties(raw, source, member.filename, result)
            if lower_name.endswith(".xml"):
                text = raw.decode("utf-8", "replace")
                if re.search(r"<(?:w:ins|w:del)\b", text):
                    result.findings.append(_finding("office_revision", "Revisioni Office", source, member.filename, 0, 0.9))
                if re.search(r'(?:state|show)="(?:hidden|veryHidden|0)"', text, re.I):
                    result.findings.append(_finding("hidden_office_content", "Foglio, slide o oggetto nascosto", source, member.filename, 0, 0.88))
                if "comments" in lower_name:
                    result.items.append({"type": "office_comments", "internal_path": member.filename, "text": _xml_text(raw)[:20000], "source": source, "offset": member.header_offset})
            if lower_name.endswith(("vbaproject.bin", ".js", ".bin")) and ("vba" in lower_name or "embeddings/" in lower_name):
                result.findings.append(_finding("macro_or_embedded_object", "Macro o oggetto incorporato", source, member.filename, member.header_offset, 0.98))
                result.artifacts.append({"name": name.name, "content": raw, "category": "office", "source": f"{source}:{member.filename}", "offset": member.header_offset, "method": "safe ZIP extraction"})
            elif any(part in lower_name for part in ("embeddings/", "thumbnail", "preview")):
                result.artifacts.append({"name": name.name, "content": raw, "category": "office", "source": f"{source}:{member.filename}", "offset": member.header_offset, "method": "safe ZIP extraction"})
    result.metrics.update({"members": len(members), "bytes_examined": total, "artifacts": len(result.artifacts)})
    return result


def _parse_xml_properties(raw: bytes, source: str, path: str, result: ModuleResult) -> None:
    """Flatten scalar XML properties; malformed XML is retained as a warning."""
    try:
        root = ElementTree.fromstring(raw)
        for element in root.iter():
            text = (element.text or "").strip()
            if text:
                field = element.tag.rpartition("}")[2]
                result.items.append({"type": "metadata_value", "namespace": "Office", "field": field, "raw_value": text, "normalized_value": text, "source": source, "internal_path": path, "offset": None, "size": len(text.encode()), "hash": None, "parser": "office-xml", "decoder": None, "timestamp": text if field.lower() in {"created", "modified", "lastprinted"} else None, "confidence": 0.95, "flag_relation": None})
    except ElementTree.ParseError as exc:
        result.warnings.append(f"XML {path} malformato: {exc}")


def _xml_text(raw: bytes) -> str:
    """Extract visible XML text without applying styles or external entities."""
    try:
        return " ".join((x.text or "").strip() for x in ElementTree.fromstring(raw).iter() if (x.text or "").strip())
    except ElementTree.ParseError:
        return raw.decode("utf-8", "replace")


def _finding(kind: str, title: str, source: str, path: str, offset: int, confidence: float) -> dict:
    """Create an Office finding with explicit internal provenance."""
    return {"type": kind, "severity": "medium", "title": title, "description": "Contenuto rilevato staticamente e non eseguito", "source": source, "internal_path": path, "offset": offset, "confidence": confidence}
