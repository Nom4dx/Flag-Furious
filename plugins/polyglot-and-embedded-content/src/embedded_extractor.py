"""Verified-range carving and streamed copying into the artifact workspace."""

from pathlib import Path

from .artifact_store import ArtifactStore
from .format_registry import safe_extension


def carve_validated(path: Path, boundaries: list[dict], store: ArtifactStore, max_object_bytes: int) -> tuple[list[dict], list[str]]:
    """Carve only structurally validated intervals and preserve provenance.

    Input boundaries use exclusive ends. Output artifacts carry offsets, method
    and confidence. Objects larger than the configured cap are skipped with a
    warning. The original remains read-only and foreign bytes are not included.
    """
    artifacts, warnings = [], []
    with path.open("rb") as stream:
        for item in boundaries:
            if item["length"] > max_object_bytes:
                warnings.append(f"Carving {item['format']} @{item['start_offset']} omesso: limite oggetto")
                continue
            stream.seek(item["start_offset"]); data = stream.read(item["length"])
            if len(data) != item["length"]:
                warnings.append(f"Carving {item['format']} incompleto")
                continue
            try:
                artifacts.append(store.save_bytes("carved", f"{item['format']}-{item['start_offset']}{safe_extension(item['format'])}", data, {
                    "format": item["format"], "source_offset": item["start_offset"], "source_length": item["length"],
                    "extraction_method": item["boundary_method"], "confidence": item["confidence"], "format_id": item["id"],
                }))
            except ValueError as exc:
                warnings.append(str(exc)); break
    return artifacts, warnings

