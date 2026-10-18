"""Exact-range carving for structurally validated embedded formats."""

from pathlib import Path

from .container_extract import ArtifactStore
from .signatures import suffix_for


def carve(path: Path, formats: list[dict], store: ArtifactStore, physical_size: int) -> tuple[list[dict], list[str]]:
    """Save validated secondary/logically bounded ranges with provenance.

    The full primary file is not duplicated. A primary whose logical end precedes
    physical EOF is carved to separate its clean interpretation. Unvalidated
    signature hits are never carved.
    """
    artifacts=[];warnings=[]
    with path.open("rb") as stream:
        for item in formats:
            if item["start_offset"]==0 and item["end_offset"]==physical_size:continue
            if item["length"]>store.limits.max_single_artifact_size:
                warnings.append(f"Carving {item['format']} @{item['start_offset']} oltre limite");continue
            stream.seek(item["start_offset"]);raw=stream.read(item["length"])
            if len(raw)!=item["length"]:warnings.append(f"Carving {item['format']} troncato");continue
            try:artifacts.append(store.save("carved",f"{item['format']}-{item['start_offset']}{suffix_for(item['format'])}",raw,{"source_offset":item["start_offset"],"source_length":item["length"],"detected_type":item["format"],"status":"extracted","technique":"validated_boundary_carving","confidence":item["confidence"],"format_id":item["id"]}))
            except ValueError as exc:warnings.append(str(exc));break
    return artifacts,warnings
