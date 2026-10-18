"""Exact-range carving restricted to structurally validated candidates."""

from pathlib import Path
from .artifact_manager import ArtifactManager

EXTENSIONS={"elf":".elf","dos_pe":".exe","pe":".exe","macho32_be":".macho","macho32_le":".macho","macho64_be":".macho","macho64_le":".macho","zip":".zip","png":".png","jpeg":".jpg","pdf":".pdf","gzip":".gz","xz":".xz","bzip2":".bz2","cpio_newc":".cpio","cpio_crc":".cpio","squashfs_le":".squashfs","squashfs_be":".squashfs"}


def carve(path:Path,formats:list[dict],store:ArtifactManager,physical_size:int)->tuple[list[dict],list[str]]:
    """Save secondary or logically bounded valid structures with provenance."""
    artifacts=[];warnings=[]
    with path.open("rb") as source:
        for item in formats:
            if item["start_offset"]==0 and item["end_offset"]==physical_size:continue
            if item["length"]>64*1024*1024:warnings.append(f"Carving {item['format']} oltre 64 MiB");continue
            source.seek(item["start_offset"]);data=source.read(item["length"])
            if len(data)!=item["length"]:warnings.append(f"Carving {item['format']} troncato");continue
            try:artifacts.append(store.save("carved",f"{item['format']}-{item['start_offset']}{EXTENSIONS.get(item['format'],'.bin')}",data,{"parent_artifact_id":"input","start_offset":item["start_offset"],"end_offset":item["end_offset"],"length":item["length"],"signature":item["signature"],"detected_type":item["format"],"validated":True,"confidence":item["confidence"],"extraction_method":"validated_range_carving"}))
            except ValueError as exc:warnings.append(str(exc));break
    return artifacts,warnings
