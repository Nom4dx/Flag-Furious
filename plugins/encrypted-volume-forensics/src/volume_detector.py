"""Content-first encrypted-volume discovery over partition starts and byte scans."""

from __future__ import annotations

from pathlib import Path

FVE_SIGNATURE = b"-FVE-FS-"


def _candidate(path: Path, start: int, available: int, source: str) -> dict | None:
    with path.open("rb") as stream:
        stream.seek(start); sector=stream.read(512)
    if len(sector)<64 or sector[3:11] != FVE_SIGNATURE: return None
    bytes_per_sector=int.from_bytes(sector[11:13],"little")
    sectors_per_cluster=sector[13]
    total_sectors=int.from_bytes(sector[40:48],"little")
    plausible_sector=bytes_per_sector in {512,1024,2048,4096}
    volume_size=total_sectors*bytes_per_sector if plausible_sector and total_sectors else available
    valid=plausible_sector and sectors_per_cluster and sectors_per_cluster & (sectors_per_cluster-1)==0
    metadata_offsets=[int.from_bytes(sector[pos:pos+8],"little") for pos in (0xB0,0xB8,0xC0) if len(sector)>=pos+8]
    metadata_offsets=[value for value in metadata_offsets if 0<value<max(volume_size,available)]
    logical_length=min(volume_size,available)
    return {"id":f"volume-{start:x}","detected_type":"BitLocker encrypted volume","source":source,"offset":start,
            "length":logical_length,"physical_available":available,"trailing_bytes":max(0,available-logical_length),"bytes_per_sector":bytes_per_sector,"sectors_per_cluster":sectors_per_cluster,
            "declared_sectors":total_sectors,"metadata_offsets":metadata_offsets,"validated":valid,
            "confidence":.99 if valid else .82,"evidence":["OEM identifier -FVE-FS-", "BPB coerente" if valid else "BPB parzialmente coerente"]}


def detect(path: Path, partitions: list[dict], byte_budget: int) -> tuple[list[dict], bool]:
    """Find BitLocker VBRs without trusting extensions.

    Partition starts are checked first. A bounded streaming scan then finds
    unpartitioned or damaged-table volumes. One MiB overlap prevents a marker
    split across blocks; results are deduplicated by volume start.
    """
    size=path.stat().st_size; found={}
    for part in partitions:
        if part.get("status") == "valid":
            item=_candidate(path,part["offset"],part["length"],f"partition-{part['number']}")
            if item: found[item["offset"]]=item
    limit=min(size,byte_budget);block_size=4*1024*1024;offset=0;tail=b""
    with path.open("rb") as source:
        while offset<limit and len(found)<128:
            block=source.read(min(block_size,limit-offset))
            if not block:break
            data=tail+block;base=offset-len(tail);cursor=0
            while (position:=data.find(FVE_SIGNATURE,cursor))>=0:
                start=base+position-3
                if start>=0 and start not in found:
                    item=_candidate(path,start,size-start,"signature_scan")
                    if item and item["validated"]:found[start]=item
                cursor=position+1
            tail=data[-16:];offset+=len(block)
    return sorted(found.values(),key=lambda item:item["offset"]), limit<size
