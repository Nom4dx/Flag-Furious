"""Bounded MBR/GPT parser with backup-header consistency checks.

Partition entries are ranges only; this module never mounts a filesystem.
Malformed offsets are retained as invalid findings rather than dereferenced.
"""

from __future__ import annotations

import binascii
import struct
import uuid
from pathlib import Path


def _filesystem(probe: bytes) -> str:
    if probe[3:11] == b"-FVE-FS-": return "BitLocker/FVE"
    if probe[3:11] == b"NTFS    ": return "NTFS"
    if probe[3:11] == b"EXFAT   ": return "exFAT"
    if probe[54:62].startswith((b"FAT12", b"FAT16")): return probe[54:62].decode("ascii", "ignore").strip()
    if probe[82:90].startswith(b"FAT32"): return "FAT32"
    if len(probe) >= 1082 and probe[1080:1082] == b"\x53\xef": return "ext2/3/4"
    return "unknown"


def _partition(number, scheme, start, sectors, sector_size, size, name="", type_id=""):
    offset, length = start * sector_size, sectors * sector_size
    return {"number": number, "scheme": scheme, "name": name, "type": type_id, "start_sector": start,
            "end_sector": start + sectors - 1 if sectors else start, "offset": offset, "length": length,
            "status": "valid" if sectors and offset + length <= size else "invalid", "filesystem": "unknown"}


def _gaps(rows:list[dict],size:int,sector_size:int)->list[dict]:
    """Return physical ranges not covered by valid allocated partitions."""
    result=[];cursor=0;total=size//sector_size
    for row in sorted((x for x in rows if x["status"]=="valid"),key=lambda x:x["start_sector"]):
        if row["start_sector"]>cursor:
            gap=_partition(0,row["scheme"],cursor,row["start_sector"]-cursor,sector_size,size,"unallocated","unallocated");gap["status"]="unallocated";result.append(gap)
        cursor=max(cursor,row["end_sector"]+1)
    if cursor<total:
        gap=_partition(0,rows[0]["scheme"] if rows else "none",cursor,total-cursor,sector_size,size,"unallocated","unallocated");gap["status"]="unallocated";result.append(gap)
    return result


def inspect(path: Path, sector_size: int = 512) -> dict:
    """Parse primary MBR/GPT and verify GPT CRC and backup signature.

    Output preserves invalid entries and anomalies. GPT entry decoding is capped
    at 16 MiB to prevent corrupt counts from allocating attacker-controlled data.
    """
    size = path.stat().st_size
    with path.open("rb") as source:
        mbr = source.read(512)
        # A standalone BitLocker volume has the normal 0x55aa boot signature,
        # but bytes 446..509 are encrypted volume data rather than an MBR table.
        # Classify the OEM ID first to avoid four bogus out-of-range partitions.
        if mbr[3:11] == b"-FVE-FS-":
            whole={**_partition(1,"volume",0,size//sector_size,sector_size,size,"BitLocker volume","bitlocker"),"filesystem":"BitLocker/FVE"}
            return {"scheme":"volume","sector_size":sector_size,"partitions":[whole],"anomalies":[],"backup_gpt":None}
        if len(mbr) < 512 or mbr[510:512] != b"\x55\xaa":
            source.seek(0); probe = source.read(2048)
            return {"scheme": "none", "sector_size": sector_size, "partitions": [{**_partition(1,"none",0,size//sector_size,sector_size,size,"whole image","whole"),"filesystem":_filesystem(probe)}], "anomalies": ["Partition table assente; analisi come volume intero"], "backup_gpt": None}
        mbr_rows = []
        for index in range(4):
            raw = mbr[446 + 16 * index:462 + 16 * index]
            ptype, start, sectors = raw[4], *struct.unpack_from("<II", raw, 8)
            if ptype and sectors: mbr_rows.append(_partition(index+1,"MBR",start,sectors,sector_size,size,type_id=f"0x{ptype:02x}"))
        if not any(row["type"] == "0xee" for row in mbr_rows):
            for row in mbr_rows:
                if row["status"] == "valid": source.seek(row["offset"]); row["filesystem"] = _filesystem(source.read(2048))
            mbr_rows.extend(_gaps(mbr_rows,size,sector_size))
            return {"scheme":"MBR","sector_size":sector_size,"partitions":mbr_rows,"anomalies":["Partizione fuori dai limiti" for row in mbr_rows if row["status"]=="invalid"],"backup_gpt":None}
        source.seek(sector_size); header = source.read(sector_size)
        if header[:8] != b"EFI PART":
            return {"scheme":"GPT-corrupt","sector_size":sector_size,"partitions":[],"anomalies":["Protective MBR presente ma GPT primaria non valida"],"backup_gpt":None}
        header_size = struct.unpack_from("<I", header, 12)[0]
        stored_crc = struct.unpack_from("<I", header, 16)[0]
        check = bytearray(header[:min(header_size, len(header))]); check[16:20] = b"\0" * 4
        anomalies=[]
        if header_size < 92 or header_size > sector_size or binascii.crc32(check) & 0xffffffff != stored_crc: anomalies.append("CRC header GPT primario non valido")
        backup_lba = struct.unpack_from("<Q", header, 32)[0]
        entries_lba, count, entry_size, entries_crc = struct.unpack_from("<QIII", header, 72)
        table_bytes = min(count * entry_size, 16 * 1024 * 1024)
        source.seek(entries_lba * sector_size); table = source.read(table_bytes)
        if count * entry_size <= 16 * 1024 * 1024 and binascii.crc32(table) & 0xffffffff != entries_crc: anomalies.append("CRC tabella GPT non valido")
        rows=[]
        for index in range(min(count, len(table)//max(1,entry_size))):
            raw=table[index*entry_size:(index+1)*entry_size]
            if len(raw)<56 or not any(raw[:16]): continue
            first,last=struct.unpack_from("<QQ",raw,32)
            try:type_id=str(uuid.UUID(bytes_le=raw[:16]))
            except ValueError:type_id=raw[:16].hex()
            name=raw[56:min(len(raw),128)].decode("utf-16le","replace").rstrip("\0")
            row=_partition(index+1,"GPT",first,last-first+1,sector_size,size,name,type_id)
            if row["status"]=="valid": source.seek(row["offset"]);row["filesystem"]=_filesystem(source.read(2048))
            rows.append(row)
        backup={"lba":backup_lba,"offset":backup_lba*sector_size,"signature_valid":False,"matches_primary":False}
        if backup["offset"]+sector_size<=size:
            source.seek(backup["offset"]); backup_header=source.read(sector_size); backup["signature_valid"]=backup_header[:8]==b"EFI PART"
            if backup["signature_valid"]: backup["matches_primary"]=struct.unpack_from("<Q",backup_header,24)[0]==backup_lba
        if not backup["signature_valid"]: anomalies.append("Backup GPT assente o corrotto")
        rows.extend(_gaps(rows,size,sector_size))
        return {"scheme":"GPT","sector_size":sector_size,"partitions":rows,"anomalies":anomalies,"backup_gpt":backup}
