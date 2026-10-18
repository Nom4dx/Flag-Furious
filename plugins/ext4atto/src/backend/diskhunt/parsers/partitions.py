from __future__ import annotations
import struct
from typing import BinaryIO

MBR_TYPES = {0x01: "FAT12", 0x04: "FAT16", 0x06: "FAT16", 0x07: "NTFS/exFAT", 0x0B: "FAT32", 0x0C: "FAT32", 0x0E: "FAT16", 0x0F: "Extended", 0x05: "Extended", 0x85: "Linux extended", 0x11: "Hidden FAT12", 0x14: "Hidden FAT16", 0x16: "Hidden FAT16", 0x1B: "Hidden FAT32", 0x1C: "Hidden FAT32", 0x83: "Linux", 0xEE: "GPT protective"}
EXTENDED_TYPES = {0x05, 0x0F, 0x85}


def detect_filesystem(sector: bytes) -> str:
    if len(sector) >= 90:
        if sector[3:11] == b"EXFAT   ": return "exFAT"
        if sector[54:62].startswith(b"FAT12"): return "FAT12"
        if sector[54:62].startswith(b"FAT16"): return "FAT16"
        if sector[82:90].startswith(b"FAT32"): return "FAT32"
    if len(sector) >= 1082 and sector[1080:1082] == b"\x53\xef": return "ext2/3/4"
    return "unknown"


def _part(number: int, kind: str, start: int, length: int, sector_size: int, filesystem: str = "unknown", name: str = "") -> dict:
    return {"number": number, "type": kind, "filesystem": filesystem, "start_sector": start,
            "end_sector": start + length - 1 if length else start, "offset_sector": start,
            "offset_byte": start * sector_size, "size": length * sector_size, "status": "allocated", "name": name}


def inspect_partitions(handle: BinaryIO, size: int, sector_size: int = 512) -> tuple[str, list[dict], list[str]]:
    handle.seek(0); mbr = handle.read(512)
    anomalies: list[str] = []
    if len(mbr) < 512 or mbr[510:512] != b"\x55\xaa":
        handle.seek(0); probe = handle.read(2048)
        fs = detect_filesystem(probe)
        return "none", [_part(1, "whole image", 0, size // sector_size, sector_size, fs)], ["partition table absent; treating image as a filesystem"]
    entries = []
    for idx in range(4):
        raw = mbr[446 + idx * 16:462 + idx * 16]
        ptype, start, length = raw[4], struct.unpack_from("<I", raw, 8)[0], struct.unpack_from("<I", raw, 12)[0]
        if ptype and length:
            entries.append((idx + 1, ptype, start, length))
    if not entries:
        handle.seek(0); probe = handle.read(2048); fs = detect_filesystem(probe)
        if fs != "unknown":
            return "none", [_part(1, "whole image", 0, size // sector_size, sector_size, fs)], ["filesystem image without a partition table"]
    if any(ptype == 0xEE for _, ptype, _, _ in entries):
        return _inspect_gpt(handle, size, sector_size)
    parts = []
    occupied: list[tuple[int, int]] = []
    for number, ptype, start, length in entries:
        if ptype in EXTENDED_TYPES:
            parts.extend(_inspect_ebr(handle, start, sector_size, len(parts) + 5, anomalies))
            container = _part(number, MBR_TYPES.get(ptype, "Extended"), start, length, sector_size)
            container["status"] = "container"; parts.append(container); continue
        handle.seek(start * sector_size); probe = handle.read(2048)
        fs = detect_filesystem(probe)
        part = _part(number, MBR_TYPES.get(ptype, f"0x{ptype:02x}"), start, length, sector_size, fs)
        if part["offset_byte"] + part["size"] > size:
            part["status"] = "invalid"; anomalies.append(f"partition {number} exceeds image bounds")
        if any(start <= end and start + length - 1 >= begin for begin, end in occupied):
            part["status"] = "overlapping"; anomalies.append(f"partition {number} overlaps another partition")
        occupied.append((start, start + length - 1)); parts.append(part)
    _add_gaps(parts, size, sector_size)
    return "MBR", parts, anomalies


def _inspect_ebr(handle: BinaryIO, base: int, sector_size: int, number: int, anomalies: list[str]) -> list[dict]:
    result = []; relative = 0; visited = set()
    for _ in range(128):
        ebr_lba = base + relative
        if ebr_lba in visited: anomalies.append("EBR loop detected"); break
        visited.add(ebr_lba); handle.seek(ebr_lba * sector_size); ebr = handle.read(512)
        if len(ebr) < 512 or ebr[510:512] != b"\x55\xaa": anomalies.append(f"invalid EBR at sector {ebr_lba}"); break
        first, link = ebr[446:462], ebr[462:478]
        ptype = first[4]; local_start, length = struct.unpack_from("<II", first, 8)
        if ptype and length:
            start = ebr_lba + local_start; handle.seek(start * sector_size); probe = handle.read(2048)
            result.append(_part(number, MBR_TYPES.get(ptype, f"0x{ptype:02x}"), start, length, sector_size, detect_filesystem(probe)))
            number += 1
        link_type = link[4]; next_relative = struct.unpack_from("<I", link, 8)[0]
        if link_type not in EXTENDED_TYPES or not next_relative: break
        relative = next_relative
    return result


def _inspect_gpt(handle: BinaryIO, size: int, sector_size: int) -> tuple[str, list[dict], list[str]]:
    handle.seek(sector_size); hdr = handle.read(sector_size); anomalies = []
    if hdr[:8] != b"EFI PART":
        return "GPT-corrupt", [], ["protective MBR found but primary GPT signature is invalid"]
    entries_lba, count, entry_size = struct.unpack_from("<QII", hdr, 72)
    handle.seek(entries_lba * sector_size); table = handle.read(min(count * entry_size, 16 * 1024 * 1024))
    parts = []
    for idx in range(min(count, len(table) // entry_size)):
        raw = table[idx * entry_size:(idx + 1) * entry_size]
        if not any(raw[:16]): continue
        start, end = struct.unpack_from("<QQ", raw, 32)
        name = raw[56:128].decode("utf-16le", "replace").rstrip("\x00")
        handle.seek(start * sector_size); probe = handle.read(2048)
        parts.append(_part(idx + 1, "GPT partition", start, end - start + 1, sector_size, detect_filesystem(probe), name))
    backup_lba = struct.unpack_from("<Q", hdr, 32)[0]
    if backup_lba * sector_size >= size: anomalies.append("backup GPT header lies outside image")
    else:
        handle.seek(backup_lba * sector_size)
        if handle.read(8) != b"EFI PART": anomalies.append("backup GPT header is missing or corrupt")
    _add_gaps(parts, size, sector_size)
    return "GPT", parts, anomalies


def _add_gaps(parts: list[dict], size: int, sector_size: int) -> None:
    cursor = 0
    for part in sorted((p for p in parts if p["status"] not in {"invalid", "container"}), key=lambda p: p["start_sector"]):
        if part["start_sector"] > cursor:
            gap = _part(0, "unallocated", cursor, part["start_sector"] - cursor, sector_size)
            gap["status"] = "unallocated"; parts.append(gap)
        cursor = max(cursor, part["end_sector"] + 1)
    total = size // sector_size
    if cursor < total:
        gap = _part(0, "unallocated", cursor, total - cursor, sector_size)
        gap["status"] = "unallocated"; parts.append(gap)
