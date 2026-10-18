from __future__ import annotations

import re
import shutil
import struct
from pathlib import Path
from typing import Any

from ..scanner import ScanConfig, scan_bytes, scan_stream
from ..util import run


def signatures(path: Path) -> list[dict[str, Any]]:
    with path.open("rb") as handle:
        data = handle.read(min(path.stat().st_size, 16 * 1024 * 1024))
    found = []
    tests = [
        (54, (b"FAT12", b"FAT16"), "FAT12/16"), (82, (b"FAT32",), "FAT32"),
        (3, (b"NTFS    ",), "NTFS"), (3, (b"EXFAT   ",), "exFAT"),
        (1024 + 56, (b"\x53\xef",), "ext2/3/4"), (1024, (b"BD",), "HFS"),
        (0x8001, (b"CD001",), "ISO9660"),
    ]
    for offset, magics, fs in tests:
        if any(data[offset:offset + len(magic)] == magic for magic in magics):
            found.append({"filesystem": fs, "offset": offset, "confidence": 1.0, "hypothesis": "known signature"})
    for match in re.finditer(b"\x53\xef", data):
        super_start = match.start() - 56
        if super_start >= 0 and not any(item["offset"] == super_start + 56 for item in found):
            found.append({"filesystem": "ext candidate", "offset": super_start, "confidence": 0.65, "hypothesis": "embedded/corrupt superblock signature"})
    if path.stat().st_size in (160 * 1024, 180 * 1024, 320 * 1024, 360 * 1024, 720 * 1024, 1200 * 1024, 1440 * 1024, 2880 * 1024):
        found.append({"filesystem": "floppy image", "offset": 0, "confidence": 0.8, "hypothesis": "legacy floppy size"})
    return found


def _partition_offsets(text: str) -> list[int]:
    offsets: list[int] = [0]
    for line in text.splitlines():
        match = re.match(r"\s*\d+:\s+\S+\s+(\d+)\s+", line)
        if match:
            offsets.append(int(match.group(1)))
    return sorted(set(offsets))


def analyze(path: Path, config: ScanConfig, recovery_dir: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"signatures": signatures(path), "partitions": [], "filesystems": [], "deleted": [], "commands": [], "warnings": [], "findings": []}
    if shutil.which("mmls"):
        record = run(["mmls", str(path)], timeout=120)
        result["commands"].append(record)
        result["partitions"] = record["stdout"].splitlines()
        offsets = _partition_offsets(record["stdout"])
    else:
        offsets = [0]
    for sector in offsets[:64]:
        valid_filesystem = False
        if shutil.which("fsstat"):
            record = run(["fsstat", "-o", str(sector), str(path)], timeout=120)
            result["commands"].append(record)
            if record["ok"]:
                valid_filesystem = True
                result["filesystems"].append({"sector_offset": sector, "byte_offset": sector * 512, "fsstat": record["stdout"]})
        if shutil.which("fls"):
            record = run(["fls", "-r", "-p", "-l", "-o", str(sector), str(path)], timeout=180)
            result["commands"].append(record)
            if record["ok"]:
                for line in record["stdout"].splitlines():
                    if line.startswith("-") or " * " in line or line.startswith("r/r *"):
                        result["deleted"].append({"sector_offset": sector, "entry": line})
        if valid_filesystem and shutil.which("tsk_recover"):
            target = recovery_dir / f"offset_{sector}"
            target.mkdir(parents=True, exist_ok=True)
            record = run(["tsk_recover", "-e", "-o", str(sector), str(path), str(target)], timeout=300)
            result["commands"].append(record)
    with path.open("rb") as handle:
        result["findings"] = scan_stream(handle, source=str(path), path=str(path), module="legacy", config=config)
    if shutil.which("strings"):
        for label, option in (("ascii", None), ("utf16le", "-el"), ("utf16be", "-eb")):
            command = ["strings", "-a", "-n", "6"]
            if option:
                command.append(option)
            command.append(str(path))
            record = run(command, timeout=300)
            result["commands"].append({**record, "stdout": record["stdout"][:200_000]})
            if record["stdout"]:
                result["findings"].extend(scan_bytes(record["stdout"].encode(), source=str(path), path=str(path), module="legacy", config=config, method=f"strings-{label}"))
    return result
