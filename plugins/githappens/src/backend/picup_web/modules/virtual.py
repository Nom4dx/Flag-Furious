from __future__ import annotations

import json
import shutil
import struct
from pathlib import Path
from typing import Any

from ..scanner import ScanConfig, scan_stream
from ..util import run

MAGICS = {
    b"QFI\xfb": "qcow2", b"KDMV": "vmdk", b"conectix": "vhd",
    b"vhdxfile": "vhdx", b"<<< QEMU QED Image >>>": "qed",
    b"<<< Oracle VM VirtualBox Disk Image >>>": "vdi",
}
EXTENSION_FORMATS = {".qcow": "qcow", ".qcow2": "qcow2", ".qed": "qed", ".vmdk": "vmdk", ".vdi": "vdi", ".vhd": "vhd", ".vhdx": "vhdx", ".iso": "iso", ".raw": "raw", ".img": "raw", ".dd": "raw"}


def identify(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        header = handle.read(0x9000)
        handle.seek(0, 2)
        physical = handle.tell()
    fmt = "raw"
    for magic, name in MAGICS.items():
        if header.startswith(magic):
            fmt = name
            break
    if len(header) >= 6 and header[0x8001:0x8006] == b"CD001":
        fmt = "iso"
    confidence = "magic"
    if fmt == "raw" and path.suffix.lower() in EXTENSION_FORMATS:
        fmt = EXTENSION_FORMATS[path.suffix.lower()]
        confidence = "extension"
    if fmt == "raw" and physical >= 512:
        with path.open("rb") as handle:
            handle.seek(-512, 2)
            if handle.read(8) == b"conectix":
                fmt = "vhd"; confidence = "footer-magic"
    result: dict[str, Any] = {"format": fmt, "format_confidence": confidence, "physical_size": physical, "sparse": path.stat().st_blocks * 512 < physical}
    if fmt in {"qcow", "qcow2"} and len(header) >= 72:
        magic, version = struct.unpack(">II", header[:8])
        result["format"] = "qcow" if version == 1 else "qcow2"
        backing_offset, backing_size = struct.unpack(">QI", header[8:20])
        cluster_bits = struct.unpack(">I", header[20:24])[0]
        virtual_size = struct.unpack(">Q", header[24:32])[0]
        crypt_method = struct.unpack(">I", header[32:36])[0]
        incompatible = struct.unpack(">Q", header[72:80])[0] if version >= 3 and len(header) >= 80 else 0
        result.update({"magic": hex(magic), "version": version, "virtual_size": virtual_size,
                       "cluster_size": 1 << cluster_bits, "encrypted": crypt_method != 0,
                       "dirty": bool(incompatible & 1), "backing_file_offset": backing_offset,
                       "backing_file_size": backing_size})
        if backing_offset and backing_size and backing_offset + backing_size <= physical:
            with path.open("rb") as handle:
                handle.seek(backing_offset)
                result["backing_file"] = handle.read(backing_size).decode("utf-8", "replace")
    return result


def _json_command(argv: list[str]) -> tuple[Any, dict[str, Any]]:
    record = run(argv)
    try:
        value = json.loads(record["stdout"]) if record["stdout"] else None
    except json.JSONDecodeError:
        value = None
    return value, record


def analyze(path: Path, config: ScanConfig) -> dict[str, Any]:
    details = identify(path)
    result: dict[str, Any] = {"metadata": details, "chain": [], "map": [], "snapshots": [], "commands": [], "warnings": [], "findings": []}
    if shutil.which("qemu-img"):
        info, rec = _json_command(["qemu-img", "info", "--output=json", "--force-share", str(path)])
        result["commands"].append(rec)
        if info:
            result["metadata"].update(info)
        chain, rec = _json_command(["qemu-img", "info", "--output=json", "--backing-chain", "--force-share", str(path)])
        result["commands"].append(rec)
        if isinstance(chain, list):
            result["chain"] = chain
        mapping, rec = _json_command(["qemu-img", "map", "--output=json", "--force-share", str(path)])
        result["commands"].append(rec)
        if isinstance(mapping, list):
            result["map"] = mapping
        snapshot = run(["qemu-img", "snapshot", "-l", str(path)])
        result["commands"].append(snapshot)
        result["snapshots"] = snapshot["stdout"].splitlines()
        check = run(["qemu-img", "check", "--output=json", str(path)], timeout=300)
        result["commands"].append(check)
    backing = details.get("backing_file")
    if backing:
        candidate = (path.parent / backing).resolve()
        if path.parent.resolve() not in candidate.parents and candidate != path.parent.resolve():
            result["warnings"].append("Backing path escapes evidence directory and was not followed")
        elif not candidate.is_file():
            result["warnings"].append(f"Missing backing file: {backing}")
        else:
            with candidate.open("rb") as handle:
                result["findings"].extend(scan_stream(handle, source=str(candidate), path=str(candidate), module="virtual", config=config))
    return result


def materialize_copy(path: Path, work_dir: Path) -> tuple[Path | None, list[dict[str, Any]], list[str]]:
    """Build a raw view only from a private duplicate; the evidence path is never a qemu-img output target."""
    commands: list[dict[str, Any]] = []
    warnings: list[str] = []
    if not shutil.which("qemu-img"):
        return None, commands, ["qemu-img unavailable; unified virtual view skipped"]
    work_dir.mkdir(parents=True, exist_ok=True)
    private = work_dir / (path.name + ".working-copy")
    with path.open("rb") as source, private.open("xb") as target:
        shutil.copyfileobj(source, target, 4 * 1024 * 1024)
    raw = work_dir / "unified-readonly-view.raw"
    record = run(["qemu-img", "convert", "-O", "raw", str(private), str(raw)], timeout=1800)
    commands.append(record)
    private.unlink(missing_ok=True)
    if not record["ok"]:
        warnings.append("Could not materialize unified raw view from private copy")
        raw.unlink(missing_ok=True)
        return None, commands, warnings
    raw.chmod(0o400)
    return raw, commands, warnings
