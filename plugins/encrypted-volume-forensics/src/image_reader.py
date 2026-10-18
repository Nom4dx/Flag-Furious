"""Immutable random-access image views and virtual-disk preparation.

The module never writes into evidence. RAW files are opened directly, split
images and VHD/VHDX images are materialized only below an explicit workspace
limit. Errors are returned to the caller as recoverable coverage warnings.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path


class SliceReader:
    """Expose a bounded partition as a seekable read-only file object.

    ``pybde`` accepts Python file objects. This view translates all seeks to a
    parent image without copying a large partition. Writes and file descriptor
    access are intentionally absent. The caller owns the parent handle.
    """

    def __init__(self, path: Path, offset: int, size: int):
        self.path, self.offset, self.size = Path(path), offset, size
        self._stream = self.path.open("rb", buffering=0)
        self._position = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self.size - self._position
        size = max(0, min(size, self.size - self._position))
        self._stream.seek(self.offset + self._position)
        data = self._stream.read(size)
        self._position += len(data)
        return data

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        base = 0 if whence == os.SEEK_SET else self._position if whence == os.SEEK_CUR else self.size
        position = base + offset
        if position < 0:
            raise OSError("seek before partition start")
        self._position = min(position, self.size)
        return self._position

    def tell(self) -> int:
        return self._position

    def get_size(self) -> int:
        """Compatibility helper used by several libyal Python bindings."""
        return self.size

    def close(self) -> None:
        self._stream.close()


def hashes(path: Path) -> dict:
    """Calculate MD5, SHA-1 and SHA-256 in one streaming pass.

    Hashes cover the full immutable source and are forensic identifiers, not
    password hashes. Read errors propagate because partial evidence hashes must
    never be presented as complete.
    """
    contexts = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    size = 0
    with Path(path).open("rb") as source:
        while block := source.read(8 * 1024 * 1024):
            size += len(block)
            for digest in contexts.values():
                digest.update(block)
    return {**{name: digest.hexdigest() for name, digest in contexts.items()}, "bytes_hashed": size}


def container_type(path: Path) -> str:
    """Identify RAW, fixed/dynamic VHD, VHDX, split image or BEK by content."""
    with Path(path).open("rb") as source:
        head = source.read(65536)
        source.seek(max(0, path.stat().st_size - 512))
        tail = source.read(512)
    if head[:8] == b"vhdxfile":
        return "vhdx"
    if tail[:8] == b"conectix" or head[:8] == b"conectix":
        return "vhd"
    if path.suffix.casefold() == ".001":
        return "split_raw"
    if path.suffix.casefold() == ".bek":
        return "bek"
    return "raw"


def prepare(path: Path, output_dir: Path, max_bytes: int, runner) -> tuple[Path, dict, list[str]]:
    """Return an analyzable RAW path, converting only with bounded output.

    VHD/VHDX conversion uses ``qemu-img`` without a shell. Split images are
    merged from regular siblings with sequential suffixes. The returned copy is
    chmod 0400. RAW evidence is returned directly.
    """
    kind = container_type(path)
    info = {"source_container": kind, "analysis_path_is_original": kind in {"raw", "bek"}}
    warnings: list[str] = []
    if kind in {"raw", "bek"}:
        return path, info, warnings
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / "prepared-image.raw"
    if kind in {"vhd", "vhdx"}:
        binary = shutil.which("qemu-img")
        if not binary:
            return path, info, ["qemu-img non disponibile: immagine virtuale inventariata senza conversione"]
        inspected = runner.run([binary, "info", "--output=json", str(path)], 30)
        try:
            description=json.loads(inspected["stdout"] or "{}")
        except (ValueError, json.JSONDecodeError):
            description={}
        if not isinstance(description,dict):description={}
        detected_format=str(description.get("format","")).casefold()
        try:virtual_size=int(description.get("virtual-size",0) or 0)
        except (TypeError,ValueError):virtual_size=0
        info["detected_format"]=detected_format or None
        info["virtual_size"] = virtual_size
        if inspected.get("exit_code")!=0 or inspected.get("output_truncated") or inspected.get("timed_out"):
            return path,info,["qemu-img info incompleto: conversione non eseguita"]
        if description.get("backing-filename") or description.get("full-backing-filename"):
            return path,info,["Immagine virtuale con backing file esterno rifiutata"]
        expected={"vhd":{"vpc"},"vhdx":{"vhdx"}}[kind]
        if detected_format not in expected:
            return path,info,[f"Formato interno {detected_format or 'sconosciuto'} non coerente con il contenitore {kind.upper()}"]
        if not virtual_size or virtual_size > max_bytes:
            return path, info, [f"Conversione {kind.upper()} non eseguita: virtual size oltre il workspace"]
        partial=target.with_name(target.name+".partial")
        partial.unlink(missing_ok=True)
        result = runner.run([binary, "convert", "-f", detected_format, "-O", "raw", str(path), str(partial)],
                            600, max_file_size=max_bytes)
        if result.get("exit_code") != 0 or result.get("output_truncated") or result.get("timed_out") or not partial.is_file():
            partial.unlink(missing_ok=True)
            return path, info, [f"Conversione {kind.upper()} fallita: {result['stderr'][-300:]}"]
        if partial.stat().st_size!=virtual_size:
            partial.unlink(missing_ok=True)
            return path,info,[f"Conversione {kind.upper()} incompleta: dimensione raw diversa dal virtual size"]
        partial.chmod(0o400);os.replace(partial,target)
    else:
        stem = str(path)[:-4]
        total = 0
        with target.open("xb") as destination:
            index = 1
            while True:
                part = Path(f"{stem}.{index:03d}")
                if not part.is_file() or part.is_symlink():
                    break
                total += part.stat().st_size
                if total > max_bytes:
                    destination.close(); target.unlink(missing_ok=True)
                    return path, info, ["Merge immagine segmentata interrotto dal workspace budget"]
                with part.open("rb") as source:
                    shutil.copyfileobj(source, destination, 4 * 1024 * 1024)
                index += 1
        info["segments"] = index - 1
    target.chmod(0o400)
    info["analysis_path_is_original"] = False
    info["prepared_size"] = target.stat().st_size
    return target, info, warnings
