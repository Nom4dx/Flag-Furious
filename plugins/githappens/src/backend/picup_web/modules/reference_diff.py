from __future__ import annotations

import difflib
import json
import sqlite3
from pathlib import Path
from typing import Any

from ..scanner import ScanConfig, scan_bytes
from ..util import iter_files, mime_for, sha256_file


def _inventory(root: Path, config: ScanConfig) -> dict[str, Path]:
    if root.is_file():
        return {root.name: root}
    return {str(path.relative_to(root)): path for path in iter_files(root,limit=10_000,diagnostics=config.diagnostics)}


def _first_difference(left: Path, right: Path, config: ScanConfig, maximum: int=64*1024*1024) -> int | None:
    offset = 0
    with left.open("rb") as a, right.open("rb") as b:
        while True:
            remaining=min(maximum-offset, max(0, config.max_input_bytes-config.bytes_read))
            if remaining<=0:
                if left.stat().st_size>offset or right.stat().st_size>offset:config.warn("File diff fermato al limite 64 MiB per confronto")
                return None
            chunk=min(1024 * 1024,remaining//2)
            if chunk<=0:return None
            x, y = a.read(chunk), b.read(chunk)
            config.bytes_read += len(x)+len(y)
            if x == y:
                if not x:
                    return None
                offset += len(x)
                continue
            for index, pair in enumerate(zip(x, y)):
                if pair[0] != pair[1]:
                    return offset + index
            return offset + min(len(x), len(y))


def _text_diff(left: Path, right: Path, config: ScanConfig) -> tuple[list[str], list[str]]:
    try:
        before_raw=config.read_prefix(left,4*1024*1024);after_raw=config.read_prefix(right,4*1024*1024)
        if len(before_raw)<left.stat().st_size or len(after_raw)<right.stat().st_size:config.warn("Testo diff limitato a 4 MiB per versione")
        before = before_raw.decode("utf-8").splitlines()
        after = after_raw.decode("utf-8").splitlines()
    except (UnicodeError, OSError):
        return [], []
    lines = list(difflib.unified_diff(before, after, fromfile=str(left), tofile=str(right), n=3))
    removed = [line[1:] for line in lines if line.startswith("-") and not line.startswith("---")]
    return lines[:10_000], removed


def analyze(base: Path, suspect: Path | None, config: ScanConfig) -> dict[str, Any]:
    if suspect is None:
        suffixes = {".bak", ".old", ".orig", ".swp", ".tmp"}
        versions = [{"path": str(path), "type": "historical-copy", "confidence": 0.75} for path in iter_files(base) if path.suffix.lower() in suffixes or "backup" in path.name.lower()]
        return {"mode": "single", "differences": versions, "findings": []}
    left, right = _inventory(base,config), _inventory(suspect,config)
    differences: list[dict[str, Any]] = []
    findings = []
    removed_hashes: dict[str, str] = {}
    added_hashes: dict[str, str] = {}
    for path in sorted(left.keys() - right.keys()):
        raw=config.read_prefix(left[path],16*1024*1024);digest=__import__("hashlib").sha256(raw).hexdigest();complete=len(raw)==left[path].stat().st_size
        if complete:removed_hashes[digest]=path
        differences.append({"path": path, "type": "removed", "old_hash": digest if complete else None, "old_visible_hash":digest,"old_hash_complete":complete,"new_hash": None, "size": left[path].stat().st_size, "offset": 0, "source": str(base), "confidence": 1.0 if complete else .7})
        data = config.read_prefix(left[path],64*1024*1024)
        findings.extend(scan_bytes(data, source=str(base), path=path, module="diff", config=config, method="removed-file"))
    for path in sorted(right.keys() - left.keys()):
        raw=config.read_prefix(right[path],16*1024*1024);digest=__import__("hashlib").sha256(raw).hexdigest();complete=len(raw)==right[path].stat().st_size
        if complete:added_hashes[digest]=path
        differences.append({"path": path, "type": "added", "old_hash": None, "new_hash": digest if complete else None,"new_visible_hash":digest,"new_hash_complete":complete,"size": right[path].stat().st_size, "offset": 0, "source": str(suspect), "confidence": 1.0 if complete else .7})
    for digest in set(removed_hashes) & set(added_hashes):
        differences.append({"path": added_hashes[digest], "old_path": removed_hashes[digest], "type": "renamed", "old_hash": digest, "new_hash": digest, "offset": None, "size": right[added_hashes[digest]].stat().st_size, "source": str(suspect), "confidence": 0.98})
    for path in sorted(left.keys() & right.keys()):
        old_raw=config.read_prefix(left[path],16*1024*1024);new_raw=config.read_prefix(right[path],16*1024*1024)
        old_hash=__import__("hashlib").sha256(old_raw).hexdigest();new_hash=__import__("hashlib").sha256(new_raw).hexdigest()
        old_complete=len(old_raw)==left[path].stat().st_size;new_complete=len(new_raw)==right[path].stat().st_size
        if old_hash == new_hash and old_complete and new_complete:
            if left[path].stat().st_mtime_ns != right[path].stat().st_mtime_ns:
                differences.append({"path": path, "type": "metadata", "old_hash": old_hash, "new_hash": new_hash, "offset": None, "size": right[path].stat().st_size, "source": str(suspect), "confidence": 1.0})
            continue
        lines, removed = _text_diff(left[path], right[path],config)
        offset = _first_difference(left[path], right[path],config)
        differences.append({"path": path, "type": "modified", "old_hash": old_hash if old_complete else None,"new_hash":new_hash if new_complete else None,"old_visible_hash":old_hash,"new_visible_hash":new_hash,"old_hash_complete":old_complete,"new_hash_complete":new_complete,"offset": offset, "size": right[path].stat().st_size, "preview": lines[:200], "source": str(suspect), "confidence": 1.0 if old_complete and new_complete else .7})
        if removed:
            findings.extend(scan_bytes("\n".join(removed).encode(), source=str(base), path=path, module="diff", config=config, method="removed-lines"))
    return {"mode": "pair", "differences": differences, "findings": findings}

