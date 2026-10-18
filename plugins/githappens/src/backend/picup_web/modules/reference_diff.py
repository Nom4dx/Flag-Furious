from __future__ import annotations

import difflib
import json
import sqlite3
from pathlib import Path
from typing import Any

from ..scanner import ScanConfig, scan_bytes
from ..util import iter_files, mime_for, sha256_file


def _inventory(root: Path) -> dict[str, Path]:
    if root.is_file():
        return {root.name: root}
    return {str(path.relative_to(root)): path for path in iter_files(root)}


def _first_difference(left: Path, right: Path) -> int | None:
    offset = 0
    with left.open("rb") as a, right.open("rb") as b:
        while True:
            x, y = a.read(1024 * 1024), b.read(1024 * 1024)
            if x == y:
                if not x:
                    return None
                offset += len(x)
                continue
            for index, pair in enumerate(zip(x, y)):
                if pair[0] != pair[1]:
                    return offset + index
            return offset + min(len(x), len(y))


def _text_diff(left: Path, right: Path) -> tuple[list[str], list[str]]:
    try:
        before = left.read_text("utf-8").splitlines()
        after = right.read_text("utf-8").splitlines()
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
    left, right = _inventory(base), _inventory(suspect)
    differences: list[dict[str, Any]] = []
    findings = []
    removed_hashes: dict[str, str] = {}
    added_hashes: dict[str, str] = {}
    for path in sorted(left.keys() - right.keys()):
        digest = sha256_file(left[path]); removed_hashes[digest] = path
        data = left[path].read_bytes()[:64 * 1024 * 1024]
        differences.append({"path": path, "type": "removed", "old_hash": digest, "new_hash": None, "size": left[path].stat().st_size, "offset": 0, "source": str(base), "confidence": 1.0})
        findings.extend(scan_bytes(data, source=str(base), path=path, module="diff", config=config, method="removed-file"))
    for path in sorted(right.keys() - left.keys()):
        digest = sha256_file(right[path]); added_hashes[digest] = path
        differences.append({"path": path, "type": "added", "old_hash": None, "new_hash": digest, "size": right[path].stat().st_size, "offset": 0, "source": str(suspect), "confidence": 1.0})
    for digest in set(removed_hashes) & set(added_hashes):
        differences.append({"path": added_hashes[digest], "old_path": removed_hashes[digest], "type": "renamed", "old_hash": digest, "new_hash": digest, "offset": None, "size": right[added_hashes[digest]].stat().st_size, "source": str(suspect), "confidence": 0.98})
    for path in sorted(left.keys() & right.keys()):
        old_hash, new_hash = sha256_file(left[path]), sha256_file(right[path])
        if old_hash == new_hash:
            if left[path].stat().st_mtime_ns != right[path].stat().st_mtime_ns:
                differences.append({"path": path, "type": "metadata", "old_hash": old_hash, "new_hash": new_hash, "offset": None, "size": right[path].stat().st_size, "source": str(suspect), "confidence": 1.0})
            continue
        lines, removed = _text_diff(left[path], right[path])
        offset = _first_difference(left[path], right[path])
        differences.append({"path": path, "type": "modified", "old_hash": old_hash, "new_hash": new_hash, "offset": offset, "size": right[path].stat().st_size, "preview": lines[:200], "source": str(suspect), "confidence": 1.0})
        if removed:
            findings.extend(scan_bytes("\n".join(removed).encode(), source=str(base), path=path, module="diff", config=config, method="removed-lines"))
    return {"mode": "pair", "differences": differences, "findings": findings}

