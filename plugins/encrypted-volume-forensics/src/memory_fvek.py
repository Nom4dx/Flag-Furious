"""Bounded extraction of BitLocker FVEK candidates from Windows memory images.

The scanner implements the stable pool layouts documented by the open-source
Volatility-BitLocker plugin (``None``, ``Cngb`` and ``FVEc`` pools).  A pool hit
is only a *candidate*: the resulting 66-byte Dislocker key must later decrypt a
BitLocker volume and yield a structurally valid filesystem before it is marked
valid.  The module never executes code from memory and never logs key bytes.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def _nontrivial(value: bytes) -> bool:
    """Reject empty, uniform and very low-diversity key material."""
    return len(value) == 64 and any(value) and len(set(value)) >= 8


def _pool_start(data: bytes, tag_offset: int, base: int) -> tuple[int, int]:
    """Return physical pool offset and x64 pool allocation size.

    Windows pool tags follow the four-byte pool header prefix.  On 64-bit
    captures ``BlockSize`` is stored at byte two in units of 16 bytes.  Size is
    used as corroborating evidence and is not trusted as an absolute boundary.
    """
    local = tag_offset - 4
    if local < 0:
        return -1, 0
    return base + local, data[local + 2] * 16


def _candidate(mode: int, material: bytes, offset: int, layout: str, pool_size: int) -> dict | None:
    """Normalize one candidate without exposing its key in result metadata."""
    if not _nontrivial(material):
        return None
    payload = bytes((mode, 0x80)) + material
    return {
        "source_offset": offset,
        "layout": layout,
        "pool_size": pool_size,
        "cipher_id": f"0x80{mode:02x}",
        "key_bits": 256 if mode in {1, 3, 5} else 128,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "confidence": 0.88,
        "status": "candidate_requires_volume_validation",
        "payload": payload,
    }


def scan(path: Path, byte_budget: int, max_candidates: int = 32) -> tuple[list[dict], list[str]]:
    """Scan a memory image in streaming windows for known BitLocker pools.

    Input is a local read-only memory image. Output candidates retain physical
    offsets and a private ``payload`` field for artifact creation.  Duplicate
    keys are removed by SHA-256. Truncation is explicitly reported.
    """
    size = path.stat().st_size
    limit = min(size, max(0, int(byte_budget)))
    overlap = 2048
    block_size = 8 * 1024 * 1024
    candidates: list[dict] = []
    seen: set[str] = set()
    tail = b""
    consumed = 0
    with path.open("rb") as source:
        while consumed < limit and len(candidates) < max_candidates:
            block = source.read(min(block_size, limit - consumed))
            if not block:
                break
            data = tail + block
            base = consumed - len(tail)
            for tag in (b"None", b"Cngb", b"FVEc"):
                cursor = 0
                while len(candidates) < max_candidates:
                    hit = data.find(tag, cursor)
                    if hit < 0:
                        break
                    cursor = hit + 1
                    pool_offset, pool_size = _pool_start(data, hit, base)
                    local = hit - 4
                    rows: list[tuple[int, bytes, str]] = []
                    if tag == b"None" and 1230 <= pool_size <= 1450:
                        f1 = data[local + 0x9C : local + 0x9C + 64]
                        f2 = data[local + 0xE0 : local + 0xE0 + 64]
                        f3 = data[local + 0xC0 : local + 0xC0 + 64]
                        if len(f1) == len(f2) == 64 and f1[:16] == f2[:16]:
                            rows.append((4 if f1[:32] == f2[:32] else 5, f1, "win10_none_xts"))
                        if len(f1) == len(f3) == 64 and f1[:16] == f3[:16]:
                            rows.append((3 if f1[:32] == f3[:32] else 2, f1, "win10_none_cbc"))
                    elif tag == b"Cngb" and 632 <= pool_size <= 672:
                        f1 = data[local + 0x6C : local + 0x6C + 64]
                        f2 = data[local + 0x90 : local + 0x90 + 64]
                        if len(f1) == len(f2) == 64 and f1[:16] == f2[:16]:
                            rows.append((3 if f1[:32] == f2[:32] else 2, f1, "win8_cngb"))
                    elif tag == b"FVEc" and pool_size in {528, 1008}:
                        cid = data[local + 44 : local + 46]
                        f1 = data[local + 48 : local + 80]
                        f2_offset = 528 if pool_size == 1008 else 480
                        f2 = data[local + f2_offset : local + f2_offset + 32]
                        if len(cid) == 2 and cid[1] == 0x80 and cid[0] <= 3 and len(f1) == len(f2) == 32:
                            rows.append((cid[0], f1 + f2, "vista_fvec_x64"))
                    for mode, material, layout in rows:
                        row = _candidate(mode, material, pool_offset, layout, pool_size)
                        if row and row["sha256"] not in seen:
                            seen.add(row["sha256"]); candidates.append(row)
            consumed += len(block)
            tail = data[-overlap:]
    warnings = []
    if limit < size:
        warnings.append(f"Scansione RAM limitata a {limit} di {size} byte")
    if len(candidates) >= max_candidates:
        warnings.append(f"Limite di {max_candidates} candidati FVEK raggiunto")
    return candidates, warnings


def is_memory_candidate(path: Path) -> bool:
    """Return a conservative extension/content hint for memory evidence."""
    suffix = path.suffix.casefold()
    if suffix in {".mem", ".dmp", ".vmem", ".lime"}:
        return True
    with path.open("rb") as source:
        head = source.read(2 * 1024 * 1024)
    return any(tag in head for tag in (b"PAGE", b"DUMP", b"None", b"Cngb", b"FVEc"))
