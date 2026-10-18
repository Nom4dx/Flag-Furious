from __future__ import annotations
import codecs
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable
from .budget import ByteBudget, BudgetExhausted

DEFAULT_PREFIXES = ["picoCTF{", "CTF{", "flag{", "HTB{", "FLAG{", "SRDNLEN{"]


def compile_flag_patterns(prefix: str | None, regex: bool, prefix_list: list[str] | None = None) -> list[tuple[str, re.Pattern[bytes]]]:
    prefixes = list(dict.fromkeys((prefix_list or []) + ([prefix] if prefix else []))) or DEFAULT_PREFIXES
    patterns = []
    for item in prefixes:
        expression = item if regex else re.escape(item)
        try:
            patterns.append((item, re.compile(expression.encode() + rb"[^\x00-\x1f\x7f\r\n]{0,240}?\}")))
        except re.error as exc:
            raise ValueError(f"invalid flag regex: {exc}") from exc
    return patterns


def score_candidate(value: bytes, method: str, exact: bool, complete: bool) -> tuple[int, list[str]]:
    score = 20; reasons = []
    if exact: score += 25; reasons.append("exact prefix")
    if complete: score += 25; reasons.append("closing brace")
    if all(32 <= byte < 127 for byte in value): score += 15; reasons.append("printable ASCII")
    weights = {"filesystem": 15, "inode": 12, "journal": 9, "slack": 7, "unallocated": 5, "carving": 3, "raw": 2}
    score += weights.get(method, 0)
    return min(score, 100), reasons


def scan_bytes(data: bytes, absolute_base: int, patterns: list[tuple[str, re.Pattern[bytes]]], *, partition: dict | None = None, source: str = "raw", method: str = "raw") -> list[dict]:
    found = []
    variants = [(data, 1, "ASCII/UTF-8")]
    # Removing UTF-16 NUL bytes preserves an approximate offset mapping.
    if len(data) > 3:
        variants.extend([(data[0::2], 2, "UTF-16LE"), (data[1::2], 2, "UTF-16LE")])
    seen = set()
    for view, scale, encoding in variants:
        for prefix, pattern in patterns:
            for match in pattern.finditer(view):
                raw = match.group(0); offset = absolute_base + match.start() * scale
                key = (offset, raw)
                if key in seen: continue
                seen.add(key)
                value = raw.decode("utf-8", "replace")
                confidence, reasons = score_candidate(raw, method, True, raw.endswith(b"}"))
                clean = lambda chunk: "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
                before = clean(view[max(0, match.start()-32):match.start()])
                after = clean(view[match.end():match.end()+32])
                part_offset = partition["offset_byte"] if partition else 0
                found.append({"candidate": value, "prefix": prefix, "absolute_offset": offset,
                    "partition_offset": offset - part_offset, "partition": partition.get("number") if partition else None,
                    "filesystem": partition.get("filesystem", "unknown") if partition else "unknown", "source": source,
                    "method": f"{method}:{encoding}", "context_before": before, "context_after": after,
                    "confidence": confidence, "confidence_reasons": reasons, "status": "CANDIDATE"})
    # Generic CTF ASCII-art recovery: join printable characters represented as `( x )`.
    tokens = list(re.finditer(rb"\(\s([\x20-\x7e])\s\)", data))
    if len(tokens) >= 4:
        reconstructed = b"".join(token.group(1) for token in tokens)
        for prefix, pattern in patterns:
            for match in pattern.finditer(reconstructed):
                first = tokens[match.start()] if match.start() < len(tokens) else tokens[0]
                raw = match.group(0); offset = absolute_base + first.start()
                confidence, reasons = score_candidate(raw, "raw", True, raw.endswith(b"}"))
                found.append({"candidate": raw.decode("utf-8", "replace"), "prefix": prefix,
                    "absolute_offset": offset, "partition_offset": offset - (partition["offset_byte"] if partition else 0),
                    "partition": partition.get("number") if partition else None,
                    "filesystem": partition.get("filesystem", "unknown") if partition else "unknown",
                    "source": source, "method": f"{method}:ASCII-art token reconstruction",
                    "context_before": "", "context_after": "", "confidence": min(confidence, 72),
                    "confidence_reasons": reasons + ["heuristic ASCII-art reconstruction"],
                    "status": "CANDIDATA — RICOSTRUZIONE PARZIALE"})
    return found


def scan_ranges(path: Path, ranges: Iterable[tuple[int, int, dict | None, str]], patterns, budget: ByteBudget, max_request: int, on_chunk: Callable[[int], None] | None = None) -> list[dict]:
    results = []; overlap = 512
    with path.open("rb") as handle:
        for start, length, partition, method in ranges:
            cursor = start; tail = b""
            while cursor < start + length:
                requested = min(max_request, start + length - cursor)
                try: block = budget.read(handle, cursor, requested, "search", max_request)
                except BudgetExhausted: return results
                if not block: break
                combined = tail + block
                results.extend(scan_bytes(combined, cursor - len(tail), patterns, partition=partition, source="disk image", method=method))
                tail = combined[-overlap:]
                cursor += len(block)
                if on_chunk: on_chunk(len(block))
    unique = {(item["absolute_offset"], item["candidate"]): item for item in results}
    return sorted(unique.values(), key=lambda item: (-item["confidence"], item["absolute_offset"]))


SIGNATURES = [
    ("jpeg", b"\xff\xd8\xff", b"\xff\xd9"), ("png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    ("gif", b"GIF8", b"\x3b"), ("pdf", b"%PDF-", b"%%EOF"), ("zip", b"PK\x03\x04", b"PK\x05\x06"),
    ("rar", b"Rar!\x1a\x07", None), ("7z", b"7z\xbc\xaf\x27\x1c", None), ("elf", b"\x7fELF", None),
    ("pe", b"MZ", None), ("sqlite", b"SQLite format 3\x00", None),
]


def carve(path: Path, output: Path, ranges, budget: ByteBudget, max_request: int, custom: list[dict[str, str]] | None = None, on_chunk: Callable[[int], None] | None = None) -> list[dict]:
    signatures = list(SIGNATURES)
    for item in custom or []:
        signatures.append((item["name"], bytes.fromhex(item["header"]), bytes.fromhex(item["footer"]) if item.get("footer") else None))
    output.mkdir(parents=True, exist_ok=True); results = []
    max_artifacts = 500
    with path.open("rb") as handle:
        for start, length, part, _ in ranges:
            cursor = start; tail = b""
            while cursor < start + length:
                try: block = budget.read(handle, cursor, min(max_request, start + length - cursor), "carving", max_request)
                except BudgetExhausted: return results
                if not block: break
                data = tail + block; base = cursor - len(tail)
                for kind, header, footer in signatures:
                    pos = 0
                    while (hit := data.find(header, pos)) >= 0:
                        if len(results) >= max_artifacts: return results
                        if kind == "pe":
                            if hit + 64 > len(data): break
                            pe_offset = int.from_bytes(data[hit + 60:hit + 64], "little")
                            if pe_offset > 1024 or data[hit + pe_offset:hit + pe_offset + 4] != b"PE\x00\x00": pos = hit + 2; continue
                        if kind == "elf" and (hit + 6 > len(data) or data[hit + 4] not in {1, 2} or data[hit + 5] not in {1, 2}): pos = hit + 4; continue
                        footer_pos = data.find(footer, hit + len(header)) if footer else -1
                        complete = footer_pos >= 0
                        end = footer_pos + len(footer) if complete else min(len(data), hit + 1024 * 1024)
                        payload = data[hit:end]
                        name = f"carved_{base + hit:016x}.{kind}"
                        target = output / name
                        if not target.exists(): target.write_bytes(payload)
                        results.append({"name": name, "type": kind, "absolute_offset": base + hit,
                            "partition": part.get("number") if part else None, "size": len(payload),
                            "status": "CARVED" if complete or footer is None else "PARTIAL", "confidence": 85 if complete else 55})
                        pos = hit + len(header)
                tail = data[-64:]; cursor += len(block)
                if on_chunk: on_chunk(len(block))
    return results
