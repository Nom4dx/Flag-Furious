"""Bounded recursive decoder for common document payload encodings."""

from __future__ import annotations

import base64
import re

from .reporting import ModuleResult

MAX_CANDIDATES = 2_000
MAX_DECODED_BYTES = 16 * 1024**2
MAX_DECODED_ITEMS = 1_000


def decode_payloads(values: list[dict], source: str) -> ModuleResult:
    """Decode Base64, hexadecimal and Brainfuck candidates.

    Input: normalized evidence records/source. Output: transformation chains.
    Invalid candidates are ignored. Limits: 2,000 examined values, 1,000 output
    items, 16 MiB cumulative decoded bytes, 3 decode levels, 4 MiB/candidate and
    2 million Brainfuck steps. Security: decoded bytes are
    data and never executed. Example: ``decode_payloads(metadata, "a.pdf")``.
    """
    result = ModuleResult("payloads")
    queue = []
    for item in values[:2000]:
        value = item.get("normalized_value") or item.get("text") or item.get("raw_value")
        if isinstance(value, str):
            queue.append((value, item.get("source", source), item.get("offset"), []))
    seen = set()
    decoded_bytes = 0
    processed = 0
    limited = False
    for value, origin, offset, chain in queue:
        if processed >= MAX_CANDIDATES:
            limited = True
            break
        processed += 1
        if (value, tuple(chain)) in seen or len(chain) >= 3 or len(value) > 4 * 1024**2:
            continue
        seen.add((value, tuple(chain)))
        candidates = []
        compact = re.sub(r"\s+", "", value)
        if len(compact) >= 8 and len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
            try:
                candidates.append((base64.b64decode(compact, validate=True), "base64"))
            except ValueError:
                pass
        if len(compact) >= 8 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
            candidates.append((bytes.fromhex(compact), "hex"))
        if len(value) >= 8 and set(value) <= set("><+-.,[] \r\n\t"):
            try:
                candidates.append((_brainfuck(value), "brainfuck"))
            except ValueError as exc:
                result.warnings.append(str(exc))
        for raw, decoder in candidates:
            if not raw or len(raw) > 4 * 1024**2:
                continue
            if len(result.items) >= MAX_DECODED_ITEMS or decoded_bytes + len(raw) > MAX_DECODED_BYTES:
                limited = True
                break
            decoded = raw.decode("utf-8", "replace")
            printable = sum(c.isprintable() or c in "\r\n\t" for c in decoded) / max(1, len(decoded))
            if printable < 0.7:
                continue
            decoded_bytes += len(raw)
            item = {"type": "decoded_payload", "raw_value": value[:10000], "normalized_value": decoded[:4 * 1024**2], "source": origin, "offset": offset, "size": len(raw), "parser": "payload-decoder", "decoder": decoder, "decoder_chain": chain + [decoder], "confidence": min(0.98, 0.72 + printable * 0.25)}
            result.items.append(item)
            queue.append((decoded, origin, offset, chain + [decoder]))
        if limited:
            break
    if limited:
        result.status = "partial"
        result.warnings.append("Decodifica payload interrotta al budget cumulativo di candidati, risultati o byte")
    result.metrics = {"decoded": len(result.items), "decoded_bytes": decoded_bytes, "candidates_examined": processed, "candidate_limit": MAX_CANDIDATES, "decoded_byte_limit": MAX_DECODED_BYTES}
    return result


def _brainfuck(program: str) -> bytes:
    """Interpret Brainfuck in a bounded VM; no host operations are possible."""
    code = "".join(c for c in program if c in "><+-.,[]")
    pairs, stack = {}, []
    for index, token in enumerate(code):
        if token == "[":
            stack.append(index)
        elif token == "]":
            if not stack:
                raise ValueError("Brainfuck: parentesi non bilanciate")
            other = stack.pop(); pairs[index] = other; pairs[other] = index
    if stack:
        raise ValueError("Brainfuck: parentesi non bilanciate")
    tape = bytearray(30000); pointer = pc = steps = 0; output = bytearray()
    while pc < len(code):
        steps += 1
        if steps > 2_000_000 or len(output) > 4 * 1024**2:
            raise ValueError("Brainfuck: budget esecuzione esaurito")
        token = code[pc]
        if token == ">": pointer = (pointer + 1) % len(tape)
        elif token == "<": pointer = (pointer - 1) % len(tape)
        elif token == "+": tape[pointer] = (tape[pointer] + 1) & 255
        elif token == "-": tape[pointer] = (tape[pointer] - 1) & 255
        elif token == ".": output.append(tape[pointer])
        elif token == "[" and not tape[pointer]: pc = pairs[pc]
        elif token == "]" and tape[pointer]: pc = pairs[pc]
        pc += 1
    return bytes(output)
