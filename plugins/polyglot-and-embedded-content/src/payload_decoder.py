"""Bounded decoding of common textual and compressed payload representations."""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
import zlib


def decode_payloads(data: bytes, max_candidates: int = 128, max_output: int = 4 * 1024 * 1024,
                    max_total_output: int = 32 * 1024 * 1024,
                    max_attempts: int = 2_000, return_meta: bool = False):
    """Decode Base64/32/58/85, hex, URL, gzip/zlib and single-byte XOR clues.

    Inputs are passive bytes and strict caps. Output records decoder, offsets and
    decoded bytes; malformed candidates are ignored. Expansion never exceeds the
    output cap. This function performs no interpretation or execution.
    """
    results, seen = [], set()
    metadata = {"attempts": 0, "decoded_bytes": 0, "truncated": False}

    def add(decoder: str, offset: int, raw: bytes, decoded: bytes):
        if not decoded:
            return
        if len(decoded) > max_output or metadata["decoded_bytes"] + len(decoded) > max_total_output:
            metadata["truncated"] = True
            return
        digest = __import__("hashlib").sha256(decoded).hexdigest()
        if digest in seen:
            return
        seen.add(digest)
        results.append({"decoder": decoder, "offset": offset, "encoded_length": len(raw), "decoded_length": len(decoded), "sha256": digest, "decoded": decoded, "preview": decoded[:256].decode("utf-8", "replace")})
        metadata["decoded_bytes"] += len(decoded)

    def limited() -> bool:
        if len(results) >= max_candidates or metadata["decoded_bytes"] >= max_total_output:
            metadata["truncated"] = True
            return True
        if metadata["attempts"] >= max_attempts:
            metadata["truncated"] = True
            return True
        return False

    patterns = [
        ("base64", rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/])", lambda x: base64.b64decode(x, validate=True)),
        ("base32", rb"(?<![A-Z2-7])[A-Z2-7]{24,}={0,6}(?![A-Z2-7])", lambda x: base64.b32decode(x)),
        ("base85", rb"(?<![!-u])[!-u]{20,}(?![!-u])", lambda x: base64.b85decode(x)),
        ("hex", rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){10,}(?![0-9A-Fa-f])", binascii.unhexlify),
    ]
    for decoder, pattern, function in patterns:
        for match in re.finditer(pattern, data):
            if limited():
                return (results, metadata) if return_meta else results
            raw = match.group()
            metadata["attempts"] += 1
            # Avoid constructing a decoded candidate that cannot fit in the
            # per-item output cap; estimated bounds intentionally round up.
            expansion_caps = {"base64": (max_output * 4 // 3) + 8,
                              "base32": (max_output * 8 // 5) + 8,
                              "base85": (max_output * 5 // 4) + 8,
                              "hex": max_output * 2}
            if len(raw) > expansion_caps[decoder]:
                metadata["truncated"] = True
                continue
            try: add(decoder, match.start(), raw, function(raw))
            except (ValueError, binascii.Error): pass
    for match in re.finditer(rb"(?:%[0-9A-Fa-f]{2}){4,}", data):
        if limited(): break
        raw = match.group(); metadata["attempts"] += 1
        if len(raw) > max_output * 3 + 3:
            metadata["truncated"] = True
            continue
        try: add("url", match.start(), raw, urllib.parse.unquote_to_bytes(raw.decode("ascii")))
        except ValueError: pass
    for marker, wbits, name in ((b"\x1f\x8b", 31, "gzip"), (b"\x78", 15, "zlib")):
        cursor = 0
        while not limited():
            pos = data.find(marker, cursor)
            if pos < 0: break
            raw = data[pos:]
            metadata["attempts"] += 1
            try:
                decoder = zlib.decompressobj(wbits=wbits)
                decoded = decoder.decompress(raw, max_output + 1)
                if len(decoded) > max_output or decoder.unconsumed_tail or not decoder.eof:
                    metadata["truncated"] = True
                else:
                    add(name, pos, raw, decoded)
            except zlib.error: pass
            cursor = pos + 1
    # Base58 is implemented locally to avoid a dependency and only accepted when
    # the decoded result contains enough printable bytes to reduce random matches.
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    for match in re.finditer(rb"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{24,}(?![1-9A-HJ-NP-Za-km-z])", data):
        if limited(): break
        raw = match.group(); metadata["attempts"] += 1
        if len(raw) > max_output:
            metadata["truncated"] = True
            continue
        number = 0
        for char in raw: number = number * 58 + alphabet.index(char)
        decoded = b"\0" * (len(raw) - len(raw.lstrip(b"1"))) + number.to_bytes((number.bit_length() + 7) // 8, "big")
        if decoded and sum(32 <= x < 127 for x in decoded) / len(decoded) > .65: add("base58", match.start(), raw, decoded)
    result = results[:max_candidates]
    return (result, metadata) if return_meta else result


def xor_candidates(data: bytes, prefixes: list[str], max_input: int = 65536) -> list[dict]:
    """Try single-byte XOR only when a configured flag prefix proves usefulness.

    This avoids emitting 255 speculative blobs. Output contains only keys whose
    decoded bytes include a prefix; input is capped and never executed.
    """
    raw = data[:max_input]; needles = [p.encode() for p in prefixes if p]
    results = []
    for key in range(1, 256):
        decoded = bytes(byte ^ key for byte in raw)
        if any(needle in decoded for needle in needles):
            results.append({"decoder": "xor_single_byte", "key": key, "offset": 0, "decoded": decoded, "preview": decoded[:256].decode("utf-8", "replace")})
    return results

