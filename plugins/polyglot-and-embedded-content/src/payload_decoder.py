"""Bounded decoding of common textual and compressed payload representations."""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
import zlib


def decode_payloads(data: bytes, max_candidates: int = 128, max_output: int = 4 * 1024 * 1024) -> list[dict]:
    """Decode Base64/32/58/85, hex, URL, gzip/zlib and single-byte XOR clues.

    Inputs are passive bytes and strict caps. Output records decoder, offsets and
    decoded bytes; malformed candidates are ignored. Expansion never exceeds the
    output cap. This function performs no interpretation or execution.
    """
    results, seen = [], set()

    def add(decoder: str, offset: int, raw: bytes, decoded: bytes):
        if not decoded or len(decoded) > max_output:
            return
        digest = __import__("hashlib").sha256(decoded).hexdigest()
        if digest in seen:
            return
        seen.add(digest)
        results.append({"decoder": decoder, "offset": offset, "encoded_length": len(raw), "decoded_length": len(decoded), "sha256": digest, "decoded": decoded, "preview": decoded[:256].decode("utf-8", "replace")})

    patterns = [
        ("base64", rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/])", lambda x: base64.b64decode(x, validate=True)),
        ("base32", rb"(?<![A-Z2-7])[A-Z2-7]{24,}={0,6}(?![A-Z2-7])", lambda x: base64.b32decode(x)),
        ("base85", rb"(?<![!-u])[!-u]{20,}(?![!-u])", lambda x: base64.b85decode(x)),
        ("hex", rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){10,}(?![0-9A-Fa-f])", binascii.unhexlify),
    ]
    for decoder, pattern, function in patterns:
        for match in re.finditer(pattern, data):
            if len(results) >= max_candidates: return results
            try: add(decoder, match.start(), match.group(), function(match.group()))
            except (ValueError, binascii.Error): pass
    for match in re.finditer(rb"(?:%[0-9A-Fa-f]{2}){4,}", data):
        try: add("url", match.start(), match.group(), urllib.parse.unquote_to_bytes(match.group().decode("ascii")))
        except ValueError: pass
    for marker, wbits, name in ((b"\x1f\x8b", 31, "gzip"), (b"\x78", 15, "zlib")):
        cursor = 0
        while len(results) < max_candidates:
            pos = data.find(marker, cursor)
            if pos < 0: break
            try: add(name, pos, data[pos:], zlib.decompress(data[pos:], wbits=wbits, bufsize=max_output)[:max_output])
            except zlib.error: pass
            cursor = pos + 1
    # Base58 is implemented locally to avoid a dependency and only accepted when
    # the decoded result contains enough printable bytes to reduce random matches.
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    for match in re.finditer(rb"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{24,}(?![1-9A-HJ-NP-Za-km-z])", data):
        number = 0
        for char in match.group(): number = number * 58 + alphabet.index(char)
        decoded = b"\0" * (len(match.group()) - len(match.group().lstrip(b"1"))) + number.to_bytes((number.bit_length() + 7) // 8, "big")
        if decoded and sum(32 <= x < 127 for x in decoded) / len(decoded) > .65: add("base58", match.start(), match.group(), decoded)
    return results[:max_candidates]


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

