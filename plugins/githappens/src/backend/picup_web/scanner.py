from __future__ import annotations

import base64
import bz2
import gzip
import hashlib
import lzma
import re
import urllib.parse
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from functools import lru_cache
from typing import Iterable

from .models import Finding

DEFAULT_PREFIXES = ("picoCTF", "CTF", "flag", "HTB", "FLAG", "SRDNLEN", "RootRunners")
MAX_DECODED = 16 * 1024 * 1024


@lru_cache(maxsize=16)
def _xor_markers(prefixes: tuple[str, ...]) -> re.Pattern[bytes]:
    encoded = []
    for prefix in prefixes:
        marker = (prefix if prefix.endswith("{") else prefix + "{").encode()
        for key in range(1, 256):
            encoded.append(re.escape(bytes(byte ^ key for byte in marker)))
    return re.compile(b"|".join(encoded))


@dataclass(slots=True)
class ScanConfig:
    prefixes: tuple[str, ...] = DEFAULT_PREFIXES
    regex: str | None = None
    case_sensitive: bool = False
    max_input_bytes: int = 256 * 1024 * 1024
    bytes_read: int = 0
    diagnostics: list[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        if message in self.diagnostics:return
        if len(self.diagnostics)<100:self.diagnostics.append(message)
        elif not any("ulteriori warning" in item for item in self.diagnostics):self.diagnostics.append("Ulteriori warning di coverage omessi")

    def read_prefix(self, path: Path, maximum: int = 64 * 1024 * 1024) -> bytes:
        """Read from the shared scan budget and record any incomplete view."""
        size = path.stat().st_size
        remaining = max(0, self.max_input_bytes - self.bytes_read)
        limit = min(max(0, maximum), remaining)
        with path.open("rb") as source:
            data = source.read(limit)
        self.bytes_read += len(data)
        if len(data) < size:
            self.warn(f"{path.name}: scan parziale ({len(data)} di {size} byte visibili)")
        return data


def _patterns(config: ScanConfig) -> list[re.Pattern[str]]:
    flags = 0 if config.case_sensitive else re.IGNORECASE
    patterns = []
    for prefix in config.prefixes or DEFAULT_PREFIXES:
        raw = prefix if prefix.endswith("{") else prefix + "{"
        patterns.append(re.compile(re.escape(raw) + r"[^\x00-\x1f\x7f{}]{1,512}\}", flags))
    if config.regex:
        patterns.append(re.compile(config.regex, flags))
    return patterns


def generated_regexes(config: ScanConfig) -> list[str]:
    """Return the literal-safe regex generated from each user prefix."""
    result = []
    for prefix in config.prefixes or DEFAULT_PREFIXES:
        raw = prefix if prefix.endswith("{") else prefix + "{"
        result.append(re.escape(raw) + r"[^\x00-\x1f\x7f{}]{1,512}\}")
    if config.regex:
        result.append(config.regex)
    return result


def variants(data: bytes, prefixes: tuple[str, ...] = DEFAULT_PREFIXES) -> Iterable[tuple[str, bytes, float]]:
    yield "raw", data, 1.0
    for encoding in ("utf-16le", "utf-16be"):
        try:
            yield encoding, data.decode(encoding).encode(), 0.95
        except UnicodeError:
            pass
    text = data.decode("utf-8", "ignore")
    compact = re.sub(r"\s+", "", text)
    candidates = [("base64", compact), ("hex", compact)]
    for method, value in candidates:
        try:
            decoded = base64.b64decode(value, validate=True) if method == "base64" else bytes.fromhex(value)
            if 0 < len(decoded) <= MAX_DECODED:
                yield method, decoded, 0.85
        except (ValueError, TypeError):
            pass
    token_text = text if len(data) <= 1024 * 1024 else ""
    for token in re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])", token_text):
        try:
            decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
            if decoded and len(decoded) <= MAX_DECODED:
                yield "base64-token", decoded, 0.82
        except (ValueError, TypeError):
            pass
    for token in re.findall(r"(?i)(?<![0-9a-f])[0-9a-f]{16,}(?![0-9a-f])", token_text):
        try:
            yield "hex-token", bytes.fromhex(token), 0.82
        except ValueError:
            pass
    try:
        decoded_url = urllib.parse.unquote_to_bytes(text)
        if decoded_url != data and len(decoded_url) <= MAX_DECODED:
            yield "url", decoded_url, 0.9
    except Exception:
        pass
    decompressors = (
        ("gzip", _bounded_gzip, data.startswith(b"\x1f\x8b")),
        ("zlib", _bounded_zlib, len(data) > 2 and data[0] == 0x78 and data[1] in {0x01, 0x5E, 0x9C, 0xDA}),
        ("bzip2", _bounded_bzip2, data.startswith(b"BZh")),
        ("xz", _bounded_xz, data.startswith(b"\xfd7zXZ\x00")),
    )
    for method, decoder, has_magic in decompressors:
        if not has_magic or len(data) >= 4 * 1024 * 1024:
            continue
        try:
            decoded = decoder(data)
            if 0 < len(decoded) <= MAX_DECODED:
                yield method, decoded, 0.9
        except Exception:
            pass
    # Single-byte XOR is deliberately ranked as heuristic, never silently accepted as proof.
    # Expensive brute-force transformation is reserved for bounded artifacts.
    # Raw multi-GB evidence is scanned directly and through extracted objects.
    if len(data) > 256 * 1024:
        return
    sample = data
    possible_keys: set[int] = set()
    marker_first = {(prefix if prefix.endswith("{") else prefix + "{").encode()[0] for prefix in prefixes}
    for match in _xor_markers(prefixes).finditer(sample):
        possible_keys.update(match.group(0)[0] ^ first for first in marker_first)
    for key in possible_keys - {0}:
        yield f"xor:0x{key:02x}", bytes(byte ^ key for byte in sample), 0.55


def _bounded_gzip(data: bytes) -> bytes:
    import io
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as source:
        return source.read(MAX_DECODED + 1)


def _bounded_zlib(data: bytes) -> bytes:
    return zlib.decompressobj().decompress(data, MAX_DECODED + 1)


def _bounded_bzip2(data: bytes) -> bytes:
    return bz2.BZ2Decompressor().decompress(data, max_length=MAX_DECODED + 1)


def _bounded_xz(data: bytes) -> bytes:
    return lzma.LZMADecompressor().decompress(data, max_length=MAX_DECODED + 1)


def scan_bytes(data: bytes, *, source: str, path: str, module: str, config: ScanConfig, base_offset: int = 0, method: str = "content") -> list[Finding]:
    results: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    artifact_hash = hashlib.sha256(data).hexdigest()
    for encoding, decoded, confidence in variants(data, config.prefixes):
        text = decoded.decode("utf-8", "replace")
        # Also joins line/chunk separators without changing the candidate itself unless clearly complete.
        texts = [(text, encoding, 0)]
        joined = re.sub(r"(?<=\w)[\r\n]+(?=[\w}])", "", text)
        if joined != text:
            texts.append((joined, encoding + "+joined-lines", -1))
        for material, variant_method, offset_bias in texts:
            for pattern in _patterns(config):
                for match in pattern.finditer(material):
                    value = match.group(0)
                    key = (value, variant_method, match.start())
                    if key in seen:
                        continue
                    seen.add(key)
                    start = match.start()
                    results.append(Finding(
                        module=module, kind="flag", source=source, path=path,
                        value=value, offset=None if offset_bias < 0 else base_offset + start,
                        size=len(value.encode()), sha256=artifact_hash,
                        method=f"{method}:{variant_method}", confidence=confidence if offset_bias >= 0 else min(confidence, 0.65),
                        context_before=material[max(0, start - 80):start],
                        context_after=material[match.end():match.end() + 80],
                        metadata={"partial": False, "decoded": encoding != "raw"},
                    ))
    return results


def scan_stream(handle, *, source: str, path: str, module: str, config: ScanConfig, chunk_size: int = 4 * 1024 * 1024) -> list[Finding]:
    results: list[Finding] = []
    overlap = 2048
    carry = b""
    absolute = 0
    seen: set[tuple[str, int | None, str]] = set()
    while block := handle.read(chunk_size):
        data = carry + block
        base = max(0, absolute - len(carry))
        for finding in scan_bytes(data, source=source, path=path, module=module, config=config, base_offset=base):
            key = (finding.value, finding.offset, finding.method)
            if key not in seen:
                seen.add(key)
                results.append(finding)
        carry = data[-overlap:]
        absolute += len(block)
    return results
