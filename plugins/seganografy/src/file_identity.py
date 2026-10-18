"""Hashing, MIME/type identification, strings and entropy inventory."""

from __future__ import annotations

import hashlib
import math
import mimetypes
import re
from collections import Counter
from pathlib import Path

from .safe_subprocess import run


def identify(path: Path, name: str, byte_budget: int, entropy_limit: int, tool_timeout: int, tool_output: int) -> dict:
    """Identify immutable input using hashes, magic, strings and statistics.

    MD5/SHA-1/SHA-256 are streamed over the granted view. Libmagic is represented
    by the allow-listed ``file`` command when present; extension and MIME are only
    hints. Output includes ASCII/UTF strings and window entropy with strict caps.
    """
    hashes={"md5":hashlib.md5(),"sha1":hashlib.sha1(),"sha256":hashlib.sha256()}; total=0; sample=bytearray()
    with path.open("rb") as stream:
        while total<byte_budget:
            block=stream.read(min(1024*1024,byte_budget-total))
            if not block: break
            for digest in hashes.values(): digest.update(block)
            if len(sample)<entropy_limit: sample.extend(block[:entropy_limit-len(sample)])
            total+=len(block)
    raw=bytes(sample); declared=mimetypes.guess_type(name)[0] or "application/octet-stream"
    magic_result=run("file",["-b","--mime-type","--",str(path)],tool_timeout,tool_output)
    description=run("file",["-b","--",str(path)],tool_timeout,tool_output)
    strings={
        "ascii": [m.group().decode("ascii","replace") for m in re.finditer(rb"[\x20-\x7e]{4,}",raw)][:1000],
        "utf16le": [m.group().decode("utf-16le","replace") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}",raw)][:500],
        "utf16be": [m.group().decode("utf-16be","replace") for m in re.finditer(rb"(?:\x00[\x20-\x7e]){4,}",raw)][:500],
    }
    return {
        "source_file":name,"physical_size":path.stat().st_size,"bytes_hashed":total,"complete_hash":total==path.stat().st_size,
        "hashes":{key:value.hexdigest() for key,value in hashes.items()},"extension":Path(name).suffix.lower(),"declared_mime":declared,
        "libmagic_mime":magic_result["stdout"].strip() or None,"libmagic_description":description["stdout"].strip() or None,
        "magic_start":raw[:32].hex(),"magic_end":raw[-32:].hex() if total==path.stat().st_size else None,
        "entropy":entropy(raw),"strings":strings,"sample_bytes":len(raw),
    }


def entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte; empty input returns zero."""
    if not data:return 0.0
    counts=Counter(data); size=len(data)
    return round(-sum((n/size)*math.log2(n/size) for n in counts.values()),4)


def entropy_windows(data: bytes, window: int = 4096, max_windows: int = 4096) -> list[dict]:
    """Return bounded offset/entropy windows for compression/encryption heuristics."""
    return [{"offset":offset,"length":len(data[offset:offset+window]),"entropy":entropy(data[offset:offset+window])} for offset in range(0,min(len(data),window*max_windows),window)]
