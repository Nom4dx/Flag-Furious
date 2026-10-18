"""Hash-deduplicated recursive decoder pipeline for extracted byte candidates."""

from __future__ import annotations

import hashlib
from collections import deque

from .decoders import decode_candidates, printable_ratio
from .limits import Limits


def detect_type(data: bytes) -> str:
    """Identify common decoded payload types from strong leading markers."""
    for name,marker in (("png",b"\x89PNG\r\n\x1a\n"),("jpeg",b"\xff\xd8\xff"),("zip",b"PK\x03\x04"),("pdf",b"%PDF-"),("gif",b"GIF8"),("gzip",b"\x1f\x8b\x08"),("riff",b"RIFF"),("7z",b"7z\xbc\xaf'\x1c")):
        if data.startswith(marker):return name
    return "text" if printable_ratio(data)>.75 else "application/octet-stream"


def decode_recursive(seeds: list[dict], limits: Limits, prefixes: list[str]) -> list[dict]:
    """Explore multiple decoder chains without assuming the first result is true.

    Seeds contain bytes/source/technique. SHA-256 prevents cycles. Output retains
    bytes for later artifact storage and ranks structural signature, readability,
    prefix and chain coherence. Depth/attempt/output caps are mandatory.
    """
    queue=deque((seed,0,seed.get("decoder_chain",[])) for seed in seeds);seen=set();results=[];attempts=0;total=0
    while queue and attempts<limits.max_decoder_attempts:
        seed,depth,chain=queue.popleft();data=seed.get("data",b"")
        if not isinstance(data,bytes) or not data:continue
        digest=hashlib.sha256(data).hexdigest()
        if digest in seen:continue
        seen.add(digest)
        if depth>=limits.max_depth:continue
        for decoded in decode_candidates(data,min(limits.max_single_artifact_size,limits.output_budget-total),prefixes):
            attempts+=1;output=decoded.pop("output");total+=len(output)
            record={**decoded,"data":output,"source":seed.get("source","input"),"technique":seed.get("technique","decoder"),"decoder_chain":[*chain,*decoded["decoder_chain"]],"depth":depth+1,"status":"decoded","printable_ratio":round(printable_ratio(output),3),"parent_hash":digest,"detected_type":detect_type(output)}
            results.append(record)
            if total>=limits.output_budget:break
            queue.append(({"data":output,"source":record["source"],"technique":record["technique"]},depth+1,record["decoder_chain"]))
        if total>=limits.output_budget:break
    return sorted(results,key=lambda x:(-x["confidence"],x["depth"]))
