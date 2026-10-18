"""Flag candidate search with decoder/source provenance and false-positive gates."""

from __future__ import annotations

import re


def hunt(sources: list[dict], prefixes: list[str], patterns: list[str] | None = None, max_results: int = 256) -> list[dict]:
    """Search UTF-8/raw and UTF-16 text for structured flag candidates.

    A bare word such as ``flag`` is never enough: default patterns require braces
    and custom regular expressions are bounded. Each result retains technique,
    decoder chain, source, offset and evidence. Invalid regexes are skipped.
    """
    compiled=[]
    for prefix in prefixes or ["flag","CTF","HTB","picoCTF"]:
        if prefix:compiled.append(re.compile(re.escape(prefix.encode())+rb"\{[^\x00\r\n{}]{1,512}\}",re.I if prefix.lower()==prefix else 0))
    for pattern in (patterns or [])[:16]:
        if len(pattern)>512:continue
        try:compiled.append(re.compile(pattern.encode()))
        except re.error:continue
    results=[];seen=set()
    for source in sources:
        data=source.get("data",b"")
        if not isinstance(data,bytes):continue
        views=[("raw",data,1)]
        if len(data)>=4:
            views.extend((("utf16le",data[::2],2),("utf16be",data[1::2],2)))
        for encoding,view,multiplier in views:
            for regex in compiled:
                for match in regex.finditer(view):
                    value=match.group().decode("utf-8","replace");offset=source.get("offset",0)+match.start()*multiplier;key=(value,source.get("source"),offset)
                    if key in seen:continue
                    seen.add(key);structural=float(source.get("confidence",.4));chain=source.get("decoder_chain",[])
                    evidence=["matching flag prefix or configured regex","valid byte decoding"]
                    if structural>=.8:evidence.append("payload extracted from validated source")
                    if chain:evidence.append("coherent decoder chain")
                    confidence=min(.99,.55+(.25 if structural>=.8 else .08)+(.1 if chain else 0))
                    results.append({"value":value,"source":source.get("source","input"),"artifact_sha256":source.get("artifact_sha256"),"offset":offset,"technique":source.get("technique",encoding),"decoder_chain":chain or [encoding],"evidence":evidence,"confidence":round(confidence,3),"status":"candidate"})
                    if len(results)>=max_results:return results
    return results
