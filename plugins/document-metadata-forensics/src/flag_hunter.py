"""Evidence-aware flag candidate classifier."""

from __future__ import annotations

import regex
import time

from .reporting import ModuleResult


def hunt_flags(items: list[dict], prefixes: list[str], source: str, patterns: list[str] | None = None) -> ModuleResult:
    """Find and rank flags in raw and decoded evidence.

    Input: structured evidence, configured prefixes and source. Output: deduplicated
    candidates linked to parser/decoder origin. Limits: 2,000 input records and 500
    results. Prefixes are escaped; optional user patterns are capped and run with
    a regex timeout. A raw match remains ``candidate``; decoded matches may be
    ``high_confidence``.
    Example: ``hunt_flags(items, ["BVAULT"], "x.pdf")``.
    """
    result = ModuleResult("flags")
    prefixes = [x.rstrip("{") for x in prefixes if x][:32] or ["flag", "CTF", "HTB", "picoCTF"]
    expressions = [r"(?:" + "|".join(regex.escape(x) for x in prefixes) + r")\{[^\x00-\x1f\x7f\r\n]{1,240}?\}"]
    for expression in (patterns or [])[:16]:
        if len(expression) > 512:
            result.warnings.append("Pattern flag oltre 512 caratteri ignorato")
            continue
        try:
            expressions.append(expression)
            regex.compile(expression, regex.I)
        except regex.error as exc:
            expressions.pop()
            result.warnings.append(f"Pattern flag non valido ignorato: {str(exc)[:160]}")
    compiled = [regex.compile(expression, regex.I) for expression in expressions]
    found = {};scanned=0;maximum_text=16*1024*1024;deadline=time.monotonic()+10;stopped=False
    for item in items[:2000]:
        if len(found) >= 500 or stopped:
            break
        fields = ("normalized_value", "text", "raw_value", "description")
        for field in fields:
            value = item.get(field)
            if not isinstance(value, str):
                continue
            remaining=maximum_text-scanned
            if remaining<=0:
                result.warnings.append("Ricerca flag fermata al budget di testo di 16 MiB")
                stopped=True
                break
            if len(value)>remaining:
                value=value[:remaining]
                result.warnings.append("Campo flag troncato al budget cumulativo di 16 MiB")
                stopped=True
            scanned+=len(value)
            for pattern in compiled:
                if time.monotonic()>=deadline:
                    result.warnings.append("Ricerca flag fermata al timeout globale di 10 secondi")
                    stopped=True
                    break
                try:
                    matches = pattern.finditer(value, timeout=0.05)
                    for match in matches:
                        decoded = bool(item.get("decoder") or item.get("decoder_chain"))
                        classification = "high_confidence" if decoded else "candidate"
                        confidence = min(0.99, float(item.get("confidence", 0.65)) + (0.08 if decoded else 0))
                        record = {"value": match.group(0), "candidate": match.group(0), "classification": classification, "status": classification, "source": item.get("source", source), "internal_path": item.get("internal_path"), "offset": item.get("offset"), "parser": item.get("parser"), "decoder": item.get("decoder"), "decoder_chain": item.get("decoder_chain", []), "confidence": confidence, "evidence_type": item.get("type"), "relation": "derived_from" if decoded else "contained_in"}
                        key = (record["value"], record["source"], record["offset"], tuple(record["decoder_chain"]))
                        found[key] = record
                        if len(found) >= 500:
                            result.warnings.append("Limite 500 flag candidate raggiunto")
                            break
                except TimeoutError:
                    result.warnings.append("Timeout regex durante la ricerca flag; risultato parziale")
                if len(found) >= 500:
                    break
            if len(found) >= 500 or stopped:
                break
    result.items = list(found.values())
    result.metrics = {"candidates": len(result.items)}
    return result
