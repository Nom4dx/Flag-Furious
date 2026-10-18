"""Evidence-aware flag candidate classifier."""

from __future__ import annotations

import re

from .reporting import ModuleResult


def hunt_flags(items: list[dict], prefixes: list[str], source: str) -> ModuleResult:
    """Find and rank flags in raw and decoded evidence.

    Input: structured evidence, configured prefixes and source. Output: deduplicated
    candidates linked to parser/decoder origin. Limits: 2,000 input records and 500
    results. Security: prefixes are escaped, no dynamic regex. A raw match remains
    ``candidate``; decoded, closed-brace matches may be ``high_confidence``.
    Example: ``hunt_flags(items, ["BVAULT"], "x.pdf")``.
    """
    result = ModuleResult("flags")
    prefixes = [x.rstrip("{") for x in prefixes if x][:32] or ["flag", "CTF", "HTB", "picoCTF"]
    pattern = re.compile(r"(?:" + "|".join(re.escape(x) for x in prefixes) + r")\{[^\x00-\x1f\x7f\r\n]{1,240}?\}", re.I)
    found = {}
    for item in items[:2000]:
        fields = ("normalized_value", "text", "raw_value", "description")
        for field in fields:
            value = item.get(field)
            if not isinstance(value, str):
                continue
            for match in pattern.finditer(value):
                decoded = bool(item.get("decoder") or item.get("decoder_chain"))
                classification = "high_confidence" if decoded else "candidate"
                confidence = min(0.99, float(item.get("confidence", 0.65)) + (0.08 if decoded else 0))
                record = {"value": match.group(0), "candidate": match.group(0), "classification": classification, "status": classification, "source": item.get("source", source), "internal_path": item.get("internal_path"), "offset": item.get("offset"), "parser": item.get("parser"), "decoder": item.get("decoder"), "decoder_chain": item.get("decoder_chain", []), "confidence": confidence, "evidence_type": item.get("type"), "relation": "derived_from" if decoded else "contained_in"}
                key = (record["value"], record["source"], record["offset"], tuple(record["decoder_chain"]))
                found[key] = record
                if len(found) >= 500:
                    result.warnings.append("Limite 500 flag candidate raggiunto")
                    break
    result.items = list(found.values())
    result.metrics = {"candidates": len(result.items)}
    return result
