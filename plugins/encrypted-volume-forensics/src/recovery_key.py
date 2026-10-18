"""BitLocker 48-digit numerical recovery-password validation.

Each of the eight six-digit groups must be divisible by 11 and encodes a
16-bit value after division. The function preserves the raw input only in the
ephemeral return value; callers must mask it before persistence.
"""

from __future__ import annotations
import re


def validate(value: str) -> dict:
    """Normalize and validate an operator-supplied recovery password."""
    raw=str(value or "");groups=re.findall(r"\d+",raw)
    compact="".join(groups)
    valid_shape=len(groups)==8 and all(len(group)==6 for group in groups)
    checks=[int(group)%11==0 and int(group)//11<=0xffff for group in groups] if valid_shape else []
    valid=valid_shape and all(checks)
    return {"valid":valid,"group_count":len(groups),"normalized":"-".join(groups) if valid_shape else None,
            "masked":"******-******-******-******-******-******-******-******" if valid_shape else "********",
            "reason":"valid_format" if valid else "expected eight six-digit groups divisible by 11"}


def find_in_text(text: str) -> list[dict]:
    """Find format-valid recovery passwords without returning plaintext values."""
    pattern=re.compile(r"(?<!\d)(?:\d{6}[- ]?){7}\d{6}(?!\d)")
    rows=[]
    for match in pattern.finditer(text):
        checked=validate(match.group(0))
        if checked["valid"]:rows.append({"offset":match.start(),"length":len(match.group(0)),"masked":checked["masked"],"confidence":.99})
    return rows
