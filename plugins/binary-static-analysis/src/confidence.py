"""Consistent evidence-based confidence scoring.

Scores describe parser confidence, never maliciousness. Structural checks carry
more weight than names, extensions or entropy. Output is clamped to ``0..1``.
"""


WEIGHTS = {"magic": 0.30, "header": 0.25, "bounds": 0.20, "checksum": 0.15, "parser": 0.10}


def score(*evidence: str, penalty: float = 0.0) -> float:
    """Sum known evidence weights and subtract an explicit bounded penalty."""
    return round(max(0.0, min(1.0, sum(WEIGHTS.get(item, 0.0) for item in set(evidence)) - penalty)), 3)


def entropy_label(value: float, structured: bool = False) -> str:
    """Classify entropy without asserting encryption or malware.

    ``structured`` indicates a validated compressed container; otherwise high
    entropy stays ``random_or_unknown`` because detection is not extraction.
    """
    if value < 1.0:
        return "low_entropy"
    if value < 7.2:
        return "normal_entropy"
    if structured:
        return "compressed_likely"
    return "random_or_unknown"
