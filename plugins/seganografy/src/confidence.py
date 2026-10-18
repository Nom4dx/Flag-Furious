"""Transparent confidence scoring for extraction and steganalysis evidence.

Scores express evidence strength rather than mathematical certainty. Statistical
anomalies alone are capped below confirmation; validated structures, checksums and
coherent decoder chains can raise a candidate.
"""


WEIGHTS = {
    "validated_structure": 0.34,
    "valid_crc": 0.16,
    "known_signature": 0.16,
    "flag_prefix": 0.18,
    "printable": 0.08,
    "coherent_chain": 0.08,
    "statistical_anomaly": 0.20,
    "metadata_hint": 0.12,
}


def score(evidence: list[str], base: float = 0.1, statistical_only: bool = False) -> float:
    """Return a bounded score from named evidence tokens.

    Input is a list from ``WEIGHTS`` and a base. Unknown tokens add nothing.
    Statistical-only results are capped at 0.69 so detection is not confused with
    extraction. Example: ``score(['known_signature','valid_crc'])``.
    """
    value = base + sum(WEIGHTS.get(item, 0) for item in set(evidence))
    if statistical_only:
        value = min(value, 0.69)
    return round(max(0.0, min(0.99, value)), 3)


def classification(value: float, extracted: bool = False, decoded: bool = False) -> str:
    """Map evidence state to the plugin's explicit lifecycle vocabulary."""
    if decoded:
        return "decoded"
    if extracted:
        return "extracted" if value >= 0.7 else "extracted_uninterpreted"
    return "detected" if value >= 0.45 else "false_positive"
