"""Rank likely decoys without deleting potentially relevant evidence."""


def detect_decoys(flags: list[dict], rejected: list[dict]) -> list[dict]:
    """Identify flags from weak origins and signature-like false format markers.

    Output is explanatory and preserves candidates for review. No content is
    discarded. Duplicate values at different provenances remain linked.
    """
    decoys = []
    values: dict[str, list[dict]] = {}
    for flag in flags: values.setdefault(flag["value"], []).append(flag)
    for value, occurrences in values.items():
        strong = [x for x in occurrences if x["confidence"] >= .85]
        weak = [x for x in occurrences if x["confidence"] < .55]
        if strong and weak:
            decoys.append({"type": "duplicate_flag_decoy", "value": value, "confidence": .75, "reasons": ["presente in origini forti e deboli", "la provenienza validata ha priorità"], "occurrences": len(occurrences)})
    for candidate in rejected[:128]:
        decoys.append({"type": "unvalidated_signature", "format": candidate["format"], "offset": candidate["offset"], "confidence": candidate.get("confidence", .2), "reasons": [candidate.get("rejection_reason", "validator respinto")]})
    return decoys

