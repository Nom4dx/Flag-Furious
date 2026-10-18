"""Reason about disjoint validated byte intervals."""


def find_concatenations(formats: list[dict]) -> list[dict]:
    """Return adjacent complete formats whose ranges do not overlap.

    Input is sorted validated formats; output contains structural relationships.
    It has no I/O or exceptions. Nested ranges are excluded from concatenation.
    """
    ordered = sorted(formats, key=lambda x: (x["start_offset"], x["end_offset"]))
    results = []
    for left, right in zip(ordered, ordered[1:]):
        if right["start_offset"] >= left["end_offset"]:
            results.append({
                "type": "concatenated",
                "left_format": left["format"], "left_end": left["end_offset"],
                "right_format": right["format"], "right_start": right["start_offset"],
                "gap": right["start_offset"] - left["end_offset"],
                "confidence": min(left["confidence"], right["confidence"]),
            })
    return results

