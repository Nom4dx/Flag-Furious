"""Classify bytes outside a primary format's declared logical boundary."""

import math
from collections import Counter
from pathlib import Path


def analyze_overlay(file_size: int, formats: list[dict], candidates: list[dict], path: Path | None = None) -> list[dict]:
    """Describe prepended/appended/overlay regions using validated boundaries.

    Bytes are classified as padding only when a caller later proves their value;
    this function never silently discards trailing evidence.
    """
    if not formats:
        return []
    primary = next((item for item in formats if item["start_offset"] == 0), formats[0])
    results = []
    if primary["start_offset"]:
        results.append({"type": "prepended_data", "start_offset": 0, "end_offset": primary["start_offset"], "length": primary["start_offset"], "confidence": .95})
    if primary["end_offset"] < file_size:
        nested = [item for item in formats if item["start_offset"] >= primary["end_offset"]]
        nature, entropy = "validated_format", None
        if not nested and path is not None:
            with path.open("rb") as stream:
                stream.seek(primary["end_offset"])
                sample = stream.read(min(65536, file_size - primary["end_offset"]))
            if sample and len(set(sample)) == 1 and sample[0] in (0, 0xFF):
                nature = "padding"
            elif sample:
                counts = Counter(sample)
                entropy = -sum((count / len(sample)) * math.log2(count / len(sample)) for count in counts.values())
                nature = "probable_random_data" if entropy > 7.5 else "unclassified_structured_data"
        results.append({
            "type": "appended_format" if nested else "unclassified_overlay",
            "start_offset": primary["end_offset"], "end_offset": file_size,
            "length": file_size - primary["end_offset"],
            "formats": [item["format"] for item in nested],
            "content_nature": nature,
            "sample_entropy": round(entropy, 3) if entropy is not None else None,
            "confidence": .98 if nested else .65,
        })
    return results
