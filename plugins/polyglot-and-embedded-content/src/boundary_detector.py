"""Convert signature candidates into validated, bounded format intervals."""

from __future__ import annotations

from pathlib import Path

from .validators import ValidationError, validate_candidate


def detect_boundaries(path: Path, candidates: list[dict], byte_budget: int) -> tuple[list[dict], list[dict]]:
    """Validate candidates independently and return accepted/rejected records.

    Parser failures are evidence against a candidate, not plugin failures. The
    per-object span is bounded by the remaining byte budget. Read-only validation
    prevents mutations. Example: ``valid, rejected = detect_boundaries(...)``.
    """
    size = path.stat().st_size
    valid, rejected = [], []
    for candidate in candidates:
        if candidate["offset"] >= min(size, byte_budget):
            continue
        if not candidate.get("root_marker", True):
            rejected.append({**candidate, "validated": False, "rejection_reason": "marker strutturale secondario: non è un inizio formato", "confidence": .2})
            continue
        try:
            item = validate_candidate(path, candidate, size, min(byte_budget - candidate["offset"], size - candidate["offset"]))
            valid.append(item)
        except (ValidationError, OSError, struct_error()) as exc:
            rejected.append({**candidate, "validated": False, "rejection_reason": str(exc), "confidence": min(.35, candidate["signature_confidence"] * .35)})
    # The same start/format can be proposed by multiple ZIP markers. Keep the
    # strongest boundary proof and preserve every raw marker in the inventory.
    unique: dict[tuple[str, int], dict] = {}
    for item in valid:
        key = (item["format"], item["start_offset"])
        if key not in unique or item["confidence"] > unique[key]["confidence"]:
            unique[key] = item
    return sorted(unique.values(), key=lambda x: (x["start_offset"], -x["confidence"])), rejected


def struct_error():
    """Return the stdlib struct exception lazily to keep the public API small."""
    import struct
    return struct.error
