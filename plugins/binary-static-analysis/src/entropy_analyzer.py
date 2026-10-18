"""Streaming Shannon entropy and region segmentation.

Entropy is an indicator only. High values are reported as compressed, packed or
unknown according to structural evidence and never as proof of encryption.
"""

from collections import Counter
from math import log2
from pathlib import Path

from .confidence import entropy_label


def shannon(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte; empty data returns zero."""
    if not data:
        return 0.0
    counts = Counter(data)
    return round(-sum((count / len(data)) * log2(count / len(data)) for count in counts.values()), 5)


def scan(path: Path, limit: int, window: int = 65536, maximum_windows: int = 4096) -> dict:
    """Read bounded windows and return global/window entropy plus abrupt changes."""
    windows = []
    aggregate = Counter()
    total = 0
    with path.open("rb") as source:
        while total < limit and len(windows) < maximum_windows:
            block = source.read(min(window, limit - total))
            if not block:
                break
            value = shannon(block)
            windows.append({"offset": total, "length": len(block), "entropy": value, "category": entropy_label(value)})
            aggregate.update(block)
            total += len(block)
    global_value = 0.0 if not total else round(-sum((count / total) * log2(count / total) for count in aggregate.values()), 5)
    changes = [
        {"offset": current["offset"], "before": previous["entropy"], "after": current["entropy"], "delta": round(current["entropy"] - previous["entropy"], 4)}
        for previous, current in zip(windows, windows[1:])
        if abs(current["entropy"] - previous["entropy"]) >= 1.5
    ]
    return {"global": global_value, "category": entropy_label(global_value), "windows": windows, "changes": changes, "bytes_scanned": total, "truncated": total < path.stat().st_size}
