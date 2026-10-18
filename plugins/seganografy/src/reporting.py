"""Factories for normalized sections, findings and phase events."""

from __future__ import annotations

import time


def finding(identifier: str, kind: str, message: str, *, severity: str = "medium", confidence: float = .5, status: str = "detected", source_file: str = "input", source_sha256: str | None = None, offset: int | None = None, length: int | None = None, technique: str | None = None, evidence: list[str] | None = None, artifact_sha256: str | None = None, **extra) -> dict:
    """Create a provenance-rich finding accepted by the hub normalizer.

    Optional values remain explicit ``null`` rather than invented. Output is JSON
    serializable. Example: ``finding('unicode-1','bidi','RLO rilevato')``.
    """
    return {
        "id": identifier, "type": kind, "title": kind.replace("_", " ").title(),
        "description": message, "message": message, "severity": severity,
        "confidence": confidence, "status": status, "source": source_file,
        "source_file": source_file, "source_sha256": source_sha256,
        "offset": offset, "length": length, "technique": technique or kind,
        "evidence": evidence or [], "artifact_sha256": artifact_sha256, **extra,
    }


def section(identifier: str, title: str, order: int, items, status: str = "completed", **extra) -> dict:
    """Build a stable dashboard section with an explicit result count."""
    count = len(items) if isinstance(items, (list, dict)) else int(bool(items))
    return {"id": identifier, "title": title, "order": order, "status": status, "items": items, "data": items, "result_count": count, **extra}


def event(name: str, started: float, status: str = "completed", **extra) -> dict:
    """Create a timed execution event for the hub graph and live UI."""
    return {"phase": name, "status": status, "duration": round(time.monotonic() - started, 4), **extra}
