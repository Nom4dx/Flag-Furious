"""Timeline normalization from heterogeneous metadata timestamps."""

from __future__ import annotations

from datetime import datetime
import re

from .reporting import ModuleResult


def build_timeline(items: list[dict], source: str) -> ModuleResult:
    """Normalize parseable timestamps while preserving raw values.

    Input: metadata records/source. Output: ordered ISO timeline. Invalid dates are
    warnings only. Limits: 4,000 items. Security: pure parsing. Example:
    ``build_timeline(metadata, "a.docx")``.
    """
    result = ModuleResult("timeline")
    for item in items[:4000]:
        value = item.get("timestamp")
        if not value and any(word in str(item.get("field", "")).lower() for word in ("date", "created", "modified", "time")):
            value = item.get("normalized_value")
        if not isinstance(value, str):
            continue
        normalized = _date(value)
        if normalized:
            result.timeline.append({"timestamp": normalized, "event": item.get("field", "Metadata timestamp"), "label": item.get("field", "Metadata timestamp"), "raw_value": value, "source": item.get("source", source), "internal_path": item.get("internal_path"), "confidence": item.get("confidence", 0.7)})
    result.timeline.sort(key=lambda x: x["timestamp"])
    result.metrics = {"events": len(result.timeline)}
    return result


def _date(value: str) -> str | None:
    """Parse common ISO, PDF and EXIF forms; return ``None`` when ambiguous."""
    cleaned = value.strip().replace("D:", "")
    cleaned = re.sub(r"^(\d{4}):(\d{2}):(\d{2})", r"\1-\2-\3", cleaned)
    cleaned = re.sub(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", r"\1-\2-\3T\4:\5:\6", cleaned)
    cleaned = cleaned.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(cleaned).isoformat()
    except ValueError:
        return None
