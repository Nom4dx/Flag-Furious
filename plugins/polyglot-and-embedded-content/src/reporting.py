"""Normalized section and finding factories for the hub result contract."""


def section(section_id: str, title: str, order: int, items, status: str = "completed", **extra) -> dict:
    """Create a stable, UI-mappable plugin section with result count."""
    return {"id": section_id, "title": title, "order": order, "status": status, "items": items, "result_count": len(items) if isinstance(items, list) else int(bool(items)), "data": items, **extra}


def finding(identifier: str, kind: str, description: str, *, severity: str = "medium", confidence: float = .8, offset: int | None = None, length: int | None = None, format_name: str | None = None, parser: str = "polyglot-detector", source: str = "input", artifacts: list[str] | None = None) -> dict:
    """Create a provenance-rich finding suitable for normalization and reports."""
    return {"id": identifier, "type": kind, "severity": severity, "title": kind.replace("_", " ").title(), "description": description, "offset": offset, "length": length, "format": format_name, "parser": parser, "confidence": confidence, "source": source, "related_artifacts": artifacts or []}

