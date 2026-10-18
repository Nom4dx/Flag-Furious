"""Cross-source metadata consistency checks."""

from __future__ import annotations

from .reporting import ModuleResult


def find_inconsistencies(items: list[dict], source: str) -> ModuleResult:
    """Compare repeated identity/date fields across namespaces.

    Input: metadata records/source. Output: explainable inconsistency findings.
    Limits: 4,000 records. Security: pure comparison. Example:
    ``find_inconsistencies(items, "a.pdf")``.
    """
    result = ModuleResult("inconsistencies")
    groups = {}
    aliases = {"creator": "author", "artist": "author", "lastmodifiedby": "last_modified_by", "creatortool": "creator_tool", "modifydate": "modified", "modified": "modified", "created": "created", "creationdate": "created"}
    for item in items[:4000]:
        field = str(item.get("field", "")).rpartition("}")[2].replace("_", "").lower()
        canonical = aliases.get(field, field)
        if canonical in {"author", "last_modified_by", "creator_tool", "created", "modified", "title"}:
            groups.setdefault(canonical, []).append(item)
    for field, values in groups.items():
        distinct = {str(x.get("normalized_value", "")).strip() for x in values if x.get("normalized_value")}
        if len(distinct) > 1:
            result.findings.append({"type": "metadata_inconsistency", "severity": "medium", "title": f"Valori discordanti: {field}", "description": " | ".join(sorted(distinct)[:10]), "source": source, "offset": values[0].get("offset"), "confidence": 0.86, "evidence": [{"namespace": x.get("namespace"), "value": x.get("normalized_value")} for x in values[:20]]})
    result.metrics = {"compared_fields": len(groups), "inconsistencies": len(result.findings)}
    return result
