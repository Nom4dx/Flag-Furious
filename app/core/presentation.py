"""Declarative output mapping. Original results are never rewritten.

Paths address the result or data.<legacy-section-id>.<nested-key>. Only dictionary
keys and list indexes are supported: no expressions, evaluation or plugin code.
"""

from copy import deepcopy
from pydantic import BaseModel, ConfigDict, Field
from app.core.visualization_engine import PALETTES


class FieldMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str
    label: str | None = None
    format: str = Field(
        "auto", pattern="^(auto|text|number|bytes|percent|duration|datetime|hex|code|boolean|tags)$"
    )
    unit: str = ""
    description: str = ""


class SectionMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_-]*$")
    title: str
    source: str = Field(min_length=1, max_length=512)
    type: str = Field(
        "auto",
        pattern="^(auto|summary|metrics|details|table|list|text|terminal|timeline|visualization|visualization_list|artifact_list)$",
    )
    group: str = "overview"
    description: str = ""
    order: int = 100
    fields: list[FieldMapping] = Field(default_factory=list, max_length=100)
    hide_empty: bool = True
    collapsed: bool = False
    actions: list[dict] = Field(default_factory=list)
    tone: str = Field("primary", pattern="^(primary|secondary|critical|muted)$")


class GroupMapping(BaseModel):
    id: str = Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_-]*$")
    title: str
    description: str = ""
    order: int = 100


class OutputMapping(BaseModel):
    version: int = Field(1, ge=1, le=1)
    groups: list[GroupMapping] = Field(default_factory=list, max_length=50)
    sections: list[SectionMapping] = Field(default_factory=list, max_length=200)
    include_unmapped: bool = True
    palette: str = "forensic"


def validate_mapping(schema):
    mapping = OutputMapping.model_validate(schema.get("presentation", {}))
    if mapping.palette not in PALETTES:
        raise ValueError(f"Palette di presentazione non supportata: {mapping.palette}")
    for items in (mapping.groups, mapping.sections):
        ids = [item.id for item in items]
        if len(ids) != len(set(ids)):
            raise ValueError("ID duplicato nel mapping di presentazione")
    groups = {g.id for g in mapping.groups}
    for section in mapping.sections:
        if groups and section.group not in groups:
            raise ValueError(f"Gruppo di presentazione sconosciuto: {section.group}")
        for path in [section.source, *[f.field for f in section.fields]]:
            if any(not part or part in ("__proto__", "constructor", "prototype") for part in path.split(".")):
                raise ValueError("Percorso mapping non valido")
    return mapping


MISSING = object()


def resolve(value, path):
    for key in path.split("."):
        if isinstance(value, dict):
            value = value.get(key, MISSING)
        elif isinstance(value, list) and key.isdigit() and int(key) < len(value):
            value = value[int(key)]
        else:
            return MISSING
    return value


def empty(value):
    return value is MISSING or value is None or value == "" or value == [] or value == {}


def without_paths(value, paths, prefix="data"):
    if prefix in paths:
        return MISSING
    if isinstance(value, dict):
        out = {}
        for key, child in value.items():
            remaining = without_paths(child, paths, (prefix + "." if prefix else "") + key)
            if remaining is not MISSING:
                out[key] = remaining
        return out if out else MISSING
    # Do not prune an entire array when only one indexed item was mapped.
    return value


def present(result, schema=None):
    schema = schema or {}
    mapping = validate_mapping(schema)
    legacy = result.get("sections", [])
    data = {s["id"]: s.get("data", s.get("content")) for s in legacy if s.get("id")}
    legacy_by_id = {s["id"]: s for s in legacy if s.get("id")}
    source = {**result, "data": data}
    sections, used = [], set()
    for item in sorted(mapping.sections, key=lambda s: s.order):
        value = resolve(source, item.source)
        if value is not MISSING:
            used.add(item.source)
        if value is MISSING or (item.hide_empty and empty(value)):
            continue
        section = {**item.model_dump(), "data": value}
        source_parts = item.source.split(".")
        legacy_id = source_parts[1] if len(source_parts) > 1 and source_parts[0] == "data" else item.id
        status = legacy_by_id.get(legacy_id, {}).get("status")
        if status:
            section["status"] = status
        sections.append(section)
    if not mapping.sections:
        sections = [
            {
                **s,
                "type": "auto" if s.get("type") == "json" else s.get("type", "auto"),
                "group": s.get("group", "overview"),
            }
            for s in legacy
        ]
    elif mapping.include_unmapped:
        remainder = without_paths(data, used)
        if remainder is not MISSING:
            for key, value in remainder.items():
                if not empty(value):
                    sections.append(
                        {
                            "id": "unmapped-" + key,
                            "title": "Altri dati · " + key.replace("_", " "),
                            "group": "additional",
                            "type": "auto",
                            "data": value,
                            "source": "data." + key,
                            "order": 1000,
                        }
                    )
    # Plugins may also return structured fields outside legacy sections. Keep these
    # discoverable rather than requiring every future plugin to define a mapping.
    reserved = {
        "plugin_id",
        "asset_id",
        "status",
        "summary",
        "confidence",
        "phase",
        "sections",
        "presentation",
        "visualizations",
        "artifacts",
        "derived_assets",
        "flags",
        "timeline",
        "warnings",
        "errors",
        "requested_plugins",
    }
    if mapping.include_unmapped:
        remaining = without_paths({k: v for k, v in result.items() if k not in reserved}, used, "")
        leftovers = {} if remaining is MISSING else {k: v for k, v in remaining.items() if not empty(v)}
        for key, value in leftovers.items():
            sections.append(
                {
                    "id": "result-" + key,
                    "title": {
                        "findings": "Evidenze raccolte",
                        "metrics": "Metriche di esecuzione",
                        "logs": "Log del plugin",
                        "execution_events": "Eventi di esecuzione",
                    }.get(key, key.replace("_", " ").capitalize()),
                    "group": "additional",
                    "type": "auto",
                    "source": key,
                    "data": value,
                    "order": 1100,
                }
            )
    groups = [g.model_dump() for g in sorted(mapping.groups, key=lambda g: g.order)]
    known = {g["id"] for g in groups}
    for section in sections:
        group = section["group"]
        if group not in known:
            groups.append(
                {
                    "id": group,
                    "title": {"overview": "Panoramica", "additional": "Altri dati"}.get(group, group),
                    "order": 1000,
                }
            )
            known.add(group)
    visualizations = []
    for chart in result.get("visualizations", []):
        chart = deepcopy(chart)
        # The output mapping is the plugin's dashboard-level color declaration.
        # An explicit visualization palette remains authoritative.
        if chart.get("palette") in (None, "forensic"):
            chart["palette"] = mapping.palette
            chart["style"] = PALETTES[mapping.palette]
        visualizations.append(chart)
    return {
        **result,
        "visualizations": visualizations,
        "presentation": {
            "version": 1,
            "palette": mapping.palette,
            "style": PALETTES[mapping.palette],
            "groups": groups,
            "sections": sections,
        },
    }


def present_graph(graph, schemas):
    # API responses are fresh decoded values; copy nodes to avoid modifying stored state.
    value = deepcopy(graph)
    for node in value.get("nodes", []):
        for key in ("result", "partial_result"):
            result = node.get(key)
            if isinstance(result, dict) and "sections" in result:
                plugin_id = result.get("plugin_id", node.get("plugin_id"))
                node[key] = present(result, schemas.get(plugin_id, {}))
    return value
