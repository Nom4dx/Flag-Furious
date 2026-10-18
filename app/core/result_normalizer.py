from app.models.contracts import Result
from app.core.visualization_engine import validate_visualization


def normalize(raw, plugin_id, asset_id, schema):
    result = Result.model_validate({**raw, "plugin_id": plugin_id, "asset_id": asset_id}).model_dump()
    definitions = {x["id"]: x for x in schema.get("sections", [])}
    sections = []
    for section in result["sections"]:
        sections.append({**section, **definitions.get(section.get("id"), {})})
    result["sections"] = sorted(sections, key=lambda s: s.get("order", 100))
    charts = []
    for chart in result["visualizations"]:
        try:
            charts.append(validate_visualization(chart))
        except (ValueError, TypeError) as exc:
            result["warnings"].append(str(exc))
            result["status"] = "partial"
    result["visualizations"] = charts
    for finding in result["findings"]:
        if isinstance(finding, dict):
            finding.setdefault("asset_id", asset_id)
            finding.setdefault("plugin_id", plugin_id)
            finding.setdefault("phase", result["phase"])
            finding.setdefault("confidence", result["confidence"])
            finding.setdefault("offset", None)
            finding.setdefault("source", asset_id)
    return result
