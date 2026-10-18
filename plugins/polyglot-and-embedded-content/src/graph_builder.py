"""Build an engine-compatible extraction/provenance graph."""


def build_graph(asset_name: str, formats: list[dict], artifacts: list[dict], flags: list[dict], relations: list[dict]) -> dict:
    """Create stable graph nodes and edges without frontend-specific components."""
    nodes = [{"id": "input", "label": asset_name, "type": "input", "status": "completed"}]
    edges = []
    for item in formats:
        nodes.append({"id": item["id"], "label": f"{item['format'].upper()} @{item['start_offset']}", "type": "format", "status": "validated", "confidence": item["confidence"]})
        edges.append({"source": "input", "target": item["id"], "relation": "contains", "label": f"offset {item['start_offset']}"})
    for relation in relations: edges.append({**relation, "label": relation["relation"]})
    hash_to_node = {}
    for index, artifact in enumerate(artifacts):
        node = f"artifact-{index + 1}"; hash_to_node[artifact.get("sha256")] = node
        nodes.append({"id": node, "label": artifact.get("name", node), "type": "artifact", "status": "extracted"})
        parent = artifact.get("parent_format_id") or artifact.get("format_id") or "input"
        edges.append({"source": parent, "target": node, "relation": "extracted", "label": artifact.get("extraction_method", "carved")})
    for index, flag in enumerate(flags):
        node = f"flag-{index + 1}"; nodes.append({"id": node, "label": flag["value"][:48], "type": "flag", "status": flag["classification"]})
        edges.append({"source": hash_to_node.get(flag.get("artifact_sha256"), "input"), "target": node, "relation": "contains_flag", "label": flag.get("decoder", "raw")})
    return {"nodes": nodes, "edges": edges}

