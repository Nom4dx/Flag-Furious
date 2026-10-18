"""Artifact/decoder/flag provenance graph for the central 2D engine."""


def build(source_name: str, source_sha256: str, formats: list[dict], artifacts: list[dict], decoded: list[dict], flags: list[dict]) -> dict:
    """Build stable nodes and ``source``/``target`` edges accepted by the hub.

    The user specification uses ``from``/``to`` conceptually; the shared engine
    contract requires ``source``/``target``. Both provenance meaning and relation
    labels are preserved.
    """
    nodes=[{"id":"input","type":"source","label":source_name,"sha256":source_sha256,"status":"completed"}];edges=[];hash_nodes={}
    for item in formats:
        node=item["id"];nodes.append({"id":node,"type":"format","label":f"{item['format'].upper()} @{item['start_offset']}","status":"validated","confidence":item["confidence"]});edges.append({"source":"input","target":node,"relation":"contains","label":item["boundary_method"]})
    for index,artifact in enumerate(artifacts,1):
        node=f"artifact-{index}";hash_nodes[artifact.get("sha256")]=node;nodes.append({"id":node,"type":"embedded_payload","label":artifact.get("name",node),"status":artifact.get("status","extracted"),"sha256":artifact.get("sha256")});parent=artifact.get("format_id") or "input";edges.append({"source":parent if any(x["id"]==parent for x in nodes) else "input","target":node,"relation":artifact.get("technique","extracted"),"label":artifact.get("technique","extracted")})
    decoded_nodes={}
    for index,item in enumerate(decoded,1):
        node=f"decoded-{index}";decoded_nodes[item.get("output_hash")]=node
        chain_label=" → ".join(item.get("decoder_chain",[]))
        nodes.append({"id":node,"type":"decoded_text","label":chain_label[:80] or "Decoded payload","status":"decoded","confidence":item.get("confidence")})
        parent=hash_nodes.get(item.get("input_hash"),"input");edges.append({"source":parent,"target":node,"relation":"decoded_as","label":chain_label})
    for index,flag in enumerate(flags,1):
        node=f"flag-{index}";nodes.append({"id":node,"type":"flag","label":flag["value"][:64],"status":"candidate","confidence":flag["confidence"]});parent=hash_nodes.get(flag.get("artifact_sha256"),"input");edges.append({"source":parent,"target":node,"relation":"contains","label":flag.get("technique","flag")})
    return {"nodes":nodes,"edges":edges}
