"""File-structure and static-code graph builders for the Hub 2D engine.

Graphs use stable deterministic IDs, explicit labels and relation types. Large
collections are capped so the central renderer can group/expand them safely.
"""

import hashlib


def structure(name:str,size:int,parsed:dict|None,validated:list[dict],artifacts:list[dict],findings:list[dict])->dict:
    """Build file → header/regions → embedded/artifact/finding relationships."""
    nodes=[{"id":"binary-file","type":"binary_file","label":name,"offset":0,"size":size,"status":"validated" if parsed else "candidate"}];edges=[]
    if parsed:
        nodes.append({"id":"binary-header","type":"header","label":f"{parsed['format'].upper()} header","offset":0,"size":parsed.get("header",{}).get("header_size",0),"status":"validated"});edges.append({"source":"binary-file","target":"binary-header","relation":"starts_with"})
        for category in ("segments","sections"):
            for item in parsed.get(category,[])[:500]:
                node_id=f"{category[:-1]}-{item.get('index',len(nodes))}";nodes.append({"id":node_id,"type":category[:-1],"label":item.get("name") or item.get("type") or node_id,"offset":item.get("offset"),"size":item.get("size",item.get("file_size")),"permissions":item.get("permissions"),"status":"validated" if item.get("valid_bounds",True) else "failed"});edges.append({"source":"binary-file","target":node_id,"relation":"contains"})
    for index,item in enumerate(validated[:500]):
        if item["start_offset"]==0 and parsed:continue
        node_id=f"embedded-{index}";nodes.append({"id":node_id,"type":"embedded_file","label":f"{item['format']} @ {item['start_offset']}","offset":item["start_offset"],"size":item["length"],"status":"validated"});edges.append({"source":"binary-file","target":node_id,"relation":"contains"})
    for index,item in enumerate(artifacts[:500]):
        node_id=f"artifact-{item['sha256'][:12]}";nodes.append({"id":node_id,"type":"artifact","label":item["name"],"size":item["size"],"sha256":item["sha256"],"status":"extracted"});edges.append({"source":"binary-file","target":node_id,"relation":item.get("extraction_method","extracted")})
    for index,item in enumerate(findings[:300]):
        digest=hashlib.sha1(f"{item.get('type')}:{item.get('offset')}:{index}".encode()).hexdigest()[:10];node_id=f"finding-{digest}";nodes.append({"id":node_id,"type":"finding","label":item.get("type","finding"),"offset":item.get("offset"),"status":"partial"});edges.append({"source":"binary-file","target":node_id,"relation":"has_finding"})
    return {"nodes":nodes,"edges":edges}


def code(entry_points:list[dict],functions:dict,imports:list[dict],instructions:list[dict])->dict:
    """Build entrypoint → function/block/call/import static relationships."""
    nodes=[];edges=[]
    for index,item in enumerate(entry_points):nodes.append({"id":f"entry-{index}","type":"entrypoint","label":hex(int(item.get("virtual_address",item.get("relative_virtual_address",0)))) ,"status":item.get("status","candidate")})
    for item in functions.get("functions",[])[:1000]:nodes.append({"id":item["id"],"type":"function","label":hex(item["address"]),"status":"validated" if item["classification"]=="function_confirmed" else "candidate"})
    for item in functions.get("blocks",[])[:2000]:nodes.append({"id":item["id"],"type":"basic_block","label":hex(item["start"]),"status":"candidate"})
    for index,item in enumerate(imports[:500]):nodes.append({"id":f"import-{index}","type":"import","label":item.get("name","import"),"status":"validated"})
    known={node["id"] for node in nodes};function_by_address={item["address"]:item["id"] for item in functions.get("functions",[])}
    if nodes:
        for item in functions.get("functions",[]):
            if "entry-0" in known:edges.append({"source":"entry-0","target":item["id"],"relation":"reaches"})
        for item in functions.get("calls",[]):
            target=function_by_address.get(item["to"])
            source=next((block["id"] for block in functions.get("blocks",[]) if block["start"]<=item["from"]<block["end"]),None)
            if source and target:edges.append({"source":source,"target":target,"relation":item["type"]})
    return {"nodes":nodes,"edges":edges}
