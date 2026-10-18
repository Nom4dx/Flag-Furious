"""Declarative 2D graph and forensic timeline construction."""

from __future__ import annotations
from datetime import datetime,timezone


def build(asset:dict,image:dict,partitions:list[dict],volumes:list[dict],metadata:list[dict],protectors:list[dict],hashes:list[dict],unlock:list[dict],filesystem:list[dict],artifacts:list[dict],flags:list[dict])->dict:
    """Represent containment and recovery without putting credentials in nodes."""
    root="disk-1";nodes=[{"id":root,"type":"disk_image","label":asset.get("name","disk image"),"size":image.get("size"),"sha256":image.get("sha256"),"status":"analyzed"}];edges=[]
    for part in partitions:
        node=f"partition-{part['number']}";nodes.append({"id":node,"type":"partition","label":part.get("name") or f"{part['scheme']} partition {part['number']}","offset":part["offset"],"size":part["length"],"status":part["status"]});edges.append({"source":root,"target":node,"relation":"contains"})
    for volume in volumes:
        vid=volume["id"];nodes.append({"id":vid,"type":"bitlocker_volume","label":f"BitLocker volume @{volume['offset']}","offset":volume["offset"],"size":volume["length"],"status":"validated" if volume["validated"] else "candidate"})
        parent=next((f"partition-{p['number']}" for p in partitions if p["offset"]==volume["offset"]),root);edges.append({"source":parent,"target":vid,"relation":"contains"})
        for index,row in enumerate([x for x in metadata if x.get("volume_id")==vid],1):
            mid=f"{vid}-metadata-{index}";nodes.append({"id":mid,"type":"fve_metadata","label":f"FVE metadata {index}","offset":row.get("offset"),"status":row.get("status")});edges.append({"source":vid,"target":mid,"relation":"contains"})
        for row in [x for x in protectors if x.get("volume_id")==vid]:
            pid=f"{vid}-{row['protector_id']}";nodes.append({"id":pid,"type":"key_protector","label":row["type"],"status":row["status"]});edges.append({"source":vid,"target":pid,"relation":"defines"})
    for row in hashes:
        nodes.append({"id":row["artifact_id"],"type":"hash_artifact","label":row["name"],"status":"ready_for_recovery"});edges.append({"source":row.get("parent_artifact_id",root),"target":row["artifact_id"],"relation":"derived_hash"})
    for index,row in enumerate(unlock,1):
        node=f"unlock-{index}";nodes.append({"id":node,"type":"unlock_attempt","label":row.get("method","unlock"),"status":row["status"]});edges.append({"source":row.get("volume_id",root),"target":node,"relation":"unlock_attempt"})
    for index,row in enumerate(filesystem,1):
        node=f"filesystem-{index}";nodes.append({"id":node,"type":"filesystem","label":row.get("filesystem","unknown"),"status":"read_only"});edges.append({"source":row.get("volume_id",root),"target":node,"relation":"unlocked_as"})
    for row in artifacts:
        if any(node["id"]==row["artifact_id"] for node in nodes):continue
        nodes.append({"id":row["artifact_id"],"type":"extracted_file","label":row.get("name","artifact"),"status":row.get("status","extracted"),"sha256":row.get("sha256")});edges.append({"source":row.get("parent_artifact_id",root),"target":row["artifact_id"],"relation":"contains"})
    for index,row in enumerate(flags,1):
        node=f"flag-{index}";nodes.append({"id":node,"type":"flag","label":"Flag candidate","status":row.get("status","candidate")});parent=row.get("source_artifact",root)
        if not any(existing["id"]==parent for existing in nodes):parent=root
        edges.append({"source":parent,"target":node,"relation":"contains"})
    return {"nodes":nodes,"edges":edges}


def timeline(phases:list[dict])->list[dict]:
    """Convert execution events into a stable relative forensic timeline."""
    now=datetime.now(timezone.utc).isoformat()
    return [{"id":f"timeline-{index}","timestamp":now,"event":row["phase"],"status":row["status"],"duration":row.get("duration",0),"source":"encrypted-volume-forensics"} for index,row in enumerate(phases,1)]
