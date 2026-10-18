"""Binary/container interval, overlay, entropy and mismatch analysis."""

from __future__ import annotations

from pathlib import Path

from .file_identity import entropy_windows


def analyze(path: Path, data: bytes, identity: dict, hits: list[dict], formats: list[dict], rejected: list[dict]) -> dict:
    """Classify validated intervals, appended/prepended bytes and high entropy.

    Signatures rejected by validators remain false-positive candidates. Format
    mismatches compare extension/MIME to validated content and never infer truth
    from the filename.
    """
    findings=[];regions=[];size=path.stat().st_size;primary=next((x for x in formats if x["start_offset"]==0),formats[0] if formats else None)
    expected={".png":"png",".jpg":"jpeg",".jpeg":"jpeg",".gif":"gif",".bmp":"bmp",".pdf":"pdf",".zip":"zip",".wav":"wav",".webp":"webp",".ogg":"ogg",".flac":"flac",".mp3":"mp3"}.get(identity["extension"])
    if expected and primary and primary["format"]!=expected:findings.append({"type":"format_mismatch","extension":identity["extension"],"declared_mime":identity["declared_mime"],"detected_format":primary["format"],"offset":primary["start_offset"],"severity":"medium","confidence":primary["confidence"],"status":"detected"})
    if primary:
        if primary["start_offset"]:regions.append({"type":"prepended_data","start_offset":0,"end_offset":primary["start_offset"],"length":primary["start_offset"],"status":"detected","confidence":.9})
        if primary["end_offset"]<size:
            nested=[x for x in formats if x["start_offset"]>=primary["end_offset"]]
            regions.append({"type":"appended_validated_format" if nested else "appended_uninterpreted","start_offset":primary["end_offset"],"end_offset":size,"length":size-primary["end_offset"],"formats":[x["format"] for x in nested],"status":"detected","confidence":.96 if nested else .6})
    relations=[]
    for index,left in enumerate(formats):
        for right in formats[index+1:]:
            relation="concatenated" if right["start_offset"]>=left["end_offset"] else "embedded" if right["end_offset"]<=left["end_offset"] else "overlapping"
            relations.append({"source":left["id"],"target":right["id"],"relation":relation,"confidence":min(left["confidence"],right["confidence"])})
    windows=entropy_windows(data)
    high=[x for x in windows if x["entropy"]>7.75]
    if high:findings.append({"type":"high_entropy_regions","severity":"low","message":"Possibile compressione o cifratura; l'entropia non prova steganografia","regions":high[:128],"status":"detected","confidence":.45})
    return {"signature_hits":hits,"validated_formats":formats,"rejected_signatures":rejected,"regions":regions,"relations":relations,"entropy_windows":windows,"findings":findings}
