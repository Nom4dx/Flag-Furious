"""Metadata and comment extraction from common image/audio/container structures."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

from .safe_subprocess import locate, run


def analyze(path: Path, data: bytes, formats: list[dict], timeout: int, output_limit: int) -> dict:
    """Extract internal PNG/JPEG/RIFF comments and optional ExifTool metadata.

    Values remain bounded text/hex previews with offsets. Compressed PNG metadata
    is decompressed under a fixed cap. No metadata payload is executed.
    """
    items=[];warnings=[];tools=[]
    for fmt in formats:
        start=fmt["start_offset"]
        if fmt["format"]=="png":
            for chunk in fmt.get("details",{}).get("chunks",[]):
                kind=chunk["type"]
                if kind not in {"tEXt","zTXt","iTXt","eXIf","iCCP"}:continue
                relative=chunk["offset"]+8;raw=data[relative:relative+min(chunk["length"],1024*1024)]
                decoded=raw
                if kind=="zTXt" and b"\0" in raw:
                    key,compressed=raw.split(b"\0",1)
                    try:decoded=key+b"="+zlib.decompress(compressed[1:])[:1024*1024]
                    except zlib.error as exc:warnings.append(f"zTXt @{relative}: {exc}")
                items.append({"type":"metadata","namespace":"PNG","field":kind,"raw_value":raw[:256].hex(),"normalized_value":decoded[:4096].decode("utf-8","replace"),"offset":relative,"length":chunk["length"],"confidence":.96})
        if fmt["format"]=="jpeg":
            for segment in fmt.get("details",{}).get("segments",[]):
                marker=segment["marker"]
                if marker.startswith("FFE") or marker=="FFFE":
                    offset=segment["offset"]+4;raw=data[offset:offset+min(segment["length"]-2,1024*1024)]
                    items.append({"type":"metadata","namespace":"JPEG","field":marker,"raw_value":raw[:256].hex(),"normalized_value":raw[:4096].decode("utf-8","replace"),"offset":offset,"length":len(raw),"confidence":.92})
    if locate("exiftool"):
        result=run("exiftool",["-json","-G","-n","--",str(path)],timeout,output_limit);tools.append(result)
        if result["exit_code"]==0:items.append({"type":"external_metadata","namespace":"ExifTool","field":"json","normalized_value":result["stdout"],"offset":None,"confidence":.9})
    return {"items":items,"warnings":warnings,"tools":tools}
