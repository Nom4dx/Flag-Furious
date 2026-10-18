"""Streaming hashes and passive identity for immutable log sources."""
from pathlib import Path
import hashlib,mimetypes

def identify(path: Path, asset: dict) -> dict:
    """Hash a regular file in blocks and return extension, MIME, head and size."""
    hashes={x:hashlib.new(x) for x in ("md5","sha1","sha256","sha512")};size=0
    with path.open('rb') as source:
        head=source.read(64);source.seek(0)
        while block:=source.read(1024*1024):
            size+=len(block)
            for value in hashes.values():value.update(block)
    return {"name":asset.get("name",path.name),"size":size,"extension":path.suffix.casefold(),"mime":asset.get("mime") or mimetypes.guess_type(path.name)[0] or "application/octet-stream","magic_hex":head.hex(),"hashes":{k:v.hexdigest() for k,v in hashes.items()},"original_modified":False}
