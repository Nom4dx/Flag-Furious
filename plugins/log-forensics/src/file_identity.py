"""Streaming hashes and passive identity for immutable log sources."""
from pathlib import Path
import hashlib,mimetypes

def identify(path: Path, asset: dict, byte_budget: int | None = None) -> dict:
    """Hash a bounded regular-file view and return extension, MIME, head and size."""
    algorithms=("md5","sha1","sha256","sha512");provided=asset.get("hashes",{});size=path.stat().st_size
    with path.open('rb') as source:
        head=source.read(64)
        if not asset.get("partial_input") and int(asset.get("size",size))==size and all(provided.get(name) for name in algorithms):
            digest_values={name:provided[name] for name in algorithms}
            hash_source="hub_asset";bytes_hashed=size
        else:
            limit=size if byte_budget is None else min(size,max(0,int(byte_budget)))
            hashes={name:hashlib.new(name) for name in algorithms};source.seek(0);bytes_hashed=0
            while bytes_hashed<limit and (block:=source.read(min(1024*1024,limit-bytes_hashed))):
                for value in hashes.values():value.update(block)
            digest_values={name:value.hexdigest() for name,value in hashes.items()};hash_source="visible_file" if bytes_hashed==size else "visible_prefix"
    hash_complete=bytes_hashed==size
    return {"name":asset.get("name",path.name),"size":size,"declared_size":asset.get("size",size),"extension":path.suffix.casefold(),"mime":asset.get("mime") or mimetypes.guess_type(path.name)[0] or "application/octet-stream","magic_hex":head.hex(),"hashes":digest_values,"hash_source":hash_source,"bytes_hashed":bytes_hashed,"hash_complete":hash_complete,"hash_scope":"entire_file" if hash_complete else "visible_prefix","original_modified":False}
