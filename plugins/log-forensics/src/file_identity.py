"""Streaming hashes and passive identity for immutable log sources."""
from pathlib import Path
import hashlib,mimetypes

def identify(path: Path, asset: dict) -> dict:
    """Hash a regular file in blocks and return extension, MIME, head and size."""
    algorithms=("md5","sha1","sha256","sha512");provided=asset.get("hashes",{});size=path.stat().st_size
    with path.open('rb') as source:
        head=source.read(64)
        if not asset.get("partial_input") and int(asset.get("size",size))==size and all(provided.get(name) for name in algorithms):
            digest_values={name:provided[name] for name in algorithms}
            hash_source="hub_asset"
        else:
            hashes={name:hashlib.new(name) for name in algorithms};source.seek(0)
            while block:=source.read(1024*1024):
                for value in hashes.values():value.update(block)
            digest_values={name:value.hexdigest() for name,value in hashes.items()};hash_source="visible_file"
    return {"name":asset.get("name",path.name),"size":size,"declared_size":asset.get("size",size),"extension":path.suffix.casefold(),"mime":asset.get("mime") or mimetypes.guess_type(path.name)[0] or "application/octet-stream","magic_hex":head.hex(),"hashes":digest_values,"hash_source":hash_source,"original_modified":False}
