"""Safe, deduplicated output writer for carved binary ranges.

Only bytes supplied by validated parsers are written below the plugin output
directory. Names are sanitized, symlinks are refused and SHA-256 tracks identity.
"""

from pathlib import Path
import hashlib
import re


class ArtifactManager:
    """Persist bounded derived bytes while enforcing count and output budgets."""
    def __init__(self,root:Path,max_bytes:int,max_count:int=128):
        self.root=Path(root)/"binary-static-analysis";self.root.mkdir(parents=True,exist_ok=True)
        if self.root.is_symlink():raise ValueError("Directory artefatti simbolica non ammessa")
        self.max_bytes=max_bytes;self.max_count=max_count;self.written=0;self.hashes={}

    def save(self,category:str,name:str,data:bytes,metadata:dict)->dict:
        """Write one immutable derived artifact or return its deduplicated record."""
        digest=hashlib.sha256(data).hexdigest()
        if digest in self.hashes:return {**self.hashes[digest],"deduplicated":True}
        if len(self.hashes)>=self.max_count:raise ValueError("Limite numero artefatti raggiunto")
        if len(data)>64*1024*1024 or len(data)>self.max_bytes-self.written:raise ValueError("Budget output artefatti esaurito")
        folder=self.root/re.sub(r"[^a-z0-9_-]","_",category.casefold());folder.mkdir(exist_ok=True)
        safe=re.sub(r"[^A-Za-z0-9._-]","_",Path(name).name)[:180] or "artifact.bin";target=folder/f"{digest[:12]}-{safe}"
        target.write_bytes(data);self.written+=len(data)
        item={"path":str(target),"name":safe,"sha256":digest,"size":len(data),"status":"extracted","validated":bool(metadata.get("validated")),**metadata}
        self.hashes[digest]=item;return item
