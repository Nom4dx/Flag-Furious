"""Deduplicated artifact writer restricted to the isolated plugin output tree."""
from pathlib import Path
import hashlib,re
class ArtifactManager:
    """Save authorized derived bytes with safe names, SHA-256 and output limits."""
    def __init__(self,root:Path,budget:int,count:int=256):
        self.root=Path(root)/'log-forensics';self.root.mkdir(parents=True,exist_ok=True);self.budget=budget;self.count=count;self.used=0;self.saved={}
    def save(self,category:str,name:str,data:bytes,metadata:dict)->dict:
        """Persist bytes without overwriting or following source-controlled paths."""
        digest=hashlib.sha256(data).hexdigest()
        if digest in self.saved:return {**self.saved[digest],"deduplicated":True}
        if len(self.saved)>=self.count or len(data)>64*1024*1024 or self.used+len(data)>self.budget:raise ValueError("Budget artefatti log esaurito")
        folder=self.root/re.sub(r'[^a-z0-9_-]','_',category.casefold());folder.mkdir(exist_ok=True)
        safe=re.sub(r'[^A-Za-z0-9._-]','_',Path(name).name)[:160] or 'artifact.bin';target=folder/f'{digest[:12]}-{safe}';target.write_bytes(data);self.used+=len(data)
        row={"path":str(target),"name":safe,"sha256":digest,"size":len(data),"status":"extracted",**metadata};self.saved[digest]=row;return row
