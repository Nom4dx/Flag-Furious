"""Deduplicated artifact storage and bounded filesystem extraction.

Files are written below the plugin output root with sanitized names. The TSK
adapter reads regular files only and never executes content or follows host
symlinks. Directory traversal and output budgets are enforced centrally.
"""

from __future__ import annotations
import hashlib
from pathlib import Path
from .security import contained,safe_name


class ArtifactStore:
    """Write immutable derived bytes with SHA-256 deduplication."""
    def __init__(self,root:Path,budget:int):self.root=Path(root)/"encrypted-volume-forensics";self.root.mkdir(parents=True,exist_ok=True);self.budget=budget;self.used=0;self.by_hash={}
    def save(self,category:str,name:str,data:bytes,metadata:dict|None=None)->dict:
        digest=hashlib.sha256(data).hexdigest()
        if digest in self.by_hash:return {**self.by_hash[digest],"deduplicated":True}
        if self.used+len(data)>self.budget:raise ValueError("output byte budget exceeded")
        folder=contained(self.root,self.root/safe_name(category,"raw"));folder.mkdir(parents=True,exist_ok=True)
        target=contained(folder,folder/f"{digest[:12]}-{safe_name(name)}");target.write_bytes(data);target.chmod(0o400);self.used+=len(data)
        row={"artifact_id":f"artifact-{digest[:16]}","name":target.name,"path":str(target),"sha256":digest,"size":len(data),"status":"extracted","writable":False,**(metadata or {})}
        self.by_hash[digest]=row;return row
    def register_file(self,category:str,name:str,path:Path,metadata:dict|None=None)->dict:
        """Register an already-created bounded file without reading it all at once."""
        size=path.stat().st_size
        if self.used+size>self.budget:raise ValueError("output byte budget exceeded")
        digest=hashlib.sha256()
        with path.open("rb") as source:
            while block:=source.read(8*1024*1024):digest.update(block)
        value=digest.hexdigest();target_dir=contained(self.root,self.root/safe_name(category));target_dir.mkdir(parents=True,exist_ok=True)
        target=contained(target_dir,target_dir/f"{value[:12]}-{safe_name(name)}")
        if path.resolve()!=target: path.replace(target)
        target.chmod(0o400);self.used+=size
        row={"artifact_id":f"artifact-{value[:16]}","name":target.name,"path":str(target),"sha256":value,"size":size,"status":"extracted","writable":False,**(metadata or {})};self.by_hash[value]=row;return row


def extract_interesting(volume_path:Path,store:ArtifactStore,options:dict)->dict:
    """Enumerate and optionally extract selected files with pytsk3.

    Default behavior inventories entries and extracts only files matching a
    configured name/extension filter. Deleted entries are clearly labeled.
    Full-volume extraction is intentionally unavailable.
    """
    try:import pytsk3
    except ImportError:return {"filesystem":None,"files":[],"deleted":[],"ads":[],"artifacts":[],"warnings":["pytsk3 non disponibile"]}
    rows=[];deleted=[];ads=[];artifacts=[];warnings=[]
    max_entries=min(int(options.get("max_files",5000)),20000);max_extract=min(int(options.get("max_extract_files",64)),512)
    max_single=min(int(options.get("max_single_file",32*1024*1024)),128*1024*1024)
    extensions={str(x).casefold() for x in options.get("extensions",[])};name_filter=str(options.get("name_contains","")).casefold()
    try:
        image=pytsk3.Img_Info(str(volume_path));fs=pytsk3.FS_Info(image);filesystem=str(fs.info.ftype)
        queue=[("/",fs.open_dir(path="/"))]
        while queue and len(rows)<max_entries:
            parent,directory=queue.pop(0)
            for entry in directory:
                name=entry.info.name.name
                if isinstance(name,bytes):name=name.decode("utf-8","replace")
                if name in {".",".."}:continue
                path=f"{parent.rstrip('/')}/{name}";meta=entry.info.meta
                if not meta:continue
                allocated=bool(meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC);is_dir=meta.type==pytsk3.TSK_FS_META_TYPE_DIR
                row={"path":path,"inode":meta.addr,"size":meta.size,"allocated":allocated,"deleted":not allocated,"is_directory":is_dir,
                     "created":getattr(meta,"crtime",0),"modified":getattr(meta,"mtime",0),"accessed":getattr(meta,"atime",0)}
                rows.append(row)
                if not allocated:deleted.append(row)
                if is_dir and allocated:
                    try:queue.append((path,fs.open_dir(inode=meta.addr)))
                    except Exception as exc:warnings.append(f"Directory {path}: {exc}")
                elif options.get("extract",True) and len(artifacts)<max_extract and meta.size<=max_single:
                    wanted=(not extensions or Path(name).suffix.casefold() in extensions) and (not name_filter or name_filter in path.casefold())
                    if wanted:
                        try:
                            handle=fs.open_meta(inode=meta.addr);data=handle.read_random(0,meta.size)
                            artifacts.append(store.save("filesystem",name,data,{"source_path":path,"inode":meta.addr,"deleted":not allocated,"extraction_method":"pytsk3","parent_artifact_id":"unlocked-volume"}))
                        except Exception as exc:warnings.append(f"Estrazione {path}: {exc}")
        return {"filesystem":filesystem,"files":rows,"deleted":deleted,"ads":ads,"artifacts":artifacts,"warnings":warnings}
    except Exception as exc:return {"filesystem":None,"files":rows,"deleted":deleted,"ads":ads,"artifacts":artifacts,"warnings":[f"Analisi filesystem: {exc}"]}
