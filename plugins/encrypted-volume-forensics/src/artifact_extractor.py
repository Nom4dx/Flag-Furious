"""Deduplicated artifact storage and bounded filesystem extraction.

Files are written below the plugin output root with sanitized names. The TSK
adapter reads regular files only and never executes content or follows host
symlinks. Directory traversal and output budgets are enforced centrally.
"""

from __future__ import annotations
import hashlib
from collections import deque
from pathlib import Path
from .security import contained,safe_name


class ArtifactStore:
    """Write immutable derived bytes with SHA-256 deduplication."""
    def __init__(self,root:Path,budget:int):self.root=Path(root)/"encrypted-volume-forensics";self.root.mkdir(parents=True,exist_ok=True);self.budget=budget;self.used=0;self.by_hash={}
    def _merge_provenance(self,digest:str,metadata:dict|None)->dict:
        existing=self.by_hash[digest];provenance=dict(metadata or {})
        if provenance:
            occurrences=existing.setdefault("source_occurrences",[])
            if provenance not in occurrences:
                if len(occurrences)<100:occurrences.append(provenance)
                else:existing["provenance_occurrences_omitted"]=existing.get("provenance_occurrences_omitted",0)+1
        return {**existing,"deduplicated":True}
    def save(self,category:str,name:str,data:bytes,metadata:dict|None=None)->dict:
        digest=hashlib.sha256(data).hexdigest()
        provenance=dict(metadata or {})
        if digest in self.by_hash:
            return self._merge_provenance(digest,provenance)
        if self.used+len(data)>self.budget:raise ValueError("output byte budget exceeded")
        folder=contained(self.root,self.root/safe_name(category,"raw"));folder.mkdir(parents=True,exist_ok=True)
        target=contained(folder,folder/f"{digest}-{safe_name(name)}");target.write_bytes(data);target.chmod(0o400);self.used+=len(data)
        row={"artifact_id":f"artifact-{digest}","name":target.name,"path":str(target),"sha256":digest,"size":len(data),"status":"extracted","writable":False,**provenance}
        if provenance:row["source_occurrences"]=[provenance]
        self.by_hash[digest]=row;return row
    def register_file(self,category:str,name:str,path:Path,metadata:dict|None=None)->dict:
        """Register an already-created bounded file without reading it all at once."""
        size=path.stat().st_size
        if self.used+size>self.budget:raise ValueError("output byte budget exceeded")
        digest=hashlib.sha256()
        with path.open("rb") as source:
            while block:=source.read(8*1024*1024):digest.update(block)
        value=digest.hexdigest()
        if value in self.by_hash:
            existing=self._merge_provenance(value,metadata)
            if path.resolve()!=Path(existing["path"]).resolve():path.unlink(missing_ok=True)
            return existing
        target_dir=contained(self.root,self.root/safe_name(category));target_dir.mkdir(parents=True,exist_ok=True)
        target=contained(target_dir,target_dir/f"{value}-{safe_name(name)}")
        if path.resolve()!=target: path.replace(target)
        target.chmod(0o400);self.used+=size
        provenance=dict(metadata or {})
        row={"artifact_id":f"artifact-{value}","name":target.name,"path":str(target),"sha256":value,"size":size,"status":"extracted","writable":False,**provenance}
        if provenance:row["source_occurrences"]=[provenance]
        self.by_hash[value]=row;return row


def extract_interesting(volume_path:Path,store:ArtifactStore,options:dict)->dict:
    """Enumerate and optionally extract selected files with pytsk3.

    Default behavior inventories entries and extracts only files matching a
    configured name/extension filter. Deleted entries are clearly labeled.
    Full-volume extraction is intentionally unavailable.
    """
    try:import pytsk3
    except ImportError:return {"filesystem":None,"files":[],"deleted":[],"ads":[],"artifacts":[],"warnings":["pytsk3 non disponibile"]}
    rows=[];deleted=[];ads=[];artifacts=[];warnings=[];warning_keys=set();omitted_warnings=0
    def warn(message):
        nonlocal omitted_warnings
        message=str(message)[:1024]
        if len(warnings)<100:
            if message in warning_keys:return
            warning_keys.add(message);warnings.append(message)
        else:omitted_warnings+=1
    def bounded_option(name,default,minimum,maximum):
        try:value=int(options.get(name,default))
        except (TypeError,ValueError):value=default
        return max(minimum,min(value,maximum))
    max_entries=bounded_option("max_files",5000,1,20000);max_extract=bounded_option("max_extract_files",64,0,512)
    max_single=bounded_option("max_single_file",32*1024*1024,0,128*1024*1024)
    extensions={str(x).casefold() for x in options.get("extensions",[])};name_filter=str(options.get("name_contains","")).casefold()
    try:
        image=pytsk3.Img_Info(str(volume_path));fs=pytsk3.FS_Info(image);filesystem=str(fs.info.ftype)
        queue=deque([("/",fs.open_dir(path="/"))]);entry_cap_hit=False;artifact_ids=set()
        while queue and len(rows)<max_entries:
            parent,directory=queue.popleft()
            for entry in directory:
                if len(rows)>=max_entries:
                    entry_cap_hit=True;break
                name=entry.info.name.name
                if isinstance(name,bytes):name=name.decode("utf-8","replace")
                if name in {".",".."}:continue
                path=f"{parent.rstrip('/')}/{name}";meta=entry.info.meta
                if not meta:continue
                size=max(0,int(meta.size));allocated=bool(meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC)
                is_dir=meta.type==pytsk3.TSK_FS_META_TYPE_DIR
                row={"path":path,"inode":meta.addr,"size":size,"allocated":allocated,"deleted":not allocated,"is_directory":is_dir,
                     "created":getattr(meta,"crtime",0),"modified":getattr(meta,"mtime",0),"accessed":getattr(meta,"atime",0)}
                rows.append(row)
                if not allocated:deleted.append(row)
                if is_dir and allocated:
                    try:queue.append((path,fs.open_dir(inode=meta.addr)))
                    except Exception as exc:warn(f"Directory {path}: {exc}")
                elif meta.type==getattr(pytsk3,"TSK_FS_META_TYPE_REG",None) and options.get("extract",True):
                    wanted=(not extensions or Path(name).suffix.casefold() in extensions) and (not name_filter or name_filter in path.casefold())
                    if wanted:
                        if size>max_single:
                            warn(f"Estrazione esclusa dal limite per file singolo: {path} ({size} byte)")
                        elif len(artifacts)>=max_extract:
                            warn(f"Estrazione esclusa dal limite artefatti ({max_extract}): {path}")
                        elif size>store.budget-store.used:
                            warn("Estrazione fermata: budget cumulativo degli artefatti esaurito")
                            continue
                        else:
                            try:
                                handle=fs.open_meta(inode=meta.addr);data=handle.read_random(0,size)
                                if len(data)!=size:
                                    warn(f"Estrazione parziale esclusa: {path} ({len(data)}/{size} byte)")
                                    continue
                                stored=store.save("filesystem",name,data,{"source_path":path,"inode":meta.addr,"deleted":not allocated,"extraction_method":"pytsk3","parent_artifact_id":"unlocked-volume"})
                                if stored["artifact_id"] not in artifact_ids:
                                    artifacts.append(stored);artifact_ids.add(stored["artifact_id"])
                            except Exception as exc:warn(f"Estrazione {path}: {exc}")
        if queue or entry_cap_hit:warn(f"Inventario filesystem parziale: raggiunto il limite di {max_entries} entry")
        if omitted_warnings:warnings.append(f"Omesse {omitted_warnings} diagnostiche oltre il limite di 100")
        return {"filesystem":filesystem,"files":rows,"deleted":deleted,"ads":ads,"artifacts":artifacts,"warnings":warnings}
    except Exception as exc:
        warn(f"Analisi filesystem: {exc}")
        if omitted_warnings:warnings.append(f"Omesse {omitted_warnings} diagnostiche oltre il limite di 100")
        return {"filesystem":None,"files":rows,"deleted":deleted,"ads":ads,"artifacts":artifacts,"warnings":warnings}
