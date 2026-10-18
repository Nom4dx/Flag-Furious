"""Streaming inventory and iteration for local wordlists."""
import hashlib
import os
from pathlib import Path
EXT={'.txt','.lst','.dic','.wordlist'}
def _encoding(path):
    with path.open('rb') as source:head=source.read(4)
    return 'utf-16' if head.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8'
def inventory(roots,max_files=1024,max_total_bytes=256*1024**2,max_file_bytes=64*1024**2,max_directories=10000,return_meta=False):
    """Inventory permitted files with streamed SHA-256 and sampled line count."""
    out=[];seen={};total_hashed=0;walked=0;limited=False;partial_files=0
    for root_item in roots:
        root=Path(root_item['path'])
        if not root.is_dir():continue
        for base,dirs,files in os.walk(root,followlinks=False):
            walked+=1
            if walked>max_directories:limited=True;break
            dirs[:]=sorted(name for name in dirs if not (Path(base)/name).is_symlink())
            for name in sorted(files):
                if len(out)>=max_files or total_hashed>=max_total_bytes:limited=True;break
                path=Path(base)/name
                if path.is_symlink() or not path.is_file() or path.suffix.lower() not in EXT:continue
                try:size=path.stat().st_size
                except OSError:continue
                limit=min(size,max_file_bytes,max_total_bytes-total_hashed);digest=hashlib.sha256();newlines=0;hashed=0
                try:
                    with path.open('rb') as source:
                        while hashed<limit:
                            block=source.read(min(1024*1024,limit-hashed))
                            if not block:break
                            digest.update(block);newlines+=block.count(b'\n');hashed+=len(block)
                except OSError:continue
                total_hashed+=hashed;is_partial=hashed<size;partial_files+=int(is_partial)
                hexdigest=digest.hexdigest();duplicate_of=seen.get(hexdigest) if not is_partial else None
                if not is_partial:seen.setdefault(hexdigest,str(path))
                out.append({'name':path.name,'path':str(path.resolve()),'relative_path':str(path.relative_to(root)),'root_source':root_item['source'],'size':size,'hashed_bytes':hashed,'hash_complete':not is_partial,'inventory_partial':is_partial,'estimated_lines':newlines+(1 if hashed else 0),'sha256':hexdigest,'encoding':_encoding(path),'modified':path.stat().st_mtime,'duplicate_of':duplicate_of,'category':'ctf' if 'ctf' in str(path).lower() else 'common','status':'duplicate' if duplicate_of else 'partial' if is_partial else 'available'})
            if limited:break
        if limited:break
    meta={'limited':limited,'bytes_hashed':total_hashed,'partial_files':partial_files}
    return (out,meta) if return_meta else out

def stream(paths,max_lines=10_000_000,max_candidate_chars=4096,warning_sink=None):
    """Yield `(password, relative source, line)` across lists without retaining values."""
    count=0
    for path in paths:
        path=Path(path)
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in EXT:continue
        encoding=_encoding(path)
        try:
            with path.open('r',encoding=encoding,errors='strict') as source:
                line_no=0
                while True:
                    line=source.readline(max_candidate_chars+1)
                    if not line:break
                    line_no+=1
                    if count>=max_lines:return
                    count+=1
                    if len(line)>max_candidate_chars and not line.endswith(('\n','\r')):
                        drained=len(line)
                        while line and not line.endswith(('\n','\r')) and drained<1024*1024:
                            line=source.readline(max_candidate_chars+1);drained+=len(line)
                        if warning_sink is not None:warning_sink.append(f"{path.name}:{line_no} candidato oltre {max_candidate_chars} caratteri ignorato")
                        if drained>=1024*1024 and not line.endswith(('\n','\r')):
                            if warning_sink is not None:warning_sink.append(f"Lettura {path.name} fermata su una riga oltre 1 MiB")
                            return
                        continue
                    yield line.rstrip('\r\n'),path.name,line_no
        except UnicodeError:
            with path.open('r',encoding='latin-1') as source:
                line_no=0
                while True:
                    line=source.readline(max_candidate_chars+1)
                    if not line:break
                    line_no+=1
                    if count>=max_lines:return
                    count+=1
                    if len(line)>max_candidate_chars and not line.endswith(('\n','\r')):
                        drained=len(line)
                        while line and not line.endswith(('\n','\r')) and drained<1024*1024:
                            line=source.readline(max_candidate_chars+1);drained+=len(line)
                        if warning_sink is not None:warning_sink.append(f"{path.name}:{line_no} candidato oltre {max_candidate_chars} caratteri ignorato")
                        if drained>=1024*1024 and not line.endswith(('\n','\r')):
                            if warning_sink is not None:warning_sink.append(f"Lettura {path.name} fermata su una riga oltre 1 MiB")
                            return
                        continue
                    yield line.rstrip('\r\n'),path.name,line_no
