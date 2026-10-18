"""Streaming inventory and iteration for local wordlists."""
import hashlib
from pathlib import Path
EXT={'.txt','.lst','.dic','.wordlist'}
def _encoding(path):
    head=path.open('rb').read(4)
    return 'utf-16' if head.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8'
def inventory(roots,max_files=5000):
    """Inventory permitted files with streamed SHA-256 and sampled line count."""
    out=[];seen={}
    for root_item in roots:
        root=Path(root_item['path'])
        if not root.is_dir():continue
        for path in root.rglob('*'):
            if len(out)>=max_files:break
            if not path.is_file() or path.is_symlink() or path.suffix.lower() not in EXT:continue
            digest=hashlib.sha256();newlines=0;size=0
            with path.open('rb') as source:
                while block:=source.read(1024*1024):digest.update(block);newlines+=block.count(b'\n');size+=len(block)
            hexdigest=digest.hexdigest();duplicate_of=seen.get(hexdigest);seen.setdefault(hexdigest,str(path))
            out.append({'name':path.name,'path':str(path.resolve()),'relative_path':str(path.relative_to(root)),'root_source':root_item['source'],'size':size,'estimated_lines':newlines+(1 if size else 0),'sha256':hexdigest,'encoding':_encoding(path),'modified':path.stat().st_mtime,'duplicate_of':duplicate_of,'category':'ctf' if 'ctf' in str(path).lower() else 'common','status':'duplicate' if duplicate_of else 'available'})
    return out

def stream(paths,max_lines=10_000_000):
    """Yield `(password, relative source, line)` across lists without retaining values."""
    count=0
    for path in paths:
        path=Path(path)
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in EXT:continue
        encoding=_encoding(path)
        try:
            with path.open('r',encoding=encoding,errors='strict') as source:
                for line_no,line in enumerate(source,1):
                    if count>=max_lines:return
                    count+=1;yield line.rstrip('\r\n'),path.name,line_no
        except UnicodeError:
            with path.open('r',encoding='latin-1') as source:
                for line_no,line in enumerate(source,1):
                    if count>=max_lines:return
                    count+=1;yield line.rstrip('\r\n'),path.name,line_no
