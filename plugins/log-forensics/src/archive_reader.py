"""Bounded reader for directories, rotations and compressed log containers."""
from pathlib import Path,PurePosixPath
import bz2,gzip,lzma,stat,zipfile

def collect(path:Path,budget:int,store,max_files:int=256,max_single:int=64*1024*1024,max_ratio:int=100):
    """Return in-memory bounded sources, derived artifacts and safety warnings."""
    sources=[];artifacts=[];warnings=[];remaining=budget
    paths=[]
    if path.is_dir():paths=[x for x in sorted(path.rglob('*')) if x.is_file() and not x.is_symlink()][:max_files]
    else:paths=[path]
    for item in paths:
        if remaining<=0:break
        try:
            raw=item.read_bytes()[:min(remaining,max_single)];remaining-=len(raw)
        except OSError as exc:warnings.append(f'{item.name}: {exc}');continue
        suffix=item.suffix.casefold()
        try:
            if suffix in {'.gz','.bz2','.xz'} or raw.startswith((b'\x1f\x8b\x08',b'BZh',b'\xfd7zXZ\x00')):
                decoder=gzip.decompress if raw.startswith(b'\x1f\x8b') or suffix=='.gz' else bz2.decompress if raw.startswith(b'BZh') or suffix=='.bz2' else lzma.decompress
                decoded=decoder(raw)
                if len(decoded)>max_single or len(decoded)>max(1,len(raw))*max_ratio:raise ValueError('rapporto di espansione oltre il limite')
                artifact=store.save('decompressed',item.stem or 'log',decoded,{"source_file":item.name,"extraction_method":"bounded_decompression","detected_type":"log_candidate"});artifacts.append(artifact);sources.append((artifact['name'],decoded,Path(artifact['path'])));continue
            if suffix=='.zip' or raw.startswith(b'PK\x03\x04'):
                with zipfile.ZipFile(item) as archive:
                    for member in archive.infolist()[:max_files]:
                        name=PurePosixPath(member.filename.replace('\\','/'));link=stat.S_ISLNK(member.external_attr>>16)
                        if member.is_dir() or member.flag_bits&1:warnings.append(f'{member.filename}: cifrato o directory, non estratto');continue
                        if name.is_absolute() or '..' in name.parts or link:warnings.append(f'{member.filename}: path o symlink non sicuro');continue
                        if member.file_size>max_single or member.file_size/max(1,member.compress_size)>max_ratio: warnings.append(f'{member.filename}: limite espansione');continue
                        decoded=archive.read(member);artifact=store.save('archive',name.name,decoded,{"source_file":item.name,"internal_path":member.filename,"extraction_method":"zip_crc","detected_type":"log_candidate"});artifacts.append(artifact);sources.append((member.filename,decoded,Path(artifact['path'])))
                continue
            sources.append((str(item.relative_to(path)) if path.is_dir() else item.name,raw,item))
        except (OSError,ValueError,EOFError,zipfile.BadZipFile,lzma.LZMAError) as exc:warnings.append(f'{item.name}: contenitore non estratto: {exc}')
    if len(paths)>=max_files:warnings.append(f'Input limitato a {max_files} file')
    if remaining<=0:warnings.append('Byte budget raggiunto durante la lettura sorgenti')
    return sources,artifacts,warnings,budget-remaining
