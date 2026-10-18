"""Safe ZIP inventory and extraction for validated archive ranges.

Central-directory metadata is authoritative. Encryption, Zip Slip, symlinks,
overlapping/oversized entries and expansion ratios are handled without falling
back to blind local-header extraction.
"""

from io import BytesIO
from pathlib import PurePosixPath,Path
import stat
import zipfile

from .artifact_manager import ArtifactManager


def analyze_zip(path:Path,item:dict,store:ArtifactManager,max_entries:int=512,max_total:int=128*1024*1024,max_ratio:int=100)->dict:
    """Inventory and extract safe unencrypted ZIP entries with CRC validation."""
    if item["length"]>128*1024*1024:return {"entries":[],"artifacts":[],"warnings":["ZIP oltre limite lettura"],"encrypted":False}
    with path.open("rb") as source:source.seek(item["start_offset"]);raw=source.read(item["length"])
    rows=[];artifacts=[];warnings=[];total=0;encrypted=False
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        members=archive.infolist()
        if len(members)>max_entries:warnings.append(f"ZIP limitato a {max_entries} entry")
        for member in members[:max_entries]:
            name=PurePosixPath(member.filename.replace("\\","/"));is_link=stat.S_ISLNK(member.external_attr>>16)
            row={"name":member.filename,"compressed_size":member.compress_size,"size":member.file_size,"crc32":f"{member.CRC:08x}","header_offset":item["start_offset"]+member.header_offset,"encrypted":bool(member.flag_bits&1)}
            rows.append(row)
            if member.is_dir():continue
            if member.flag_bits&1:encrypted=True;continue
            if name.is_absolute() or ".." in name.parts or is_link:warnings.append(f"Entry ZIP non sicura ignorata: {member.filename}");continue
            ratio=member.file_size/max(1,member.compress_size)
            if member.file_size>32*1024*1024 or total+member.file_size>max_total or ratio>max_ratio:warnings.append(f"Limite espansione ZIP: {member.filename}");continue
            try:
                data=archive.read(member)
                if len(data)!=member.file_size:raise ValueError("dimensione estratta incoerente")
                artifacts.append(store.save("archive",name.name,data,{"parent_artifact_id":"input","start_offset":row["header_offset"],"detected_type":"archive_entry","validated":True,"confidence":.99,"extraction_method":"zip_central_directory_crc"}));total+=len(data)
            except (RuntimeError,zipfile.BadZipFile,ValueError) as exc:warnings.append(f"{member.filename}: {exc}")
    return {"entries":rows,"artifacts":artifacts,"warnings":warnings,"encrypted":encrypted,"bytes_extracted":total}
