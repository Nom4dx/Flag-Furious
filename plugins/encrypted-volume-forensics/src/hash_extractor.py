"""Safe adapter for bitlocker2john hash extraction.

The tool accepts a BitLocker volume image rather than an arbitrary whole disk.
For a non-zero partition offset this adapter makes a temporary bounded partition
copy only when it fits the workspace allowance, then deletes that copy.
"""

from __future__ import annotations
import shutil
from pathlib import Path


def _copy_range(source:Path,target:Path,offset:int,length:int)->None:
    with source.open("rb") as src,target.open("xb") as dst:
        src.seek(offset);remaining=length
        while remaining:
            block=src.read(min(8*1024*1024,remaining))
            if not block:break
            dst.write(block);remaining-=len(block)


def extract(path:Path,volume:dict,temp_dir:Path,store,runner,max_copy_bytes:int)->tuple[list[dict],list[str]]:
    """Create John/Hashcat compatible text artifacts when the tool succeeds."""
    binary=shutil.which("bitlocker2john")
    if not binary:return [],["bitlocker2john non disponibile: hash non estratto"]
    candidate=path;temporary=None
    if volume["offset"]:
        if volume["length"]>max_copy_bytes:return [],["Hash non estratto: la copia della partizione supererebbe il workspace budget"]
        temp_dir.mkdir(parents=True,exist_ok=True);temporary=temp_dir/f"partition-{volume['offset']:x}.raw"
        _copy_range(path,temporary,volume["offset"],volume["length"]);candidate=temporary
    try:
        result=runner.run([binary,"-i",str(candidate)],120)
        lines=[]
        for line in (result["stdout"]+"\n"+result["stderr"]).splitlines():
            if "$bitlocker$" in line:
                value=line[line.find("$bitlocker$"):].strip();lines.append(value)
        unique=list(dict.fromkeys(lines))
        artifacts=[]
        for index,value in enumerate(unique,1):
            mode=value.split("$",3)[2] if value.count("$")>=3 else "unknown"
            artifacts.append(store.save("bitlocker",f"bitlocker-hash-{index}.txt",(value+"\n").encode(),{"kind":"password_hash","hash_format":"bitlocker","hash_mode":mode,"source_offset":volume["offset"],"protector_id":None,"john_compatible":True,"hashcat_compatible":True,"status":"ready_for_recovery","parent_artifact_id":volume["id"]}))
        warnings=[] if artifacts else [f"bitlocker2john non ha prodotto hash compatibili (exit {result['exit_code']})"]
        return artifacts,warnings
    finally:
        if temporary:temporary.unlink(missing_ok=True)
