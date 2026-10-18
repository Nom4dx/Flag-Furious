"""BitLocker/FVE metadata facade backed by libbde with a bounded fallback.

libbde is the authoritative parser when available. The fallback only reports
boot-record evidence and metadata locations; it deliberately does not guess VMK
or FVEK structures from arbitrary bytes. This avoids presenting false key
protectors when metadata are damaged.
"""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

from .image_reader import SliceReader

METHODS = {
    0x8000:"AES-128-CBC with diffuser",0x8001:"AES-256-CBC with diffuser",
    0x8002:"AES-128-CBC",0x8003:"AES-256-CBC",0x8004:"AES-128-XTS",0x8005:"AES-256-XTS",
}
PROTECTORS = {0:"clear_key",0x100:"tpm",0x200:"startup_key",0x500:"tpm_and_pin",0x800:"recovery_password",0x2000:"password"}


def _guid(value) -> str | None:
    if value is None:return None
    if isinstance(value,uuid.UUID):return str(value)
    if isinstance(value,(bytes,bytearray)) and len(value)==16:
        try:return str(uuid.UUID(bytes_le=bytes(value)))
        except ValueError:return bytes(value).hex()
    return str(value)


def parse_with_libbde(path: Path, volume: dict) -> tuple[dict, list[dict], list[str]]:
    """Open a partition view through pybde and inventory public metadata.

    No password is set and no decrypted sectors are read. TPM material is never
    queried from the host. A missing binding or corrupt metadata yields a warning
    and lets the bounded fallback remain useful.
    """
    warnings=[];protectors=[];info={"parser":"internal_fve_boot_record","locked":True}
    try:import pybde
    except ImportError:return info,protectors,["pybde non disponibile: key protector non enumerati"]
    view=SliceReader(path,volume["offset"],volume["length"]);handle=None
    try:
        view.seek(0)
        if not pybde.check_volume_signature_file_object(view):
            return info,protectors,["libbde non conferma la firma del volume"]
        view.seek(0);handle=pybde.volume();handle.open_file_object(view)
        method=int(handle.encryption_method)
        locked=bool(handle.locked)
        # libbde intentionally refuses ``get_size`` before a credential has
        # unlocked the volume.  The encrypted partition extent is already
        # bounded and validated by the image reader, so use that value during
        # metadata-only triage instead of emitting a false parser warning.
        logical_size=volume["length"] if locked else int(handle.size)
        info.update({"parser":"pybde","libbde_version":pybde.get_version(),"volume_identifier":_guid(handle.identifier),
                     "description":handle.description or "","creation_time":str(handle.creation_time) if handle.creation_time else None,
                     "encryption_method_id":method,"encryption_method":METHODS.get(method,f"unknown_0x{method:04x}"),
                     # ``pybde.volume`` versions differ on whether they expose
                     # a logical ``offset`` property.  The authoritative source
                     # offset is the partition extent already selected by the
                     # Hub, so keep that stable value across bindings.
                     "size":logical_size,"locked":locked,"offset":int(volume["offset"])})
        for index in range(int(handle.number_of_key_protectors)):
            protector=handle.get_key_protector(index);kind=int(protector.type)
            protectors.append({"protector_id":f"protector-{index+1}","type":PROTECTORS.get(kind,f"unknown_0x{kind:04x}"),
                               "type_id":kind,"guid":_guid(protector.identifier),"version":None,"offset":None,"length":None,
                               "status":"recognized","requires_user_secret":kind not in {0},"confidence":.99,"parser":"pybde"})
    except Exception as exc:
        warnings.append(f"Parser libbde: {exc}")
    finally:
        try:
            if handle:handle.close()
        except Exception:pass
        view.close()
    return info,protectors,warnings


def metadata_copies(path: Path, volume: dict, block_size: int = 4096) -> list[dict]:
    """Hash declared primary/backup metadata blocks for consistency comparison.

    The boot record stores three relative metadata offsets in common BitLocker
    layouts. Hash comparison detects divergence without claiming which copy is
    semantically correct. Reads are bounded to one page per location.
    """
    rows=[]
    with path.open("rb") as source:
        for index,relative in enumerate(volume.get("metadata_offsets",[]),1):
            absolute=volume["offset"]+relative
            if absolute<volume["offset"] or absolute>=volume["offset"]+volume["length"]:continue
            source.seek(absolute);data=source.read(min(block_size,volume["offset"]+volume["length"]-absolute))
            rows.append({"copy":index,"role":"primary" if index==1 else "backup","relative_offset":relative,"offset":absolute,
                         "length":len(data),"sha256":hashlib.sha256(data).hexdigest(),"signature":data[:8].hex(),
                         "all_zero":not any(data),"status":"read" if data else "missing","parser":"fve_metadata_offsets"})
    baseline=rows[0]["sha256"] if rows else None
    for row in rows:row["matches_primary"]=row["sha256"]==baseline
    return rows
