"""Normalized BitLocker metadata analysis and primary/backup diagnostics."""

from pathlib import Path
from .fve_parser import metadata_copies, parse_with_libbde


def analyze(path: Path, volume: dict) -> dict:
    """Return parser metadata, protector inventory and copy inconsistencies."""
    info,protectors,warnings=parse_with_libbde(path,volume)
    copies=metadata_copies(path,volume)
    diverged=bool(copies and any(not row["matches_primary"] for row in copies[1:]))
    if diverged:warnings.append("Metadata FVE primari e backup non coincidono a livello binario")
    return {"metadata":{**volume,**info,"metadata_copy_count":len(copies),"metadata_copies_diverge":diverged,
                         "encryption_percentage":None,"conversion_status":"unknown","nonce":"not_exposed",
                         "block_size":volume.get("bytes_per_sector"),"vmk":"not_exposed","fvek":"not_exposed"},
            "copies":copies,"protectors":protectors,"warnings":warnings}
