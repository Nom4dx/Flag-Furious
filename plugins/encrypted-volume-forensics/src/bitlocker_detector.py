"""Fast BitLocker compatibility matcher used before full analysis."""

from pathlib import Path
from .volume_detector import FVE_SIGNATURE


def probe(path: Path, limit: int = 8 * 1024 * 1024) -> dict:
    """Inspect only a bounded prefix and common partition offsets."""
    size=path.stat().st_size;reasons=[];offsets=[]
    with path.open("rb") as source:
        data=source.read(min(size,limit))
    cursor=0
    while (hit:=data.find(FVE_SIGNATURE,cursor))>=0:
        start=max(0,hit-3);sector=data[start:start+64]
        bytes_per_sector=int.from_bytes(sector[11:13],"little") if len(sector)>=14 else 0
        clusters=sector[13] if len(sector)>=14 else 0
        if bytes_per_sector in {512,1024,2048,4096} and clusters and clusters & (clusters-1)==0:offsets.append(start)
        cursor=hit+1
        if len(offsets)>=16:break
    if offsets:reasons.append("Firma BitLocker/FVE nella vista limitata")
    if data[510:512]==b"\x55\xaa":reasons.append("Tabella MBR o boot sector presente")
    if data[512:520]==b"EFI PART":reasons.append("Header GPT presente")
    suffix=path.suffix.casefold()
    if suffix in {".img",".dd",".raw",".001",".vhd",".vhdx",".bde",".fve"}:reasons.append("Estensione immagine come indizio secondario")
    compatible=bool(offsets or reasons)
    return {"compatible":compatible,"score":.99 if offsets else .72 if len(reasons)>1 else .52 if reasons else 0,"reasons":reasons or ["Nessuna evidenza di volume cifrato nella vista limitata"],"candidate_offsets":offsets}
