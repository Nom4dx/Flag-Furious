"""Non-conclusive encryption and protected-container indicators.

The module never attempts decryption. It separates structural password markers
from high-entropy heuristics and emits broker requests for explicit user action.
"""

import zipfile
from pathlib import Path

from app.core.unlock_requests import request


def detect(path:Path,validated:list[dict],entropy:dict,asset_id:str)->tuple[list[dict],list[dict]]:
    """Return encryption indicators and password-free bruteforce requests."""
    indicators=[];requests=[]
    for item in validated:
        fmt=item["format"]
        protected=False;protection=fmt
        if fmt=="zip" and item["start_offset"]==0:
            try:
                with zipfile.ZipFile(path) as archive:protected=any(member.flag_bits&1 for member in archive.infolist())
            except (OSError,zipfile.BadZipFile):pass
            protection="zipcrypto"
        if fmt=="pdf":
            with path.open("rb") as source:source.seek(item["start_offset"]);protected=b"/Encrypt" in source.read(min(item["length"],8*1024*1024))
            protection="pdf"
        # 7z/RAR signatures do not prove encryption. Their bit-level encryption
        # flags need a format parser or an audited listing tool; keep this as a
        # low-confidence indicator and never open the broker automatically.
        if fmt in {"7z","rar4","rar5"}:
            indicators.append({"type":"possible_protected_container","format":fmt,"offset":item["start_offset"],"structural":False,"confidence":.42,"explanation":"Formato capace di cifratura; protezione non confermata dal solo header"})
        if protected:
            indicators.append({"type":"password_required","format":fmt,"offset":item["start_offset"],"structural":True,"confidence":.95})
            requests.append(request(asset_id,protection,"binary-static-analysis",[f"{protection}_adapter"],offset=item["start_offset"],operation="extract"))
    if entropy["global"]>7.7:indicators.append({"type":"high_entropy_unclassified","format":"unknown","offset":0,"structural":False,"confidence":.42,"explanation":"Può indicare compressione, cifratura o dati casuali"})
    return indicators,requests
