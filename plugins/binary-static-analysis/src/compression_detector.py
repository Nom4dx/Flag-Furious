"""Structural compression markers and conservative entropy hints."""

COMPRESSED={"gzip","xz","bzip2","zstd","lz4","zip","7z","rar4","rar5","squashfs_le","squashfs_be"}


def detect(candidates:list[dict],entropy:dict)->list[dict]:
    """Return signature-backed compression candidates plus an entropy hint."""
    rows=[{"format":item["format"],"offset":item["offset"],"evidence":"firma di compressione","validated":item.get("validated",False),"confidence":item.get("confidence",.55)} for item in candidates if item["format"] in COMPRESSED]
    if entropy["global"]>7.4 and not rows:rows.append({"format":"unknown","offset":0,"evidence":"entropia elevata senza struttura compressa validata","validated":False,"confidence":.45})
    return rows
