"""Content-based filesystem identification for decrypted volume artifacts."""

from pathlib import Path


def detect(path:Path)->dict:
    """Identify common filesystem boot records without mounting the file."""
    with path.open("rb") as source:
        head=source.read(4096)
        source.seek(1024);superblock=source.read(1024)
    kind="unknown";evidence=[]
    if head[3:11]==b"NTFS    ":kind="NTFS";evidence.append("NTFS OEM identifier")
    elif head[3:11]==b"EXFAT   ":kind="exFAT";evidence.append("exFAT OEM identifier")
    elif head[82:90].startswith(b"FAT32"):kind="FAT32";evidence.append("FAT32 BPB label")
    elif len(superblock)>=58 and superblock[56:58]==b"\x53\xef":kind="ext2/3/4";evidence.append("ext superblock magic")
    return {"filesystem":kind,"confidence":.99 if kind!="unknown" else .2,"evidence":evidence,"size":path.stat().st_size,"read_only":True}
