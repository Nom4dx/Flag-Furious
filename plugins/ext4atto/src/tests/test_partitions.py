import struct
from io import BytesIO
from diskhunt.parsers.partitions import detect_filesystem, inspect_partitions
from conftest import fat_boot, ext_superblock


def make_mbr(entries):
    disk = bytearray(4 * 1024 * 1024); disk[510:512] = b"\x55\xaa"
    for i,(ptype,start,length) in enumerate(entries):
        off=446+i*16; disk[off+4]=ptype; struct.pack_into("<II",disk,off+8,start,length)
    return disk


def test_mbr_and_fat16():
    disk=make_mbr([(0x06,1,100)]); disk[512:1024]=fat_boot("FAT16")
    table,parts,issues=inspect_partitions(BytesIO(disk),len(disk)); assert table=="MBR"; assert parts[0]["filesystem"]=="FAT16"; assert not issues


def test_partition_overlap_and_bad_offset():
    disk=make_mbr([(0x83,1,5000),(0x83,100,5000)])
    _,parts,issues=inspect_partitions(BytesIO(disk),len(disk)); assert any("overlap" in x for x in issues); assert any(p["status"]=="overlapping" for p in parts)


def test_gpt_and_backup():
    disk=make_mbr([(0xEE,1,7000)]); disk[512:520]=b"EFI PART"; struct.pack_into("<Q",disk,512+32,7000); struct.pack_into("<QII",disk,512+72,2,1,128)
    disk[1024:1040]=b"1"*16; struct.pack_into("<QQ",disk,1024+32,40,80); disk[7000*512:7000*512+8]=b"EFI PART"
    table,parts,_=inspect_partitions(BytesIO(disk),len(disk)); assert table=="GPT"; assert parts[0]["start_sector"]==40


def test_corrupt_gpt():
    disk=make_mbr([(0xEE,1,7000)]); table,_,issues=inspect_partitions(BytesIO(disk),len(disk)); assert table=="GPT-corrupt"; assert issues


def test_raw_ext_detection():
    disk=bytearray(8192); disk[1024:2048]=ext_superblock(); table,parts,_=inspect_partitions(BytesIO(disk),len(disk)); assert table=="none"; assert parts[0]["filesystem"]=="ext2/3/4"


def test_fat_superfloppy_is_not_empty_mbr():
    disk=bytearray(1024*1024); disk[:512]=fat_boot("FAT16")
    table,parts,issues=inspect_partitions(BytesIO(disk),len(disk)); assert table=="none"; assert parts[0]["filesystem"]=="FAT16"
