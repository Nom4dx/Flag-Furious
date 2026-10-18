import struct
import pytest
from conftest import fat_boot, ext_superblock
from diskhunt.parsers.fat import parse_fat_boot
from diskhunt.parsers.ext import parse_ext_superblock


@pytest.mark.parametrize("kind,sectors,expected",[("FAT12",2000,"FAT12"),("FAT16",20000,"FAT16"),("FAT32",100000,"FAT32")])
def test_fat_families(kind,sectors,expected):
    data=bytearray(fat_boot(kind,min(sectors,65535)))
    if sectors>65535: struct.pack_into("<H",data,19,0); struct.pack_into("<I",data,32,sectors); struct.pack_into("<H",data,22,0); struct.pack_into("<I",data,36,100)
    # The FAT family is derived from geometry, not the cosmetic string.
    parsed=parse_fat_boot(data); assert parsed["type"]==expected; assert parsed["bytes_per_sector"]==512; assert parsed["fat_count"]==2


def test_ext4_superblock_fields():
    parsed=parse_ext_superblock(ext_superblock()); assert parsed["type"]=="ext4"; assert parsed["block_size"]==4096; assert parsed["inode_size"]==256


def test_invalid_superblocks():
    with pytest.raises(ValueError): parse_fat_boot(bytes(512))
    with pytest.raises(ValueError): parse_ext_superblock(bytes(1024))
