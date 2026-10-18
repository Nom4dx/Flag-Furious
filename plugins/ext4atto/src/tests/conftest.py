import os
import struct
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "backend"))


def fat_boot(kind="FAT16", sectors=8192):
    b = bytearray(512); b[:3] = b"\xeb\x3c\x90"; b[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHBHHBHHHII", b, 11, 512, 1, 1, 2, 512, sectors, 0xF8, 9, 32, 64, 0, 0)
    b[43:54] = b"DISKHUNT   "; b[54:62] = kind.encode().ljust(8); b[510:512] = b"\x55\xaa"
    return bytes(b)


def ext_superblock():
    b = bytearray(1024); struct.pack_into("<IIII", b, 0, 128, 4096, 2048, 64); struct.pack_into("<I", b, 24, 2)
    struct.pack_into("<I", b, 32, 32768); struct.pack_into("<I", b, 40, 1024); struct.pack_into("<HH", b, 56, 0xEF53, 1)
    struct.pack_into("<H", b, 88, 256); struct.pack_into("<III", b, 92, 4, 0x40, 0); b[120:128] = b"TESTEXT4"
    return bytes(b)


@pytest.fixture
def tmp_data(tmp_path, monkeypatch):
    monkeypatch.setenv("DISKHUNT_DATA_DIR", str(tmp_path / "data")); return tmp_path

