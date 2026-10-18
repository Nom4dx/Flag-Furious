"""Structural parser tests for executable formats and firmware."""
import importlib
import hashlib


def test_elf_32_64_and_rwx(package,fixtures):
    elf=importlib.import_module(package+".src.elf_analyzer")
    assert elf.analyze(fixtures/"elf32.bin",1_000_000)["bits"]==32
    parsed=elf.analyze(fixtures/"elf64.bin",1_000_000)
    assert parsed["validated"] and parsed["sections"][1]["name"]==".text"
    assert any(x["type"]=="rwx_section" for x in elf.analyze(fixtures/"elf-rwx.bin",1_000_000)["findings"])


def test_pe_32_64(package,fixtures):
    pe=importlib.import_module(package+".src.pe_analyzer")
    assert pe.analyze(fixtures/"pe32.bin",1_000_000)["bits"]==32
    assert pe.analyze(fixtures/"pe64.bin",1_000_000)["bits"]==64


def test_macho_and_uboot(package,fixtures):
    macho=importlib.import_module(package+".src.macho_analyzer")
    firmware=importlib.import_module(package+".src.firmware_analyzer")
    assert macho.analyze(fixtures/"macho64.bin",1_000_000)["header"]["bits"]==64
    item={"offset":0,"validator":"uboot"}
    result=firmware.analyze(fixtures/"uboot.bin",item)
    assert result["validated"] and result["header"]["header_crc_valid"]
