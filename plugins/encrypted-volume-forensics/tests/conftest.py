"""Synthetic, non-secret BitLocker-like fixtures for parser tests."""
from __future__ import annotations
import importlib.util,struct,sys,types
from pathlib import Path
import pytest

PLUGIN_ROOT=Path(__file__).resolve().parents[1]

def load_module(name:str):
    """Load a plugin source module without relying on its hyphenated folder name."""
    package='evf_test'
    if package not in sys.modules:
        module=types.ModuleType(package);module.__path__=[str(PLUGIN_ROOT)];sys.modules[package]=module
    full=f'{package}.{name}';path=PLUGIN_ROOT.joinpath(*name.split('.')).with_suffix('.py')
    spec=importlib.util.spec_from_file_location(full,path);module=importlib.util.module_from_spec(spec);sys.modules[full]=module;spec.loader.exec_module(module);return module

def fve_sector(total_sectors=4096,metadata=(65536,131072,196608)):
    """Build a structurally plausible VBR, not an encrypted working volume."""
    value=bytearray(512);value[:3]=b'\xeb\x58\x90';value[3:11]=b'-FVE-FS-';struct.pack_into('<H',value,11,512);value[13]=8;struct.pack_into('<Q',value,40,total_sectors)
    for position,offset in zip((0xb0,0xb8,0xc0),metadata):struct.pack_into('<Q',value,position,offset)
    value[510:512]=b'\x55\xaa';return value

@pytest.fixture
def whole_fve(tmp_path):
    path=tmp_path/'volume.raw';data=bytearray(2*1024*1024);data[:512]=fve_sector();data[65536:65544]=b'-FVE-FS-';path.write_bytes(data);return path

@pytest.fixture
def mbr_fve(tmp_path):
    path=tmp_path/'disk.dd';data=bytearray(4*1024*1024);start=2048;sectors=4096
    entry=bytearray(16);entry[4]=7;struct.pack_into('<II',entry,8,start,sectors);data[446:462]=entry;data[510:512]=b'\x55\xaa';offset=start*512;data[offset:offset+512]=fve_sector(sectors);data[offset+65536:offset+65544]=b'-FVE-FS-';path.write_bytes(data);return path
