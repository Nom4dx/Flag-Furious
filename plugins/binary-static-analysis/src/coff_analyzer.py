"""COFF object-file recognition without loading executable code.

Standalone COFF lacks a universal magic. The parser accepts only known machine
types, bounded section counts and an in-file section table, reducing false hits.
"""

from pathlib import Path
from .binary_reader import BinaryReader

MACHINES={0x14c:"x86",0x8664:"x86_64",0x1c0:"ARM",0xaa64:"ARM64",0x1f0:"PowerPC"}


def analyze(path:Path,budget:int)->dict:
    """Validate a standalone COFF header and return its section inventory."""
    reader=BinaryReader(path,max(1024,min(budget,16*1024*1024)))
    machine,count,timestamp,symbol_offset,symbol_count,optional_size,flags=reader.unpack("<HHIIIHH",0)
    if machine not in MACHINES or not 1<=count<=512 or optional_size>4096:raise ValueError("Header COFF non plausibile")
    table=20+optional_size
    sections=[]
    for index in range(count):
        raw=reader.read(table+index*40,40);name=raw[:8].split(b"\0",1)[0].decode("ascii","replace")
        size,offset=reader.unpack("<II",table+index*40+16)
        if offset>reader.size or size>reader.size-offset:raise ValueError("Sezione COFF fuori dai limiti")
        characteristics=reader.unpack("<I",table+index*40+36)[0]
        sections.append({"index":index,"name":name,"offset":offset,"size":size,"permissions":("R" if characteristics&0x40000000 else "")+("W" if characteristics&0x80000000 else "")+("X" if characteristics&0x20000000 else ""),"characteristics":hex(characteristics),"valid_bounds":True})
    end=max([table+count*40,*(s["offset"]+s["size"] for s in sections)])
    return {"format":"coff","validated":True,"header":{"machine":MACHINES[machine],"section_count":count,"timestamp":timestamp,"symbol_table_offset":symbol_offset,"symbol_count":symbol_count,"characteristics":hex(flags)},"sections":sections,"segments":[],"entry_points":[],"symbols":[],"imports":[],"exports":[],"relocations":[],"findings":[],"logical_end":end,"architecture":MACHINES[machine],"bits":64 if machine in (0x8664,0xaa64) else 32,"endian":"little","executable_regions":[s for s in sections if "X" in s["permissions"]]}
