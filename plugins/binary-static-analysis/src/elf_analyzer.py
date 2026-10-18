"""Internal ELF32/ELF64 structural parser.

The parser follows the ELF header, program-header and section-header tables with
explicit endian/class formats and bounds. It does not load, link or execute the
object. DWARF content is inventoried by section name but not fully decoded.
"""

from pathlib import Path
import struct

from .binary_reader import BinaryReader
from .entropy_analyzer import shannon

MACHINES = {3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM", 43: "SPARCv9", 62: "x86_64", 183: "AArch64", 243: "RISC-V", 247: "BPF"}
PT = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR", 7: "TLS", 0x6474E551: "GNU_STACK", 0x6474E552: "GNU_RELRO"}


def analyze(path: Path, budget: int) -> dict:
    """Parse an ELF at offset zero and return bounded structure dictionaries.

    Invalid table ranges raise ``ValueError``. Counts are capped at 8192 entries;
    strings and section samples are bounded. Output distinguishes sections,
    segments, symbols, imports, exports, relocations and findings.
    """
    reader = BinaryReader(path, max(4096, min(budget, 64 * 1024 * 1024)))
    ident = reader.read(0, 16)
    if ident[:4] != b"\x7fELF" or ident[4] not in (1, 2) or ident[5] not in (1, 2):
        raise ValueError("Header ELF non valido")
    bits = 32 if ident[4] == 1 else 64
    endian = "<" if ident[5] == 1 else ">"
    fmt = endian + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH")
    values = reader.unpack(fmt, 16)
    keys = ("type", "machine", "version", "entrypoint", "program_offset", "section_offset", "flags", "header_size", "program_entry_size", "program_count", "section_entry_size", "section_count", "section_names_index")
    header = dict(zip(keys, values))
    header.update(format="ELF", bits=bits, endian="little" if endian == "<" else "big", os_abi=ident[7], architecture=MACHINES.get(header["machine"], f"machine-{header['machine']}"))
    minimum_header = 52 if bits == 32 else 64
    if header["header_size"] < minimum_header:
        raise ValueError("Dimensione header ELF incoerente")
    if header["program_count"] > 8192 or header["section_count"] > 8192:
        raise ValueError("Numero tabelle ELF oltre il limite")
    segments = _segments(reader, header, endian, bits)
    raw_sections = _section_headers(reader, header, endian, bits)
    names = _section_names(reader, raw_sections, header["section_names_index"])
    sections = []
    findings = []
    for index, section in enumerate(raw_sections):
        section["index"] = index
        section["name"] = _cstring(names, section["name_offset"])
        section["permissions"] = ("W" if section["flags"] & 1 else "") + ("A" if section["flags"] & 2 else "") + ("X" if section["flags"] & 4 else "")
        if section["type"] != 8 and section["size"]:
            if section["offset"] > reader.size or section["size"] > reader.size - section["offset"]:
                section["valid_bounds"] = False
                findings.append(_finding("invalid_header", "high", 0.99, section["offset"], section["name"], "Sezione oltre i limiti fisici"))
            else:
                section["valid_bounds"] = True
                sample = reader.view(section["offset"], section["size"], 1024 * 1024)
                section["entropy"] = shannon(sample)
        if section["flags"] & 1 and section["flags"] & 4:
            findings.append(_finding("rwx_section", "high", 0.98, section["offset"], section["name"], "Sezione ELF scrivibile ed eseguibile"))
        sections.append(section)
    for left, right in zip(sorted((s for s in sections if s.get("valid_bounds") and s["size"]), key=lambda x: x["offset"]), sorted((s for s in sections if s.get("valid_bounds") and s["size"]), key=lambda x: x["offset"])[1:]):
        if left["offset"] + left["size"] > right["offset"]:
            findings.append(_finding("overlapping_sections", "medium", 0.95, right["offset"], right["name"], "Sezioni ELF sovrapposte"))
    symbols, imports, exports, relocations = _symbols(reader, sections, endian, bits)
    entry_section = next((s for s in sections if s.get("address", 0) <= header["entrypoint"] < s.get("address", 0) + s.get("size", 0) and "X" in s["permissions"]), None)
    if header["entrypoint"] and not entry_section:
        findings.append(_finding("entrypoint_outside_executable_section", "high", 0.95, 0, None, "Entrypoint non contenuto in una sezione eseguibile"))
    logical_end = max([header["header_size"], *(s["offset"] + s["size"] for s in sections if s.get("valid_bounds")), *(s["offset"] + s["file_size"] for s in segments)], default=reader.size)
    return {"format":"elf", "validated":True, "header":header, "sections":sections, "segments":segments, "entry_points":[{"virtual_address":header["entrypoint"],"section":entry_section and entry_section["name"],"status":"validated" if entry_section else "candidate"}], "symbols":symbols, "imports":imports, "exports":exports, "relocations":relocations, "findings":findings, "logical_end":min(reader.size, logical_end), "architecture":header["architecture"], "bits":bits, "endian":header["endian"], "executable_regions":[s for s in sections if "X" in s["permissions"] and s.get("valid_bounds")]}


def _segments(reader, header, endian, bits):
    expected = 32 if bits == 32 else 56
    if header["program_count"] and header["program_entry_size"] < expected:
        raise ValueError("Program header ELF troppo piccolo")
    rows = []
    for index in range(header["program_count"]):
        offset = header["program_offset"] + index * header["program_entry_size"]
        values = reader.unpack(endian + ("IIIIIIII" if bits == 32 else "IIQQQQQQ"), offset)
        if bits == 32:
            p_type, file_offset, vaddr, paddr, file_size, memory_size, flags, alignment = values
        else:
            p_type, flags, file_offset, vaddr, paddr, file_size, memory_size, alignment = values
        if file_offset > reader.size or file_size > reader.size - file_offset:
            raise ValueError(f"Segmento ELF {index} fuori dai limiti")
        perms = ("R" if flags & 4 else "") + ("W" if flags & 2 else "") + ("X" if flags & 1 else "")
        rows.append({"index":index,"type":PT.get(p_type,hex(p_type)),"offset":file_offset,"file_size":file_size,"virtual_address":vaddr,"physical_address":paddr,"virtual_size":memory_size,"alignment":alignment,"permissions":perms})
    return rows


def _section_headers(reader, header, endian, bits):
    expected = 40 if bits == 32 else 64
    if header["section_count"] and header["section_entry_size"] < expected:
        raise ValueError("Section header ELF troppo piccolo")
    keys = ("name_offset","type","flags","address","offset","size","link","info","alignment","entry_size")
    fmt = endian + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ")
    return [dict(zip(keys, reader.unpack(fmt, header["section_offset"] + index * header["section_entry_size"]))) for index in range(header["section_count"])]


def _section_names(reader, sections, index):
    if not sections or index >= len(sections):
        return b""
    item = sections[index]
    if item["offset"] > reader.size or item["size"] > reader.size - item["offset"]:
        return b""
    return reader.view(item["offset"], item["size"], 4 * 1024 * 1024)


def _cstring(table, offset):
    if offset < 0 or offset >= len(table):
        return ""
    return table[offset : table.find(b"\0", offset) if table.find(b"\0", offset) >= 0 else len(table)].decode("utf-8", "replace")[:256]


def _symbols(reader, sections, endian, bits):
    symbols=[];imports=[];exports=[];relocations=[]
    for section in sections:
        if not section.get("valid_bounds") or not section.get("entry_size"):
            continue
        if section["type"] in (2, 11) and section["link"] < len(sections):
            strings=sections[section["link"]];table=reader.view(strings["offset"],strings["size"],8*1024*1024) if strings.get("valid_bounds") else b""
            count=min(section["size"]//section["entry_size"],20000)
            fmt=endian+("IIIBBH" if bits==32 else "IBBHQQ")
            size=struct.calcsize(fmt)
            for i in range(count):
                pos=section["offset"]+i*section["entry_size"]
                if size>section["entry_size"]:break
                vals=reader.unpack(fmt,pos)
                name_off,value,size_value,info,other,shndx=vals if bits==32 else (vals[0],vals[4],vals[5],vals[1],vals[2],vals[3])
                name=_cstring(table,name_off)
                if not name:continue
                row={"name":name,"value":value,"size":size_value,"binding":info>>4,"type":info&15,"section_index":shndx,"source_section":section["name"]}
                symbols.append(row)
                if shndx==0:imports.append(row)
                elif (info>>4) in (1,2):exports.append(row)
        elif section["type"] in (4,9):
            count=min(section["size"]//section["entry_size"],20000)
            relocations.extend({"section":section["name"],"offset":section["offset"]+i*section["entry_size"]} for i in range(count))
    return symbols,imports,exports,relocations


def _finding(kind,severity,confidence,offset,section,explanation):
    return {"type":kind,"severity":severity,"confidence":confidence,"evidence":[explanation],"offset":offset,"section":section,"explanation":explanation}
