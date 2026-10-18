"""Internal PE/COFF parser following Microsoft PE/COFF layout.

DOS, COFF, optional headers, data directories and section tables are checked
against physical bounds. Optional ``pefile`` enriches imports/exports/resources;
its absence leaves the internal structural result intact. Samples are never run.
"""

from datetime import datetime, timezone
from pathlib import Path
import struct

from .binary_reader import BinaryReader
from .entropy_analyzer import shannon

MACHINES = {0x14C:"x86",0x8664:"x86_64",0x1C0:"ARM",0xAA64:"ARM64",0x1F0:"PowerPC",0x5032:"RISC-V32",0x5064:"RISC-V64"}
DIRECTORIES = ("export","import","resource","exception","certificate","relocation","debug","architecture","global_ptr","tls","load_config","bound_import","iat","delay_import","clr","reserved")


def analyze(path: Path, budget: int) -> dict:
    """Parse PE32/PE32+ headers and enrich safe metadata when available."""
    reader=BinaryReader(path,max(4096,min(budget,64*1024*1024)))
    if reader.read(0,2)!=b"MZ":raise ValueError("DOS magic assente")
    pe_offset=reader.unpack("<I",0x3C)[0]
    if pe_offset<0x40 or pe_offset>min(reader.size-24,16*1024*1024):raise ValueError("e_lfanew PE fuori dai limiti")
    if reader.read(pe_offset,4)!=b"PE\0\0":raise ValueError("Firma PE assente")
    machine,section_count,timestamp,symbol_ptr,symbol_count,optional_size,characteristics=reader.unpack("<HHIIIHH",pe_offset+4)
    if not 1<=section_count<=512:raise ValueError("Numero sezioni PE non plausibile")
    optional_offset=pe_offset+24
    magic=reader.unpack("<H",optional_offset)[0]
    if magic not in (0x10B,0x20B):raise ValueError("Optional header PE non supportato")
    is64=magic==0x20B
    minimum=112 if is64 else 96
    if optional_size<minimum:raise ValueError("Optional header PE troncato")
    optional=reader.read(optional_offset,optional_size)
    entry_rva=struct.unpack_from("<I",optional,16)[0]
    image_base=struct.unpack_from("<Q" if is64 else "<I",optional,24 if is64 else 28)[0]
    section_alignment,file_alignment=struct.unpack_from("<II",optional,32 if is64 else 32)
    image_size,headers_size=struct.unpack_from("<II",optional,56 if is64 else 56)
    subsystem,dll_characteristics=struct.unpack_from("<HH",optional,68 if is64 else 68)
    directory_count=min(struct.unpack_from("<I",optional,108 if is64 else 92)[0],16)
    directory_offset=112 if is64 else 96
    directories=[]
    for index in range(directory_count):
        rva,size=struct.unpack_from("<II",optional,directory_offset+index*8)
        directories.append({"name":DIRECTORIES[index],"rva":rva,"size":size})
    section_offset=optional_offset+optional_size
    sections=[];findings=[]
    for index in range(section_count):
        raw=reader.read(section_offset+index*40,40)
        name=raw[:8].split(b"\0",1)[0].decode("ascii","replace")
        virtual_size,virtual_address,raw_size,raw_offset=struct.unpack_from("<IIII",raw,8)
        flags=struct.unpack_from("<I",raw,36)[0]
        valid=raw_offset<=reader.size and raw_size<=reader.size-raw_offset
        perms=("R" if flags&0x40000000 else "")+("W" if flags&0x80000000 else "")+("X" if flags&0x20000000 else "")
        item={"index":index,"name":name,"offset":raw_offset,"size":raw_size,"raw_size":raw_size,"virtual_address":virtual_address,"virtual_size":virtual_size,"permissions":perms,"characteristics":hex(flags),"valid_bounds":valid}
        if valid and raw_size:item["entropy"]=shannon(reader.view(raw_offset,raw_size,1024*1024))
        if not valid:findings.append(_finding("invalid_header","high",.99,raw_offset,name,"Sezione PE oltre i limiti fisici"))
        if "W" in perms and "X" in perms:findings.append(_finding("rwx_section","high",.98,raw_offset,name,"Sezione PE scrivibile ed eseguibile"))
        if not name or not name.startswith("."):findings.append(_finding("unusual_section_name","low",.62,raw_offset,name,"Nome sezione PE non convenzionale"))
        if item.get("entropy",0)>7.4:findings.append(_finding("high_entropy_region","medium",.72,raw_offset,name,"Entropia elevata; possibile packing, compressione o dati casuali"))
        sections.append(item)
    entry_section=next((s for s in sections if s["virtual_address"]<=entry_rva<s["virtual_address"]+max(s["virtual_size"],s["size"]) and "X" in s["permissions"]),None)
    if not entry_section:findings.append(_finding("entrypoint_outside_executable_section","high",.96,entry_rva,None,"Entrypoint PE fuori da una sezione eseguibile"))
    try:stamp=datetime.fromtimestamp(timestamp,tz=timezone.utc).isoformat()
    except (ValueError,OSError,OverflowError):stamp="invalid"
    year=datetime.now(timezone.utc).year
    try:stamp_year=datetime.fromtimestamp(timestamp,tz=timezone.utc).year
    except (ValueError,OSError,OverflowError):stamp_year=0
    if stamp_year<1990 or stamp_year>year+1:findings.append(_finding("impossible_timestamp","medium",.85,pe_offset+8,None,"Timestamp COFF fuori dall’intervallo plausibile"))
    header={"format":"PE32+" if is64 else "PE32","dos_magic":"MZ","pe_offset":pe_offset,"machine":MACHINES.get(machine,hex(machine)),"section_count":section_count,"timestamp":timestamp,"timestamp_utc":stamp,"symbol_table_offset":symbol_ptr,"symbol_count":symbol_count,"characteristics":hex(characteristics),"entrypoint_rva":entry_rva,"image_base":image_base,"section_alignment":section_alignment,"file_alignment":file_alignment,"image_size":image_size,"headers_size":headers_size,"subsystem":subsystem,"dll_characteristics":hex(dll_characteristics),"data_directories":directories}
    imports,exports,symbols,extra_findings=_enrich(path,reader.size)
    findings.extend(extra_findings)
    certificate=next((item for item in directories if item["name"]=="certificate"),{"rva":0,"size":0})
    logical_end=max([headers_size,*(s["offset"]+s["size"] for s in sections if s["valid_bounds"]),certificate["rva"]+certificate["size"]])
    return {"format":"pe","validated":True,"header":header,"sections":sections,"segments":[],"entry_points":[{"relative_virtual_address":entry_rva,"virtual_address":image_base+entry_rva,"section":entry_section and entry_section["name"],"status":"validated" if entry_section else "candidate"}],"symbols":symbols,"imports":imports,"exports":exports,"relocations":[],"findings":findings,"logical_end":min(reader.size,logical_end),"architecture":header["machine"],"bits":64 if is64 else 32,"endian":"little","executable_regions":[s for s in sections if "X" in s["permissions"] and s["valid_bounds"]]}


def _enrich(path,size):
    imports=[];exports=[];symbols=[];findings=[]
    if size>64*1024*1024:return imports,exports,symbols,findings
    try:
        import pefile
    except ImportError:
        return imports,exports,symbols,findings
    try:
        pe=pefile.PE(str(path),fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]])
        for library in getattr(pe,"DIRECTORY_ENTRY_IMPORT",[]):
            dll=library.dll.decode("utf-8","replace") if library.dll else ""
            for item in library.imports[:10000]:
                name=item.name.decode("utf-8","replace") if item.name else f"ordinal:{item.ordinal}"
                row={"library":dll,"name":name,"address":item.address,"suspicious_category":_api_category(name)};imports.append(row)
                if row["suspicious_category"]:findings.append(_finding("suspicious_import","medium",.78,0,".idata",f"{dll}!{name}: {row['suspicious_category']}"))
        directory=getattr(pe,"DIRECTORY_ENTRY_EXPORT",None)
        for item in (directory.symbols if directory else [])[:10000]:exports.append({"name":item.name.decode("utf-8","replace") if item.name else "","ordinal":item.ordinal,"address":item.address})
        if getattr(pe,"DIRECTORY_ENTRY_TLS",None):findings.append(_finding("tls_callback","medium",.85,0,".tls","Directory TLS presente; verificare callback staticamente"))
        if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress:findings.append(_finding("dotnet_metadata","info",.99,0,None,"Directory CLR/.NET presente"))
    except (ValueError,AttributeError,TypeError,OSError,pefile.PEFormatError):
        pass
    return imports,exports,symbols,findings


def _api_category(name):
    value=name.casefold()
    categories={"process":["createprocess","shellexecute","winexec"],"injection":["virtualallocex","writeprocessmemory","createremotethread"],"network":["internetopen","urlmon","wsastartup","connect"],"dynamic_resolution":["loadlibrary","getprocaddress"],"anti_analysis":["isdebuggerpresent","checkremotedebugger"]}
    return next((category for category,terms in categories.items() if any(term in value for term in terms)),None)


def _finding(kind,severity,confidence,offset,section,explanation):return {"type":kind,"severity":severity,"confidence":confidence,"evidence":[explanation],"offset":offset,"section":section,"explanation":explanation}
