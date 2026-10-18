"""Mach-O 32/64 and FAT/Universal structural parser.

Mach headers lead to bounded load commands; LC_SEGMENT/LC_SEGMENT_64 expose
sections and executable regions. FAT slices are inventoried and checked for
overlap. Code signatures and encryption commands are reported, never invoked.
"""

from pathlib import Path
import struct

from .binary_reader import BinaryReader
from .entropy_analyzer import shannon

MAGICS={b"\xfe\xed\xfa\xce":(">",32),b"\xce\xfa\xed\xfe":("<",32),b"\xfe\xed\xfa\xcf":(">",64),b"\xcf\xfa\xed\xfe":("<",64)}
CPU={7:"x86",0x01000007:"x86_64",12:"ARM",0x0100000C:"ARM64",18:"PowerPC",0x01000012:"PowerPC64"}


def analyze(path:Path,budget:int,base_offset:int=0)->dict:
    """Parse Mach-O or FAT headers and return sections, slices and findings."""
    reader=BinaryReader(path,max(4096,min(budget,64*1024*1024)))
    magic=reader.read(base_offset,4)
    if magic in (b"\xca\xfe\xba\xbe",b"\xca\xfe\xba\xbf",b"\xbe\xba\xfe\xca",b"\xbf\xba\xfe\xca"):
        return _fat(reader,base_offset,magic)
    if magic not in MAGICS:raise ValueError("Magic Mach-O non valido")
    endian,bits=MAGICS[magic];header_fmt=endian+("IIIIII" if bits==32 else "IIIIIII")
    cpu,subtype,file_type,command_count,commands_size,flags,*reserved=reader.unpack(header_fmt,base_offset+4)
    header_size=28 if bits==32 else 32
    if command_count>8192 or commands_size>reader.size-base_offset-header_size:raise ValueError("Load commands Mach-O fuori dai limiti")
    commands=[];sections=[];findings=[];cursor=base_offset+header_size
    logical_end=cursor+commands_size
    for index in range(command_count):
        command,size=reader.unpack(endian+"II",cursor)
        if size<8 or size>commands_size or cursor+size>base_offset+header_size+commands_size:raise ValueError("Load command Mach-O non valida")
        row={"index":index,"command":hex(command),"offset":cursor,"size":size}
        if command in (1,0x19):
            segment_bits=64 if command==0x19 else 32
            fmt=endian+("16sIIIIIIII" if segment_bits==32 else "16sQQQQIIII")
            vals=reader.unpack(fmt,cursor+8);name=vals[0].split(b"\0",1)[0].decode("ascii","replace")
            vmaddr,vmsize,fileoff,filesize,maxprot,initprot,nsects,segflags=vals[1:]
            row.update(name=name,virtual_address=vmaddr,virtual_size=vmsize,file_offset=fileoff,file_size=filesize,max_protection=maxprot,initial_protection=initprot,section_count=nsects,flags=segflags)
            if fileoff>reader.size or filesize>reader.size-fileoff:findings.append(_finding("invalid_header","high",.99,fileoff,name,"Segmento Mach-O oltre EOF"))
            else:logical_end=max(logical_end,fileoff+filesize)
            section_size=68 if segment_bits==32 else 80;section_cursor=cursor+(56 if segment_bits==32 else 72)
            if nsects>4096 or section_cursor+nsects*section_size>cursor+size:raise ValueError("Section table Mach-O incoerente")
            for section_index in range(nsects):
                raw=reader.read(section_cursor+section_index*section_size,section_size)
                section_name=raw[:16].split(b"\0",1)[0].decode("ascii","replace");segment_name=raw[16:32].split(b"\0",1)[0].decode("ascii","replace")
                if segment_bits==32:address,length,offset=struct.unpack_from(endian+"III",raw,32)
                else:address,length,offset=struct.unpack_from(endian+"QQI",raw,32)
                valid=offset<=reader.size and length<=reader.size-offset
                item={"index":len(sections),"name":section_name,"segment":segment_name,"offset":offset,"size":length,"virtual_address":address,"permissions":_permissions(initprot),"valid_bounds":valid}
                if valid and length:item["entropy"]=shannon(reader.view(offset,length,1024*1024))
                sections.append(item)
        elif command in (0x21,0x2C):
            findings.append(_finding("encrypted_region","medium",.9,cursor,None,"Load command Mach-O encryption info presente"))
            row["kind"]="encryption_info"
        elif command==0x1D:row["kind"]="code_signature"
        elif command==0x1B:row.update(kind="uuid",uuid=reader.read(cursor+8,16).hex())
        commands.append(row);cursor+=size
    return {"format":"macho","validated":True,"header":{"bits":bits,"endian":"little" if endian=="<" else "big","cpu":CPU.get(cpu,hex(cpu)),"cpu_subtype":subtype,"file_type":file_type,"load_commands":command_count,"commands_size":commands_size,"flags":hex(flags)},"sections":sections,"segments":[row for row in commands if "file_offset" in row],"load_commands":commands,"entry_points":[],"symbols":[],"imports":[],"exports":[],"relocations":[],"findings":findings,"logical_end":min(reader.size,logical_end),"architecture":CPU.get(cpu,hex(cpu)),"bits":bits,"endian":"little" if endian=="<" else "big","executable_regions":[s for s in sections if "X" in s["permissions"] and s["valid_bounds"]]}


def _fat(reader,base,magic):
    endian=">" if magic[:1]==b"\xca" else "<";is64=magic in (b"\xca\xfe\xba\xbf",b"\xbf\xba\xfe\xca")
    count=reader.unpack(endian+"I",base+4)[0]
    if not 1<=count<=128:raise ValueError("Numero slice FAT non plausibile")
    slices=[];cursor=base+8;entry_size=32 if is64 else 20
    for index in range(count):
        vals=reader.unpack(endian+("IIQQII" if is64 else "IIIII"),cursor+index*entry_size)
        cpu,subtype,offset,size,alignment=vals[:5]
        if offset>reader.size or size>reader.size-offset:raise ValueError("Slice Mach-O FAT fuori dai limiti")
        slices.append({"index":index,"cpu":CPU.get(cpu,hex(cpu)),"cpu_subtype":subtype,"offset":offset,"size":size,"alignment_power":alignment})
    ordered=sorted(slices,key=lambda item:item["offset"])
    findings=[]
    for left,right in zip(ordered,ordered[1:]):
        if left["offset"]+left["size"]>right["offset"]:findings.append(_finding("overlapping_slices","high",.99,right["offset"],None,"Slice FAT sovrapposte"))
    return {"format":"macho_fat","validated":True,"header":{"bits":64 if is64 else 32,"endian":"big" if endian==">" else "little","slice_count":count},"sections":[],"segments":slices,"entry_points":[],"symbols":[],"imports":[],"exports":[],"relocations":[],"findings":findings,"logical_end":max(item["offset"]+item["size"] for item in slices),"architecture":"universal","bits":64 if is64 else 32,"endian":"big" if endian==">" else "little","executable_regions":[]}


def _permissions(protection):return ("R" if protection&1 else "")+("W" if protection&2 else "")+("X" if protection&4 else "")
def _finding(kind,severity,confidence,offset,section,explanation):return {"type":kind,"severity":severity,"confidence":confidence,"evidence":[explanation],"offset":offset,"section":section,"explanation":explanation}
