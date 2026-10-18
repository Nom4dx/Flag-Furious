"""Optional Capstone disassembly restricted to parser-validated executable ranges.

No raw whole-file disassembly is attempted. At most 4 MiB and 20,000 instructions
are decoded. Missing Capstone returns an explicit warning and empty code graph.
"""

from pathlib import Path
import re
import time


def disassemble(path:Path,regions:list[dict],architecture:str,bits:int,endian:str,max_instructions:int=20000,byte_budget:int|None=None)->tuple[list[dict],list[str]]:
    """Decode validated executable sections and return normalized instructions."""
    try:
        import capstone
    except ImportError:return [],["Capstone non disponibile: disassemblaggio statico saltato"]
    mapping=_mapping(capstone,architecture,bits,endian)
    if not mapping:return [],[f"Architettura Capstone non supportata: {architecture}"]
    engine=capstone.Cs(*mapping);engine.detail=False;rows=[];warnings=[]
    remaining=4*1024*1024;deadline=time.monotonic()+10
    if len(regions)>128:warnings.append("Regioni eseguibili oltre le prime 128 omesse")
    with path.open("rb") as source:
        for region in regions[:128]:
            offset=int(region.get("offset",0))
            available=max(0,(byte_budget-offset) if byte_budget is not None else int(region.get("size",region.get("file_size",0))))
            declared=int(region.get("size",region.get("file_size",0)))
            length=min(declared,available,remaining)
            if length<declared:warnings.append("Disassemblaggio limitato al byte budget cumulativo di 4 MiB")
            if length<=0:continue
            source.seek(offset);data=source.read(length);remaining-=len(data);base=int(region.get("virtual_address",offset))
            for ins in engine.disasm(data,base):
                group="call" if ins.mnemonic.startswith(("call","bl","jal")) else "jump" if ins.mnemonic.startswith(("j","b")) else "return" if ins.mnemonic.startswith(("ret","bx lr")) else None
                target=None
                if group in {"call","jump"}:
                    match=re.search(r"(?:0x)?([0-9a-fA-F]+)$",ins.op_str.strip())
                    if match:
                        try:target=int(match.group(1),16)
                        except ValueError:pass
                rows.append({"offset":region["offset"]+(ins.address-base),"address":ins.address,"opcode":bytes(ins.bytes).hex(),"mnemonic":ins.mnemonic,"operands":ins.op_str,"section":region.get("name"),"group":group,"target":target})
                if len(rows)>=max_instructions:return rows,warnings+["Disassemblaggio limitato al numero massimo di istruzioni"]
                if len(rows)%1024==0 and time.monotonic()>=deadline:return rows,warnings+["Disassemblaggio interrotto al limite di 10 secondi"]
            if remaining<=0:
                if len(regions)>1:warnings.append("Ulteriori regioni eseguibili omesse dal budget di disassemblaggio")
                break
    return rows,warnings


def _mapping(capstone,architecture,bits,endian):
    value=str(architecture).casefold();end=capstone.CS_MODE_BIG_ENDIAN if endian=="big" else capstone.CS_MODE_LITTLE_ENDIAN
    if value in {"x86","x86_64"}:return capstone.CS_ARCH_X86,capstone.CS_MODE_64 if bits==64 else capstone.CS_MODE_32
    if value in {"arm","aarch64","arm64"}:return (capstone.CS_ARCH_ARM64, end) if value in {"aarch64","arm64"} else (capstone.CS_ARCH_ARM,capstone.CS_MODE_ARM|end)
    if "mips" in value:return capstone.CS_ARCH_MIPS,(capstone.CS_MODE_MIPS64 if bits==64 else capstone.CS_MODE_MIPS32)|end
    if "powerpc" in value:return capstone.CS_ARCH_PPC,(capstone.CS_MODE_64 if bits==64 else capstone.CS_MODE_32)|end
    if "sparc" in value:return capstone.CS_ARCH_SPARC,(capstone.CS_MODE_V9 if bits==64 else 0)|end
    if "risc-v" in value and hasattr(capstone,"CS_ARCH_RISCV"):return capstone.CS_ARCH_RISCV,capstone.CS_MODE_RISCV64 if bits==64 else capstone.CS_MODE_RISCV32
    return None
