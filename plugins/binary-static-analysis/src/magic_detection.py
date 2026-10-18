"""Streaming signature inventory and structural boundary validation.

Scanning proposes candidates across arbitrary offsets. ``validate`` then applies
format-specific bounds, checksums or parser constraints. A candidate rejected by
validation remains visible but is never carved or called a present format.
"""

from io import BytesIO
from pathlib import Path
import bz2
import gzip
import lzma
import struct
import zipfile
import zlib

from .format_registry import MAX_SIGNATURE, SIGNATURES
from .firmware_analyzer import analyze as analyze_firmware
from .filesystem_analyzer import analyze as analyze_filesystem
from .uefi_analyzer import analyze as analyze_uefi


def scan(path:Path,limit:int,max_results:int=4096)->tuple[list[dict],bool]:
    """Scan a bounded file view in blocks while preserving boundary overlap."""
    found=[];seen=set();consumed=0;tail=b""
    with path.open("rb") as source:
        while consumed<limit:
            block=source.read(min(1024*1024,limit-consumed))
            if not block:break
            window=tail+block;base=consumed-len(tail)
            for signature in SIGNATURES:
                cursor=0
                while True:
                    pos=window.find(signature.value,cursor)
                    if pos<0:break
                    offset=base+pos-signature.relative_offset;key=(signature.name,offset)
                    if offset>=0 and key not in seen:
                        seen.add(key);context=window[max(0,pos-12):min(len(window),pos+len(signature.value)+20)]
                        found.append({"id":f"signature-{len(found)+1}","format":signature.name,"offset":offset,"marker_offset":base+pos,"signature":signature.value.hex(),"validator":signature.validator,"context_hex":context.hex(),"validated":False,"confidence":.34,"classification":"signature_found"})
                        if len(found)>=max_results:return sorted(found,key=lambda item:(item["offset"],item["format"])),True
                    cursor=pos+1
            consumed+=len(block);tail=window[-MAX_SIGNATURE:]
        truncated=source.read(1)!=b""
    # Standalone COFF has no stable magic; only a strict offset-zero heuristic is proposed.
    with path.open("rb") as source:head=source.read(4096)
    if len(head)>=20:
        machine,count=struct.unpack_from("<HH",head)
        if machine in {0x14c,0x8664,0x1c0,0xaa64,0x1f0} and 1<=count<=512:
            found.append({"id":f"signature-{len(found)+1}","format":"coff","offset":0,"marker_offset":0,"signature":head[:4].hex(),"validator":"coff","context_hex":head.hex(),"validated":False,"confidence":.28,"classification":"header_candidate"})
    if head.startswith(b":"):
        found.append({"id":f"signature-{len(found)+1}","format":"intel_hex","offset":0,"marker_offset":0,"signature":"3a","validator":"intel_hex","context_hex":head[:64].hex(),"validated":False,"confidence":.3,"classification":"header_candidate"})
    if len(head)>=4 and head[:1]==b"S" and head[1:2] in b"0123456789":
        found.append({"id":f"signature-{len(found)+1}","format":"motorola_s_record","offset":0,"marker_offset":0,"signature":head[:2].hex(),"validator":"s_record","context_hex":head[:64].hex(),"validated":False,"confidence":.3,"classification":"header_candidate"})
    return sorted(found,key=lambda item:(item["offset"],item["format"])),truncated


def validate(path:Path,candidates:list[dict],limit:int)->tuple[list[dict],list[dict]]:
    """Validate candidate structure and exact/logical boundaries independently."""
    valid=[];rejected=[]
    for candidate in candidates:
        if candidate["offset"]>=limit:
            rejected.append({**candidate,"reason":"offset oltre byte budget"});continue
        try:
            result=_validator(path,candidate,limit)
            if not result.get("validated"):raise ValueError("controllo strutturale non superato")
            if result.get("start_offset", -1) < 0 or result.get("end_offset", limit + 1) > limit:
                raise ValueError("struttura oltre il byte budget")
            valid.append({**candidate,**result,"classification":"structure_validated"})
        except (OSError,ValueError,EOFError,struct.error,zipfile.BadZipFile,zlib.error,lzma.LZMAError) as exc:
            rejected.append({**candidate,"reason":str(exc),"classification":"signature_rejected"})
    # Keep one equivalent structural range; preserve the strongest interpretation.
    unique={}
    for item in valid:
        key=(item["format"],item["start_offset"],item["end_offset"])
        if key not in unique or item["confidence"]>unique[key]["confidence"]:unique[key]=item
    return sorted(unique.values(),key=lambda item:(item["start_offset"],item["end_offset"])),rejected


def _validator(path,candidate,limit):
    kind=candidate["validator"];offset=candidate["offset"];size=min(path.stat().st_size,limit)
    with path.open("rb") as source:source.seek(offset);data=source.read(min(size-offset,64*1024*1024))
    if kind in {"uboot","fdt","android_boot","android_vendor","trx"}:return analyze_firmware(path,candidate)
    if kind=="uefi":return analyze_uefi(path,offset)
    if kind in {"squashfs","cramfs","ubi","ubifs","erofs","iso9660","ext","ntfs","fat","hfs","apfs"}:return analyze_filesystem(path,candidate)
    if kind=="elf":
        if len(data)<52 or data[:4]!=b"\x7fELF" or data[4] not in (1,2) or data[5] not in (1,2):raise ValueError("Header ELF non valido")
        endian="little" if data[5]==1 else "big";header_size=int.from_bytes(data[40:42] if data[4]==1 else data[52:54],endian)
        if header_size not in range(52,4097):raise ValueError("Dimensione header ELF non plausibile")
        return _range(candidate,offset,size,.92,{"header_size":header_size})
    if kind=="pe":
        if len(data)<64:raise ValueError("DOS header troncato")
        pe=int.from_bytes(data[0x3c:0x40],"little")
        if pe+4>len(data):raise ValueError("Header referenziato fuori dai limiti")
        signature=data[pe:pe+4]
        if signature==b"PE\0\0":return _range(candidate,offset,size,.94,{"executable_variant":"PE","pe_header_offset":pe})
        if signature[:2] in (b"NE",b"LE",b"LX"):
            result=_range(candidate,offset,size,.82,{"executable_variant":signature[:2].decode("ascii"),"header_offset":pe,"boundary":"physical_eof_fallback"})
            result["format"]={b"NE":"new_executable",b"LE":"linear_executable",b"LX":"linear_executable_lx"}[signature[:2]]
            return result
        raise ValueError("Firma PE/NE/LE/LX referenziata non valida")
    if kind=="macho":return _macho(candidate,data,size)
    if kind=="java":
        if len(data)<10 or data[:4]!=b"\xca\xfe\xba\xbe":raise ValueError("Class header troncato")
        major=int.from_bytes(data[6:8],"big");constant_pool=int.from_bytes(data[8:10],"big")
        if not 45<=major<=100 or not 1<=constant_pool<=65535:raise ValueError("Versione Java/constant pool non plausibili")
        return _range(candidate,offset,size,.9,{"major_version":major,"constant_pool_count":constant_pool})
    if kind=="wasm":
        if len(data)<8 or data[:8]!=b"\x00asm\x01\x00\x00\x00":raise ValueError("Header WebAssembly non valido")
        return _range(candidate,offset,size,.95,{"version":1})
    if kind=="png":return _png(candidate,data,size)
    if kind=="jpeg":
        end=data.find(b"\xff\xd9",2)
        if end<2:raise ValueError("EOI JPEG assente")
        return _range(candidate,offset,offset+end+2,.97,{"eoi_offset":offset+end})
    if kind=="gif":
        if len(data)<14 or data[:6] not in (b"GIF87a",b"GIF89a"):raise ValueError("Header GIF non valido")
        end=data.rfind(b"\x3b")
        if end<13:raise ValueError("Trailer GIF assente")
        return _range(candidate,offset,offset+end+1,.9,{"version":data[3:6].decode("ascii"),"trailer_offset":offset+end})
    if kind=="bmp":
        if len(data)<54 or data[:2]!=b"BM":raise ValueError("Header BMP troncato")
        declared=int.from_bytes(data[2:6],"little");pixels=int.from_bytes(data[10:14],"little");dib=int.from_bytes(data[14:18],"little")
        if declared<54 or declared>len(data) or pixels>=declared or dib not in (12,16,40,52,56,64,108,124):raise ValueError("Dimensioni BMP incoerenti")
        return _range(candidate,offset,offset+declared,.97,{"pixel_offset":offset+pixels,"dib_size":dib})
    if kind=="tiff":
        endian="little" if data[:2]==b"II" else "big";ifd=int.from_bytes(data[4:8],endian)
        if len(data)<8 or ifd<8 or ifd+2>len(data):raise ValueError("IFD TIFF fuori dai limiti")
        count=int.from_bytes(data[ifd:ifd+2],endian)
        if count>4096 or ifd+2+count*12+4>len(data):raise ValueError("Tabella IFD TIFF incoerente")
        return _range(candidate,offset,size,.86,{"endian":endian,"first_ifd":offset+ifd,"entries":count,"boundary":"physical_eof_fallback"})
    if kind=="pdf":
        end=data.rfind(b"%%EOF")
        if end<0:raise ValueError("EOF PDF assente")
        cursor=end+5
        while cursor<len(data) and data[cursor] in b"\r\n \t":cursor+=1
        return _range(candidate,offset,offset+cursor,.91,{"eof_offset":offset+end,"multiple_eof":data.count(b"%%EOF")})
    if kind=="riff":
        if len(data)<12 or data[:4]!=b"RIFF":raise ValueError("RIFF troncato")
        length=int.from_bytes(data[4:8],"little")+8
        if length<12 or offset+length>size:raise ValueError("Dimensione RIFF incoerente")
        return _range(candidate,offset,offset+length,.98,{"form_type":data[8:12].decode("ascii","replace")})
    if kind=="zip":return _zip(candidate,data,size)
    if kind in {"gzip","xz","bzip2"}:return _compressed(candidate,data,size,kind)
    if kind in {"7z","rar"}:
        minimum=32 if kind=="7z" else 16
        if len(data)<minimum:raise ValueError("Contenitore troncato")
        return _range(candidate,offset,size,.72,{"boundary":"physical_eof_fallback"})
    if kind in {"zstd","lz4"}:
        if len(data)<8:raise ValueError("Frame compresso troncato")
        return _range(candidate,offset,size,.68,{"boundary":"physical_eof_fallback"})
    if kind=="sqlite":
        page=int.from_bytes(data[16:18],"big");page=65536 if page==1 else page
        pages=int.from_bytes(data[28:32],"big")
        if page not in (512,1024,2048,4096,8192,16384,32768,65536):raise ValueError("Page size SQLite non valida")
        end=offset+(pages*page if pages and pages*page<=len(data) else len(data))
        return _range(candidate,offset,end,.96,{"page_size":page,"pages":pages})
    if kind in {"ole","pcap","pcapng"}:
        if len(data)<24:raise ValueError("Header contenitore troncato")
        return _range(candidate,offset,size,.78,{"boundary":"physical_eof_fallback"})
    if kind=="tar":return _tar(candidate,data,size)
    if kind=="cpio":return _cpio(candidate,data,size)
    if kind=="coff":
        from .coff_analyzer import analyze as analyze_coff
        parsed=analyze_coff(path,limit);return _range(candidate,0,parsed["logical_end"],.9,{"machine":parsed["architecture"]})
    if kind in {"intel_hex","s_record"}:
        return _text_firmware(candidate,data,size,kind)
    raise ValueError("Validator non disponibile")


def _range(candidate,start,end,confidence,header):
    if end<=start:raise ValueError("Confine logico non valido")
    return {"validated":True,"format":candidate["format"],"start_offset":start,"end_offset":end,"length":end-start,"confidence":confidence,"boundary_method":"internal_structure","header":header}


def _png(candidate,data,size):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):raise ValueError("PNG magic assente")
    cursor=8;chunks=0
    while cursor+12<=len(data) and chunks<100000:
        length=int.from_bytes(data[cursor:cursor+4],"big");kind=data[cursor+4:cursor+8];end=cursor+12+length
        if end>len(data):raise ValueError("Chunk PNG oltre i limiti")
        expected=int.from_bytes(data[cursor+8+length:end],"big")
        if zlib.crc32(data[cursor+4:cursor+8+length])&0xffffffff!=expected:raise ValueError("CRC PNG non valido")
        chunks+=1;cursor=end
        if kind==b"IEND":return _range(candidate,candidate["offset"],candidate["offset"]+cursor,.99,{"chunks":chunks,"crc_valid":True})
    raise ValueError("IEND PNG assente")


def _zip(candidate,data,size):
    eocd=data.rfind(b"PK\x05\x06")
    if eocd<0 or eocd+22>len(data):raise ValueError("EOCD ZIP assente")
    comment=int.from_bytes(data[eocd+20:eocd+22],"little");end=eocd+22+comment
    if end>len(data):raise ValueError("Commento ZIP oltre EOF")
    archive=data[:end]
    with zipfile.ZipFile(BytesIO(archive)) as zipped:
        members=zipped.infolist()
        if len(members)>100000:raise ValueError("Troppe entry ZIP")
        encrypted=any(member.flag_bits&1 for member in members);checked=0
        for member in members:
            if member.header_offset<0 or member.header_offset>=end:raise ValueError("Offset entry ZIP fuori archivio")
            if member.flag_bits&1 or member.is_dir() or member.file_size>8*1024*1024:continue
            if checked+member.file_size>32*1024*1024:break
            with zipped.open(member) as source:
                while source.read(65536):pass
            checked+=member.file_size
    return _range(candidate,candidate["offset"],candidate["offset"]+end,.99 if checked or not members else .96,{"entries":len(members),"eocd_offset":candidate["offset"]+eocd,"crc_bytes_checked":checked,"encrypted":encrypted})


def _compressed(candidate,data,size,kind):
    if kind=="gzip":
        obj=zlib.decompressobj(16+zlib.MAX_WBITS);obj.decompress(data,32*1024*1024);consumed=len(data)-len(obj.unused_data)
    elif kind=="xz":
        obj=lzma.LZMADecompressor();obj.decompress(data,max_length=32*1024*1024)
        if not obj.eof:raise ValueError("Stream XZ oltre il limite di decompressione")
        consumed=len(data)-len(obj.unused_data)
    else:
        obj=bz2.BZ2Decompressor();obj.decompress(data,max_length=32*1024*1024)
        if not obj.eof:raise ValueError("Stream BZIP2 oltre il limite di decompressione")
        consumed=len(data)-len(obj.unused_data)
    if kind=="gzip" and not obj.eof:raise ValueError("Stream GZIP oltre il limite di decompressione")
    if consumed<=0:raise ValueError("Stream compresso non decodificabile")
    return _range(candidate,candidate["offset"],candidate["offset"]+consumed,.94,{"decoder":kind,"boundary":"decoder_consumed_bytes"})


def _macho(candidate,data,size):
    if len(data)<8:raise ValueError("Mach-O troncato")
    magic=data[:4]
    if magic in (b"\xca\xfe\xba\xbe",b"\xca\xfe\xba\xbf"):
        count=int.from_bytes(data[4:8],"big")
        if not 1<=count<=128:raise ValueError("Slice FAT non plausibili")
        return _range(candidate,candidate["offset"],size,.87,{"slices":count})
    endian="little" if magic in (b"\xce\xfa\xed\xfe",b"\xcf\xfa\xed\xfe") else "big";count=int.from_bytes(data[16:20],endian);commands=int.from_bytes(data[20:24],endian);header=32 if magic in (b"\xfe\xed\xfa\xcf",b"\xcf\xfa\xed\xfe") else 28
    if count>8192 or header+commands>len(data):raise ValueError("Load commands Mach-O incoerenti")
    return _range(candidate,candidate["offset"],size,.9,{"load_commands":count,"commands_size":commands})


def _tar(candidate,data,size):
    if len(data)<512 or data[257:262]!=b"ustar":raise ValueError("Header TAR assente")
    stored=data[148:156].strip(b"\0 ");checksum=int(stored or b"0",8);block=bytearray(data[:512]);block[148:156]=b" "*8
    if sum(block)!=checksum:raise ValueError("Checksum TAR non valido")
    cursor=0
    while cursor+512<=len(data):
        header=data[cursor:cursor+512]
        if header==b"\0"*512:return _range(candidate,candidate["offset"],candidate["offset"]+cursor+512,.96,{"checksum_valid":True})
        length=int(header[124:136].strip(b"\0 ") or b"0",8);cursor+=512+((length+511)//512)*512
    raise ValueError("Fine TAR non trovata")


def _cpio(candidate,data,size):
    cursor=0
    while cursor+110<=len(data):
        if data[cursor:cursor+6] not in (b"070701",b"070702"):raise ValueError("Entry CPIO non valida")
        namesize=int(data[cursor+94:cursor+102],16);filesize=int(data[cursor+54:cursor+62],16);name_start=cursor+110;name_end=name_start+namesize
        if name_end>len(data):raise ValueError("Nome CPIO troncato")
        name=data[name_start:name_end].rstrip(b"\0");data_start=(name_end+3)&~3;data_end=data_start+filesize
        if data_end>len(data):raise ValueError("Payload CPIO troncato")
        cursor=(data_end+3)&~3
        if name==b"TRAILER!!!":return _range(candidate,candidate["offset"],candidate["offset"]+cursor,.96,{"trailer":True})
    raise ValueError("Trailer CPIO assente")


def _text_firmware(candidate,data,size,kind):
    """Validate checksums for bounded Intel HEX or Motorola S-record lines."""
    lines=[line.strip() for line in data.splitlines() if line.strip()]
    if not lines or len(lines)>1_000_000:raise ValueError("Nessun record firmware valido")
    checked=0
    for line in lines:
        try:
            if kind=="intel_hex":
                if not line.startswith(b":"):raise ValueError
                raw=bytes.fromhex(line[1:].decode("ascii"))
                if len(raw)<5 or raw[0]+5!=len(raw) or sum(raw)&0xff:raise ValueError
            else:
                if len(line)<4 or line[:1]!=b"S":raise ValueError
                raw=bytes.fromhex(line[2:].decode("ascii"))
                if len(raw)<2 or raw[0]+1!=len(raw) or sum(raw)&0xff!=0xff:raise ValueError
            checked+=1
        except (ValueError,UnicodeError):raise ValueError(f"Checksum record {kind} non valido")
    return _range(candidate,0,size,.98,{"records":checked,"checksums_valid":True})
