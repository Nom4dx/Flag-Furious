"""Streaming signature registry and structural boundary validators.

A hit is only a candidate. ``validate_candidates`` checks parser invariants and
returns explicit rejected records for random markers. This mirrors binwalk-style
discovery without treating every byte pattern as an embedded file.
"""

from __future__ import annotations

import bz2
import gzip
import io
import json
import lzma
import struct
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree


@dataclass(frozen=True)
class Signature:
    """Describe a binary marker, candidate-relative offset and confidence."""

    format: str
    marker: bytes
    validator: str
    confidence: float
    relative_offset: int = 0


SIGNATURES = (
    Signature("png", b"\x89PNG\r\n\x1a\n", "png", .99), Signature("jpeg", b"\xff\xd8\xff", "jpeg", .98),
    Signature("gif", b"GIF87a", "gif", .98), Signature("gif", b"GIF89a", "gif", .98),
    Signature("bmp", b"BM", "bmp", .82), Signature("tiff", b"II*\x00", "tiff", .98), Signature("tiff", b"MM\x00*", "tiff", .98),
    Signature("pdf", b"%PDF-", "pdf", .98), Signature("zip", b"PK\x03\x04", "zip", .97), Signature("zip", b"PK\x05\x06", "zip", .96),
    Signature("gzip", b"\x1f\x8b\x08", "gzip", .97), Signature("rar", b"Rar!\x1a\x07", "rar", .94), Signature("7z", b"7z\xbc\xaf'\x1c", "7z", .99),
    Signature("tar", b"ustar", "tar", .93, 257), Signature("elf", b"\x7fELF", "elf", .99), Signature("pe", b"MZ", "pe", .78),
    Signature("sqlite", b"SQLite format 3\x00", "sqlite", .99), Signature("riff", b"RIFF", "riff", .96),
    Signature("ogg", b"OggS", "ogg", .98), Signature("flac", b"fLaC", "flac", .99), Signature("mp3", b"ID3", "mp3", .94),
    Signature("isobmff", b"ftyp", "isobmff", .96, 4), Signature("mkv", b"\x1aE\xdf\xa3", "mkv", .96),
    Signature("psd", b"8BPS", "psd", .98), Signature("au", b".snd", "au", .98), Signature("aiff", b"FORM", "aiff", .82),
    Signature("java_class", b"\xca\xfe\xba\xbe", "java", .97), Signature("xml", b"<?xml", "xml", .90),
    Signature("html", b"<!DOCTYPE html", "html", .91), Signature("html", b"<html", "html", .86),
    Signature("script", b"#!/", "script", .91),
)

EXTENSIONS = {
    "png": ".png", "jpeg": ".jpg", "gif": ".gif", "bmp": ".bmp", "tiff": ".tiff", "pdf": ".pdf",
    "zip": ".zip", "gzip": ".gz", "rar": ".rar", "7z": ".7z", "tar": ".tar", "elf": ".elf", "pe": ".exe",
    "sqlite": ".sqlite", "riff": ".riff", "wav": ".wav", "webp": ".webp", "avi": ".avi", "ogg": ".ogg",
    "flac": ".flac", "mp3": ".mp3", "java_class": ".class", "xml": ".xml", "html": ".html", "json": ".json", "script": ".txt",
}


def scan(path: Path, byte_budget: int, max_hits: int = 2048) -> tuple[list[dict], bool]:
    """Scan an input in overlapping blocks and return unvalidated signature hits.

    Reads at most ``byte_budget`` and stores only short context. Marker offsets are
    absolute. ``truncated`` means the physical file or hit limit exceeded the
    scan. Example: ``hits, partial = scan(path, 64 << 20)``.
    """
    overlap = max(len(x.marker) + x.relative_offset for x in SIGNATURES)
    hits, seen, consumed, tail = [], set(), 0, b""
    with path.open("rb") as stream:
        while consumed < byte_budget:
            block = stream.read(min(1024 * 1024, byte_budget - consumed))
            if not block: break
            window, base = tail + block, consumed - len(tail)
            for signature in SIGNATURES:
                cursor = 0
                while True:
                    found = window.find(signature.marker, cursor)
                    if found < 0: break
                    marker_offset = base + found; start = marker_offset - signature.relative_offset
                    key = (signature.format, start)
                    if start >= 0 and key not in seen:
                        seen.add(key); hits.append({
                            "id": f"signature-{len(hits)+1}", "format": signature.format,
                            "offset": start, "marker_offset": marker_offset, "signature": signature.marker.hex(),
                            "context_hex": window[max(0, found-12):found+len(signature.marker)+20].hex(),
                            "validator": signature.validator, "signature_confidence": signature.confidence,
                            "validated": False,
                        })
                        if len(hits) >= max_hits: return sorted(hits, key=lambda x: x["offset"]), True
                    cursor = found + 1
            consumed += len(block); tail = window[-overlap:]
        truncated = stream.read(1) != b""
    # Structured text roots do not always have fixed magic bytes. These are
    # candidates at offset zero and still require their real parser below.
    with path.open("rb") as stream: prefix = stream.read(min(byte_budget, 1024 * 1024))
    stripped = prefix.lstrip(b"\xef\xbb\xbf\x00\t\r\n ")
    for fmt, predicate in (
        ("json", stripped.startswith((b"{", b"["))),
        ("html", stripped[:32].lower().startswith((b"<!doctype html", b"<html"))),
        ("xml", stripped.startswith(b"<?xml")),
        ("svg", stripped[:64].lower().startswith(b"<svg")),
    ):
        if predicate and (fmt, 0) not in seen:
            hits.append({"id": f"signature-{len(hits)+1}", "format": fmt, "offset": 0, "marker_offset": len(prefix)-len(stripped), "signature": stripped[:16].hex(), "context_hex": stripped[:64].hex(), "validator": fmt, "signature_confidence": .82, "validated": False})
    return sorted(hits, key=lambda x: (x["offset"], x["format"])), truncated


def validate_candidates(path: Path, hits: list[dict], file_size: int, byte_budget: int) -> tuple[list[dict], list[dict]]:
    """Validate candidate structures and derive exclusive logical boundaries.

    Each parser is fault-isolated. Output is ``(validated, rejected)``; a rejected
    hit records the reason and cannot be carved as a file. Reads remain within the
    granted range.
    """
    accepted, rejected = [], []
    for hit in hits:
        try:
            end, method, details, confidence = _validate(path, hit, file_size, min(byte_budget - hit["offset"], file_size - hit["offset"]))
            if end <= hit["offset"] or end > min(file_size, byte_budget): raise ValueError("confine fuori dal byte budget")
            accepted.append({"id": hit["id"].replace("signature", "format"), "format": details.pop("normalized_format", hit["format"]), "start_offset": hit["offset"], "end_offset": end, "length": end-hit["offset"], "boundary_method": method, "validated": True, "confidence": confidence, "details": details})
        except (ValueError, OSError, struct.error, zipfile.BadZipFile, tarfile.TarError, zlib.error, EOFError, lzma.LZMAError) as exc:
            rejected.append({**hit, "status": "false_positive", "confidence": min(.35, hit["signature_confidence"]*.35), "rejection_reason": str(exc)})
    unique = {}
    for item in accepted:
        key = (item["format"], item["start_offset"])
        if key not in unique or item["confidence"] > unique[key]["confidence"]: unique[key] = item
    return sorted(unique.values(), key=lambda x: (x["start_offset"], x["end_offset"])), rejected


def _read(path: Path, start: int, length: int) -> bytes:
    """Read a bounded region from immutable evidence."""
    with path.open("rb") as stream: stream.seek(start); return stream.read(max(0, length))


def _validate(path: Path, hit: dict, size: int, cap: int):
    """Dispatch one hit; private to keep every public result normalized."""
    fmt, start = hit["validator"], hit["offset"]
    if cap <= 0: raise ValueError("byte budget esaurito")
    if fmt == "png":
        pos, chunks = start+8, []
        if _read(path, start, 8) != b"\x89PNG\r\n\x1a\n": raise ValueError("signature PNG")
        while pos+12 <= min(size, start+cap):
            head = _read(path, pos, 8); length = struct.unpack(">I", head[:4])[0]; kind = head[4:]
            if length > cap or pos+12+length > size: raise ValueError("chunk PNG fuori limite")
            body = _read(path, pos+4, length+8)
            if zlib.crc32(body[:-4]) & 0xffffffff != struct.unpack(">I", body[-4:])[0]: raise ValueError("CRC PNG errato")
            chunks.append({"type": kind.decode("latin1"), "offset": pos, "length": length, "crc_valid": True}); pos += length+12
            if kind == b"IEND": return pos, "png_chunks_crc_iend", {"chunks": chunks}, .995
        raise ValueError("IEND assente")
    if fmt == "jpeg":
        data = _read(path, start, cap)
        if not data.startswith(b"\xff\xd8"): raise ValueError("SOI assente")
        pos, segments, sos = 2, [], False
        while pos+1 < len(data):
            if data[pos] != 0xff:
                if sos: pos += 1; continue
                raise ValueError("segmento JPEG incoerente")
            while pos < len(data) and data[pos] == 0xff: pos += 1
            if pos >= len(data): break
            marker = data[pos]; pos += 1
            if marker == 0: continue
            if marker == 0xd9: return start+pos, "jpeg_segments_eoi", {"segments": segments}, .98
            if 0xd0 <= marker <= 0xd7 or marker == 1: continue
            if pos+2 > len(data): break
            length = struct.unpack(">H", data[pos:pos+2])[0]
            if length < 2 or pos+length > len(data): raise ValueError("lunghezza JPEG")
            segments.append({"marker": f"FF{marker:02X}", "offset": start+pos-2, "length": length}); sos = sos or marker == 0xda; pos += length
        raise ValueError("EOI assente")
    if fmt == "gif":
        data = _read(path, start, cap)
        if len(data)<14 or data[:6] not in (b"GIF87a", b"GIF89a"): raise ValueError("header GIF")
        end = data.rfind(b";")
        if end < 13: raise ValueError("trailer GIF")
        return start+end+1, "gif_trailer", {}, .89
    if fmt == "bmp":
        head = _read(path, start, 54)
        if len(head)<26 or head[:2]!=b"BM": raise ValueError("header BMP")
        declared = struct.unpack("<I", head[2:6])[0]; pixel = struct.unpack("<I", head[10:14])[0]; dib = struct.unpack("<I", head[14:18])[0]
        if declared < pixel or dib < 12 or declared > cap or start+declared>size: raise ValueError("dimensione BMP")
        return start+declared, "bmp_declared_size", {"pixel_offset": pixel, "dib_size": dib}, .97
    if fmt == "tiff":
        head = _read(path, start, 16); endian = "<" if head[:2]==b"II" else ">" if head[:2]==b"MM" else None
        if not endian or struct.unpack(endian+"H",head[2:4])[0]!=42: raise ValueError("header TIFF")
        ifd = struct.unpack(endian+"I",head[4:8])[0]
        if ifd<8 or ifd>=cap: raise ValueError("IFD TIFF")
        count_raw = _read(path,start+ifd,2)
        if len(count_raw)<2: raise ValueError("IFD troncato")
        count=struct.unpack(endian+"H",count_raw)[0]
        if start+ifd+2+count*12+4>size: raise ValueError("entry TIFF fuori file")
        return min(size,start+cap), "tiff_ifd_structure", {"ifd_offset":ifd,"entries":count,"boundary_exact":False}, .88
    if fmt == "pdf":
        data=_read(path,start,cap)
        if not data.startswith(b"%PDF-") or b" obj" not in data: raise ValueError("struttura PDF")
        eof=data.rfind(b"%%EOF")
        if eof<0: raise ValueError("EOF PDF")
        end=eof+5
        while end<len(data) and data[end] in b"\r\n \t": end+=1
        return start+end,"pdf_last_eof",{"eof_count":data.count(b"%%EOF"),"objects":data.count(b" obj")},.94
    if fmt == "zip":
        data=_read(path,start,cap); cursor=0
        while True:
            pos=data.find(b"PK\x05\x06",cursor)
            if pos<0: raise ValueError("EOCD ZIP assente")
            if pos+22<=len(data):
                fields=struct.unpack("<4s4H2LH",data[pos:pos+22]); entries,cd_size,cd_offset,comment=fields[4],fields[5],fields[6],fields[7]; end=pos+22+comment
                if end<=len(data) and cd_offset+cd_size<=pos and (entries==0 or data[cd_offset:cd_offset+4]==b"PK\x01\x02"):
                    chunk=data[:end]
                    with zipfile.ZipFile(io.BytesIO(chunk)) as archive:
                        infos=archive.infolist(); encrypted=[x.filename for x in infos if x.flag_bits&1]
                        bad=None if encrypted else archive.testzip()
                        if bad: raise ValueError(f"CRC ZIP {bad}")
                        if len(infos)!=entries: raise ValueError("conteggio ZIP")
                    return start+end,"zip_eocd_central_directory",{"entries":entries,"encrypted":encrypted,"members":[{"name":x.filename,"size":x.file_size,"compressed":x.compress_size} for x in infos[:256]]},.99 if not encrypted else .93
            cursor=pos+1
    if fmt == "gzip":
        data=_read(path,start,cap); obj=zlib.decompressobj(31); obj.decompress(data,cap)
        if not obj.eof: raise ValueError("gzip troncato")
        return start+len(data)-len(obj.unused_data),"gzip_crc",{},.97
    if fmt == "7z":
        head=_read(path,start,32)
        if len(head)<32 or zlib.crc32(head[12:32])&0xffffffff!=struct.unpack("<I",head[8:12])[0]: raise ValueError("CRC 7z")
        nxt,nxtlen=struct.unpack("<QQ",head[12:28]); end=start+32+nxt+nxtlen
        if end>min(size,start+cap): raise ValueError("7z fuori file")
        return end,"7z_start_header_crc",{},.98
    if fmt == "tar":
        data=_read(path,start,cap)
        with tarfile.open(fileobj=io.BytesIO(data),mode="r:") as archive: members=archive.getmembers()
        if not members: raise ValueError("TAR vuoto")
        end=max(x.offset_data+((x.size+511)//512)*512 for x in members)+1024
        if end>len(data): raise ValueError("TAR troncato")
        return start+end,"tar_header_checksums",{"entries":len(members)},.96
    if fmt == "riff":
        head=_read(path,start,12)
        if len(head)<12 or head[:4]!=b"RIFF": raise ValueError("RIFF")
        length=struct.unpack("<I",head[4:8])[0]+8; subtype=head[8:12]
        if length<12 or length>cap or start+length>size: raise ValueError("dimensione RIFF")
        normalized={b"WAVE":"wav",b"WEBP":"webp",b"AVI ":"avi"}.get(subtype,"riff")
        return start+length,"riff_declared_size",{"normalized_format":normalized,"subtype":subtype.decode("latin1")},.97
    if fmt == "ogg":
        data=_read(path,start,cap); pos=0; pages=0; eos=False
        while pos+27<=len(data) and data[pos:pos+4]==b"OggS":
            segments=data[pos+26]; table=data[pos+27:pos+27+segments]
            if len(table)!=segments: raise ValueError("lacing OGG")
            length=27+segments+sum(table)
            if pos+length>len(data): raise ValueError("pagina OGG")
            stored=struct.unpack("<I",data[pos+22:pos+26])[0]; page=bytearray(data[pos:pos+length]); page[22:26]=b"\0"*4
            if zlib.crc32(page)&0xffffffff!=stored: raise ValueError("CRC OGG")
            eos=eos or bool(data[pos+5]&4); pos+=length; pages+=1
            if eos: break
        if not pages or not eos: raise ValueError("OGG EOS assente")
        return start+pos,"ogg_page_crc_eos",{"pages":pages},.98
    if fmt == "flac":
        data=_read(path,start,min(cap,4*1024*1024))
        if not data.startswith(b"fLaC"): raise ValueError("FLAC")
        pos=4; blocks=0
        while pos+4<=len(data):
            last=bool(data[pos]&0x80); length=int.from_bytes(data[pos+1:pos+4],"big"); pos+=4
            if pos+length>len(data): raise ValueError("metadata FLAC")
            pos+=length; blocks+=1
            if last: break
        if not blocks or not last: raise ValueError("ultimo metadata block FLAC")
        return min(size,start+cap),"flac_metadata_blocks",{"metadata_blocks":blocks,"boundary_exact":False},.89
    if fmt == "mp3":
        data=_read(path,start,min(cap,1024*1024)); pos=10+int.from_bytes(bytes((b&0x7f for b in data[6:10])),"big") if data.startswith(b"ID3") and len(data)>=10 else 0
        sync=next((i for i in range(pos,max(pos,len(data)-1)) if data[i]==0xff and data[i+1]&0xe0==0xe0),-1)
        if sync<0: raise ValueError("frame MP3 assente")
        return min(size,start+cap),"mp3_id3_and_frame_sync",{"first_frame":start+sync,"boundary_exact":False},.86
    if fmt == "isobmff":
        data=_read(path,start,cap);pos=0;boxes=[]
        while pos+8<=len(data):
            length=struct.unpack(">I",data[pos:pos+4])[0];kind=data[pos+4:pos+8]
            header=8
            if length==1:
                if pos+16>len(data):raise ValueError("box ISO BMFF esteso")
                length=struct.unpack(">Q",data[pos+8:pos+16])[0];header=16
            elif length==0:length=len(data)-pos
            if length<header or pos+length>len(data):raise ValueError("dimensione box ISO BMFF")
            boxes.append({"type":kind.decode("latin1"),"offset":start+pos,"length":length});pos+=length
            if length==0:break
        if not boxes or boxes[0]["type"]!="ftyp":raise ValueError("ftyp non iniziale")
        brand=data[8:12]
        normalized="avif" if brand in {b"avif",b"avis"} else "heic" if brand in {b"heic",b"heix",b"hevc",b"hevx",b"mif1"} else "m4a" if brand in {b"M4A ",b"M4B ",b"isom"} and any(x["type"]=="moov" for x in boxes) else "mp4"
        return start+pos,"isobmff_box_sizes",{"normalized_format":normalized,"major_brand":brand.decode("latin1"),"boxes":boxes},.94
    if fmt == "mkv":
        head=_read(path,start,min(cap,4096))
        if len(head)<8 or not head.startswith(b"\x1aE\xdf\xa3"):raise ValueError("EBML header")
        if b"matroska" not in head.lower() and b"webm" not in head.lower():raise ValueError("DocType EBML non riconosciuto")
        normalized="webm" if b"webm" in head.lower() else "mkv"
        return min(size,start+cap),"ebml_header_doctype",{"normalized_format":normalized,"boundary_exact":False},.88
    if fmt == "psd":
        head=_read(path,start,26)
        if len(head)<26 or head[:4]!=b"8BPS" or struct.unpack(">H",head[4:6])[0] not in (1,2):raise ValueError("PSD header")
        channels,height,width,depth,mode=struct.unpack(">HIIHH",head[12:26])
        if not (1<=channels<=56 and width and height and depth in {1,8,16,32}):raise ValueError("PSD dimensions")
        return min(size,start+cap),"psd_header_dimensions",{"channels":channels,"width":width,"height":height,"depth":depth,"color_mode":mode,"boundary_exact":False},.9
    if fmt == "au":
        head=_read(path,start,24)
        if len(head)<24 or head[:4]!=b".snd":raise ValueError("AU header")
        offset,length,encoding,rate,channels=struct.unpack(">5I",head[4:24]);end=size if length==0xffffffff else start+offset+length
        if offset<24 or end>min(size,start+cap) or not rate or not channels:raise ValueError("AU fields")
        return end,"au_declared_data_size",{"encoding":encoding,"sample_rate":rate,"channels":channels},.96
    if fmt == "aiff":
        head=_read(path,start,12)
        if len(head)<12 or head[:4]!=b"FORM" or head[8:12] not in {b"AIFF",b"AIFC"}:raise ValueError("AIFF FORM")
        length=struct.unpack(">I",head[4:8])[0]+8
        if length>cap or start+length>size:raise ValueError("AIFF size")
        return start+length,"aiff_form_size",{"normalized_format":"aiff"},.96
    if fmt == "elf":
        head=_read(path,start,64)
        if len(head)<52 or head[:4]!=b"\x7fELF" or head[4] not in (1,2) or head[5] not in (1,2): raise ValueError("ELF header")
        return min(size,start+cap),"elf_header",{"class":32 if head[4]==1 else 64,"boundary_exact":False},.88
    if fmt == "pe":
        head=_read(path,start,min(cap,4096))
        if len(head)<64 or head[:2]!=b"MZ": raise ValueError("MZ")
        pe=struct.unpack("<I",head[60:64])[0]
        if pe+24>len(head) or head[pe:pe+4]!=b"PE\0\0": raise ValueError("PE signature")
        return min(size,start+cap),"pe_coff_header",{"pe_offset":pe,"boundary_exact":False},.91
    if fmt == "sqlite":
        head=_read(path,start,100)
        if len(head)<100: raise ValueError("SQLite header")
        page=struct.unpack(">H",head[16:18])[0] or 65536; pages=struct.unpack(">I",head[28:32])[0]; length=pages*page if pages else size-start
        if page<512 or page>65536 or page&(page-1) or length>cap: raise ValueError("SQLite pages")
        return start+length,"sqlite_pages",{"page_size":page,"pages":pages},.96
    if fmt == "java":
        head=_read(path,start,10)
        if len(head)<10 or struct.unpack(">H",head[6:8])[0] not in range(45,101): raise ValueError("Java class")
        return min(size,start+cap),"java_header_version",{"boundary_exact":False},.79
    if fmt == "xml":
        data=_read(path,start,cap); root=ElementTree.fromstring(data)
        return start+len(data),"xml_parser",{"root":root.tag},.94
    if fmt == "html":
        data=_read(path,start,cap); lower=data.lower(); end=lower.rfind(b"</html>")
        if end<0: raise ValueError("HTML envelope")
        return start+end+7,"html_envelope",{"active_content":b"<script" in lower},.90
    if fmt == "svg":
        data=_read(path,start,cap);lower=data.lower();end=lower.rfind(b"</svg>")
        if end<0:raise ValueError("SVG envelope")
        ElementTree.fromstring(data[:end+6])
        return start+end+6,"svg_xml_parser",{"active_content":b"<script" in lower or b"javascript:" in lower},.94
    if fmt == "json":
        data=_read(path,start,cap); value=json.loads(data.decode("utf-8-sig"))
        return start+len(data),"json_parser",{"root_type":type(value).__name__},.96
    if fmt == "script":
        data=_read(path,start,cap)
        if not data.startswith(b"#!/") or b"\0" in data[:4096]: raise ValueError("script")
        markers=[p for marker in (b"PK\x03\x04",b"\x1f\x8b\x08") if (p:=data.find(marker,1))>0]; end=min(markers) if markers else len(data)
        return start+end,"script_text_prefix",{"executed":False},.88
    if fmt == "rar":
        head=_read(path,start,16)
        if not head.startswith(b"Rar!\x1a\x07") or len(head)<14: raise ValueError("RAR header")
        return min(size,start+cap),"rar_signature_block",{"boundary_exact":False},.72
    raise ValueError("validator non disponibile")


def suffix_for(format_name: str) -> str:
    """Return a safe controlled extension for carved validated ranges."""
    return EXTENSIONS.get(format_name, ".bin")
