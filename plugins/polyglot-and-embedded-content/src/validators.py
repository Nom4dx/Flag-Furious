"""Bounded structural validators and logical boundary calculations.

Validators never execute content.  Each returns an exclusive end offset and a
method explaining the proof.  A marker with an incoherent structure is rejected,
which keeps carving and flag ranking from treating random bytes as a real file.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import struct
import tarfile
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path


class ValidationError(ValueError):
    """Signal an invalid or unsupported candidate without aborting the plugin."""


def _read(path: Path, offset: int, length: int) -> bytes:
    """Read an exact bounded region in read-only mode; short reads are allowed."""
    with path.open("rb") as stream:
        stream.seek(offset)
        return stream.read(max(0, length))


def _result(candidate: dict, end: int, method: str, confidence: float, details: dict | None = None) -> dict:
    """Create the common validated-format record with an exclusive boundary."""
    start = candidate["offset"]
    if end <= start:
        raise ValidationError("confine logico non coerente")
    return {
        "id": candidate["id"].replace("candidate", "format"),
        "format": candidate["format"],
        "start_offset": start,
        "end_offset": end,
        "length": end - start,
        "boundary_method": method,
        "validated": True,
        "confidence": round(min(1.0, confidence), 3),
        "validator": candidate["validator"],
        "details": details or {},
    }


def validate_candidate(path: Path, candidate: dict, file_size: int, max_span: int) -> dict:
    """Dispatch a candidate to its declared validator.

    Inputs are a path, candidate, physical size and per-object span. Output is a
    normalized boundary. ``ValidationError`` means the marker was not structural
    proof. Limits cap parsing; all access is passive. Example: validate a PNG
    candidate returned by ``scan_signatures``.
    """
    function = globals().get(candidate.get("validator", ""))
    if not callable(function):
        raise ValidationError("validator non disponibile")
    return function(path, candidate, file_size, max_span)


def validate_png(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate PNG chunks, lengths and CRC through IEND; rejects broken CRC."""
    start, pos = c["offset"], c["offset"] + 8
    if _read(path, start, 8) != b"\x89PNG\r\n\x1a\n":
        raise ValidationError("signature PNG non valida")
    chunks, saw_ihdr = [], False
    while pos + 12 <= size and pos - start <= cap:
        head = _read(path, pos, 8)
        length = struct.unpack(">I", head[:4])[0]
        kind = head[4:8]
        if length > cap or pos + 12 + length > size:
            raise ValidationError("lunghezza chunk PNG fuori limite")
        body_crc = _read(path, pos + 4, 4 + length + 4)
        expected = struct.unpack(">I", body_crc[-4:])[0]
        actual = zlib.crc32(body_crc[:-4]) & 0xFFFFFFFF
        if actual != expected:
            raise ValidationError(f"CRC PNG errato nel chunk {kind.decode('latin1')}")
        chunks.append({"type": kind.decode("latin1"), "offset": pos, "length": length, "crc_valid": True})
        if not chunks or (len(chunks) == 1 and kind != b"IHDR"):
            raise ValidationError("IHDR non è il primo chunk")
        saw_ihdr = saw_ihdr or kind == b"IHDR"
        pos += 12 + length
        if kind == b"IEND":
            if length != 0 or not saw_ihdr:
                raise ValidationError("IEND/IHDR non coerenti")
            return _result(c, pos, "png_iend_and_crc", .995, {"chunks": chunks})
    raise ValidationError("IEND PNG non trovato entro i limiti")


def validate_jpeg(path: Path, c: dict, size: int, cap: int) -> dict:
    """Parse JPEG marker segments and entropy data until a non-stuffed EOI."""
    start = c["offset"]
    data = _read(path, start, min(cap, size - start))
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        raise ValidationError("SOI JPEG assente")
    pos, segments, saw_sos = 2, [], False
    while pos < len(data) - 1:
        if data[pos] != 0xFF:
            if not saw_sos:
                raise ValidationError("byte fuori segmento JPEG")
            pos += 1
            continue
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            break
        marker = data[pos]
        pos += 1
        if marker == 0x00:
            continue
        if marker == 0xD9:
            return _result(c, start + pos, "jpeg_eoi_after_segments", .98, {"segments": segments, "scan": saw_sos})
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:
            continue
        if pos + 2 > len(data):
            break
        length = struct.unpack(">H", data[pos:pos + 2])[0]
        if length < 2 or pos + length > len(data):
            raise ValidationError("segmento JPEG sovradimensionato")
        segments.append({"marker": f"FF{marker:02X}", "offset": start + pos - 2, "length": length})
        saw_sos = saw_sos or marker == 0xDA
        pos += length
    raise ValidationError("EOI JPEG non trovato")


def validate_gif(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate GIF header, logical screen dimensions and trailer boundary."""
    start = c["offset"]
    data = _read(path, start, min(cap, size - start))
    if len(data) < 14 or data[:6] not in (b"GIF87a", b"GIF89a"):
        raise ValidationError("header GIF non valido")
    width, height = struct.unpack("<HH", data[6:10])
    if not width or not height:
        raise ValidationError("dimensioni GIF nulle")
    trailer = data.rfind(b";")
    if trailer < 13:
        raise ValidationError("trailer GIF assente")
    return _result(c, start + trailer + 1, "gif_trailer", .90, {"width": width, "height": height})


def validate_riff(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate RIFF declared length and identify WAVE or WebP subtype."""
    start = c["offset"]
    head = _read(path, start, 12)
    if len(head) != 12 or head[:4] != b"RIFF":
        raise ValidationError("header RIFF assente")
    declared = struct.unpack("<I", head[4:8])[0] + 8
    if declared < 12 or declared > cap or start + declared > size:
        raise ValidationError("dimensione RIFF incoerente")
    subtype = head[8:12].decode("latin1")
    if subtype not in {"WAVE", "WEBP", "AVI "}:
        raise ValidationError("sottotipo RIFF sconosciuto")
    out = dict(c)
    out["format"] = "wav" if subtype == "WAVE" else "webp" if subtype == "WEBP" else "riff"
    return _result(out, start + declared, "riff_declared_size", .97, {"subtype": subtype})


def _find_zip_eocd(path: Path, start: int, size: int, cap: int) -> tuple[int, dict]:
    """Locate a coherent ZIP EOCD and central directory relative to archive start."""
    data = _read(path, start, min(cap, size - start))
    cursor = 0
    while True:
        pos = data.find(b"PK\x05\x06", cursor)
        if pos < 0:
            break
        if pos + 22 <= len(data):
            fields = struct.unpack("<4s4H2LH", data[pos:pos + 22])
            entries, cd_size, cd_offset, comment = fields[4], fields[5], fields[6], fields[7]
            end = pos + 22 + comment
            cd_abs = cd_offset
            central_ok = entries == 0 or (cd_abs + 4 <= len(data) and data[cd_abs:cd_abs + 4] == b"PK\x01\x02")
            if end <= len(data) and central_ok and cd_offset + cd_size <= pos:
                return start + end, {"entries": entries, "central_directory_offset": cd_offset, "central_directory_size": cd_size, "comment_length": comment}
        cursor = pos + 1
    raise ValidationError("EOCD/central directory ZIP non coerenti")


def validate_zip(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate ZIP EOCD, central directory, members and CRC without extraction."""
    start = c["offset"]
    end, details = _find_zip_eocd(path, start, size, cap)
    data = _read(path, start, end - start)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            encrypted = [i.filename for i in infos if i.flag_bits & 1]
            bad = None if encrypted else archive.testzip()
            if bad:
                raise ValidationError(f"CRC ZIP errato: {bad}")
            if len(infos) != details["entries"]:
                raise ValidationError("conteggio entry ZIP discordante")
            details["members"] = [{"name": i.filename, "compressed": i.compress_size, "size": i.file_size, "crc": f"{i.CRC:08x}"} for i in infos[:256]]
            details["zip64"] = any(i.file_size >= 0xFFFFFFFF or i.header_offset >= 0xFFFFFFFF for i in infos)
            details["encrypted_entries"] = encrypted
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise ValidationError(f"parser ZIP: {exc}") from exc
    return _result(c, end, "eocd_central_directory_and_crc" if not details["encrypted_entries"] else "eocd_and_central_directory_encrypted", .995 if not details["encrypted_entries"] else .94, details)


def validate_pdf(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate PDF header, indirect objects, trailer/startxref and EOF boundary."""
    start = c["offset"]
    data = _read(path, start, min(cap, size - start))
    if not data.startswith(b"%PDF-") or len(data) < 16:
        raise ValidationError("header PDF non valido")
    eof_positions, cursor = [], 0
    while True:
        pos = data.find(b"%%EOF", cursor)
        if pos < 0:
            break
        eof_positions.append(pos)
        cursor = pos + 5
    if not eof_positions or b" obj" not in data or b"trailer" not in data:
        raise ValidationError("struttura PDF incompleta")
    chosen = eof_positions[-1]
    before = data[max(0, chosen - 4096):chosen]
    sx = before.rfind(b"startxref")
    if sx < 0:
        raise ValidationError("startxref PDF assente")
    tail = before[sx + 9:].strip().splitlines()
    if not tail or not tail[0].strip().isdigit():
        raise ValidationError("offset startxref non numerico")
    xref = int(tail[0].strip())
    if xref >= chosen or data[xref:xref + 4] not in (b"xref",) and not data[xref:xref + 20].lstrip().startswith(tuple(str(i).encode() for i in range(10))):
        # Object streams/xref streams begin with an indirect object number.
        raise ValidationError("startxref fuori struttura")
    end = chosen + 5
    while end < len(data) and data[end] in b"\r\n \t":
        end += 1
    return _result(c, start + end, "pdf_startxref_and_eof", .96, {"eof_count": len(eof_positions), "startxref": xref, "objects": data.count(b" obj")})


def validate_gzip(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate a gzip stream, CRC and consumed boundary with a capped decoder."""
    start = c["offset"]
    data = _read(path, start, min(cap, size - start))
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        output = decoder.decompress(data, cap)
    except zlib.error as exc:
        raise ValidationError(f"gzip non valido: {exc}") from exc
    if not decoder.eof:
        raise ValidationError("stream gzip troncato o oltre limite")
    consumed = len(data) - len(decoder.unused_data)
    return _result(c, start + consumed, "gzip_stream_crc", .97, {"uncompressed_preview_bytes": len(output)})


def _compressed_validator(path: Path, c: dict, size: int, cap: int, decoder, method: str) -> dict:
    """Validate a bounded single-stream compressor and derive consumed bytes."""
    start = c["offset"]
    data = _read(path, start, min(cap, size - start))
    try:
        obj = decoder()
        obj.decompress(data, max_length=cap)
    except (OSError, EOFError, lzma.LZMAError) as exc:
        raise ValidationError(str(exc)) from exc
    if not obj.eof:
        raise ValidationError("stream compresso incompleto")
    return _result(c, start + len(data) - len(obj.unused_data), method, .96)


def validate_bzip2(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate BZip2 stream checksum and boundary without writing output."""
    return _compressed_validator(path, c, size, cap, bz2.BZ2Decompressor, "bzip2_stream_crc")


def validate_xz(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate XZ stream and footer checksum through the standard decoder."""
    return _compressed_validator(path, c, size, cap, lzma.LZMADecompressor, "xz_stream_footer")


def validate_tar(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate TAR headers/checksums and stop after the two zero blocks."""
    start = c["offset"]
    data = _read(path, start, min(cap, size - start))
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            members = archive.getmembers()
            if not members:
                raise ValidationError("TAR senza entry")
            logical = max((m.offset_data + ((m.size + 511) // 512) * 512 for m in members), default=0) + 1024
    except (tarfile.TarError, OSError) as exc:
        raise ValidationError(f"TAR non valido: {exc}") from exc
    if logical > len(data):
        raise ValidationError("TAR troncato")
    return _result(c, start + logical, "tar_headers_checksums", .96, {"entries": len(members)})


def validate_pe(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate DOS/PE headers and section table; boundary includes raw sections."""
    start = c["offset"]
    head = _read(path, start, min(cap, size - start))
    if len(head) < 0x40 or head[:2] != b"MZ":
        raise ValidationError("DOS header assente")
    peoff = struct.unpack("<I", head[0x3c:0x40])[0]
    if peoff + 24 > len(head) or head[peoff:peoff + 4] != b"PE\x00\x00":
        raise ValidationError("PE signature/e_lfanew non validi")
    sections, opt_size = struct.unpack("<H", head[peoff + 6:peoff + 8])[0], struct.unpack("<H", head[peoff + 20:peoff + 22])[0]
    table = peoff + 24 + opt_size
    if not 0 < sections <= 96 or table + sections * 40 > len(head):
        raise ValidationError("section table PE non valida")
    end = table + sections * 40
    for index in range(sections):
        row = head[table + index * 40:table + (index + 1) * 40]
        raw_size, raw_ptr = struct.unpack("<II", row[16:24])
        end = max(end, raw_ptr + raw_size)
    if end > min(cap, size - start):
        raise ValidationError("sezioni PE fuori file")
    return _result(c, start + end, "pe_section_table", .98, {"sections": sections, "pe_offset": peoff})


def validate_elf(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate ELF class/endian header and program/section table extents."""
    start = c["offset"]
    data = _read(path, start, min(cap, size - start))
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValidationError("identificatore ELF non valido")
    endian = "<" if data[5] == 1 else ">"
    is64 = data[4] == 2
    if is64:
        phoff, shoff = struct.unpack(endian + "QQ", data[32:48]); phents, phnum, shents, shnum = struct.unpack(endian + "HHHH", data[54:62])
    else:
        phoff, shoff = struct.unpack(endian + "II", data[28:36]); phents, phnum, shents, shnum = struct.unpack(endian + "HHHH", data[42:50])
    end = max(64 if is64 else 52, phoff + phents * phnum, shoff + shents * shnum)
    if end > len(data) or phnum > 4096 or shnum > 65535:
        raise ValidationError("tabelle ELF fuori limite")
    # Section headers do not necessarily cover appended bytes; logical end is their table here.
    return _result(c, start + end, "elf_header_tables", .92, {"class": 64 if is64 else 32, "program_headers": phnum, "sections": shnum})


def validate_macho(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate Mach-O magic and bounded load-command table."""
    start = c["offset"]
    data = _read(path, start, min(cap, size - start))
    magic = data[:4]
    if magic not in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
        raise ValidationError("magic Mach-O non valido")
    little, is64 = magic in {b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}, magic in {b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}
    endian = "<" if little else ">"; header = 32 if is64 else 28
    if len(data) < header:
        raise ValidationError("header Mach-O troncato")
    ncmds, sizeofcmds = struct.unpack(endian + "II", data[16:24])
    if ncmds > 65535 or header + sizeofcmds > len(data):
        raise ValidationError("load commands Mach-O incoerenti")
    return _result(c, start + header + sizeofcmds, "macho_load_commands", .92, {"commands": ncmds, "class": 64 if is64 else 32})


def validate_sqlite(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate SQLite header page size, versions and file page alignment."""
    start = c["offset"]
    head = _read(path, start, 100)
    if len(head) < 100 or not head.startswith(b"SQLite format 3\x00"):
        raise ValidationError("header SQLite troncato")
    page = struct.unpack(">H", head[16:18])[0] or 65536
    pages = struct.unpack(">I", head[28:32])[0]
    if page < 512 or page > 65536 or page & (page - 1) or head[18] not in (1, 2) or head[19] not in (1, 2):
        raise ValidationError("parametri SQLite non validi")
    length = pages * page if pages else ((size - start) // page) * page
    if not length or length > min(cap, size - start):
        raise ValidationError("dimensione SQLite incoerente")
    return _result(c, start + length, "sqlite_page_count", .97, {"page_size": page, "pages": pages})


def validate_java(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate Java class version and constant-pool envelope conservatively."""
    start = c["offset"]
    data = _read(path, start, min(cap, size - start))
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        raise ValidationError("class header assente")
    minor, major, count = struct.unpack(">HHH", data[4:10])
    if not 45 <= major <= 100 or count < 1:
        raise ValidationError("versione/pool Java incoerenti")
    pos, index = 10, 1
    widths = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}
    while index < count:
        if pos >= len(data): raise ValidationError("constant pool troncato")
        tag = data[pos]; pos += 1
        if tag == 1:
            if pos + 2 > len(data): raise ValidationError("UTF8 pool troncato")
            width = struct.unpack(">H", data[pos:pos + 2])[0] + 2
        elif tag in widths: width = widths[tag]
        else: raise ValidationError("tag constant pool sconosciuto")
        pos += width
        if pos > len(data): raise ValidationError("constant pool fuori file")
        index += 2 if tag in (5, 6) else 1
    if pos + 8 > len(data): raise ValidationError("class body troncato")
    return _result(c, start + len(data), "java_constant_pool", .86, {"major": major, "minor": minor, "constant_pool": count})


def validate_wasm(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate WASM version and LEB128 section envelope to the parsed end."""
    start = c["offset"]
    data = _read(path, start, min(cap, size - start))
    if len(data) < 8 or data[:8] != b"\x00asm\x01\x00\x00\x00":
        raise ValidationError("header/versione WASM non validi")
    pos, sections = 8, 0
    while pos < len(data):
        pos += 1; value = 0; shift = 0
        while pos < len(data):
            byte = data[pos]; pos += 1; value |= (byte & 0x7f) << shift
            if not byte & 0x80: break
            shift += 7
            if shift > 35: raise ValidationError("LEB128 WASM invalido")
        if pos + value > len(data): raise ValidationError("sezione WASM troncata")
        pos += value; sections += 1
    return _result(c, start + pos, "wasm_sections", .96, {"sections": sections})


def validate_ole(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate OLE CFB header, byte order and sector/DIFAT parameters."""
    start = c["offset"]
    head = _read(path, start, 512)
    if len(head) != 512 or head[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" or head[28:30] != b"\xfe\xff":
        raise ValidationError("header CFB/OLE non valido")
    sector_shift = struct.unpack("<H", head[30:32])[0]
    mini_shift = struct.unpack("<H", head[32:34])[0]
    if sector_shift not in (9, 12) or mini_shift != 6:
        raise ValidationError("dimensione settori OLE non valida")
    sector = 1 << sector_shift
    length = ((size - start) // sector) * sector
    if length < 512 or length > cap:
        raise ValidationError("contenitore OLE fuori limite")
    return _result(c, start + length, "ole_header_sector_alignment", .90, {"sector_size": sector})


def validate_7z(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate 7z start-header CRC and declared next-header boundary."""
    start = c["offset"]
    head = _read(path, start, 32)
    if len(head) < 32 or head[:6] != b"7z\xbc\xaf'\x1c": raise ValidationError("header 7z assente")
    if zlib.crc32(head[12:32]) & 0xffffffff != struct.unpack("<I", head[8:12])[0]: raise ValidationError("CRC start header 7z errato")
    nxt, nxt_size = struct.unpack("<QQ", head[12:28]); end = start + 32 + nxt + nxt_size
    if end > min(size, start + cap): raise ValidationError("next header 7z fuori file")
    return _result(c, end, "7z_start_header_crc", .98, {"next_header_size": nxt_size})


def validate_rar(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate RAR signature and a plausible first block header conservatively."""
    start = c["offset"]; data = _read(path, start, min(64, size - start))
    siglen = 8 if data.startswith(b"Rar!\x1a\x07\x01\x00") else 7 if data.startswith(b"Rar!\x1a\x07\x00") else 0
    if not siglen or len(data) < siglen + 7: raise ValidationError("header RAR troncato")
    return _result(c, min(size, start + cap), "rar_signature_and_block_header", .78, {"version": 5 if siglen == 8 else 4, "boundary_exact": False})


def validate_cpio(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate newc CPIO hexadecimal header fields and aligned records."""
    start = c["offset"]; data = _read(path, start, min(cap, size - start)); pos = 0; entries = 0
    while pos + 110 <= len(data):
        if data[pos:pos + 6] not in (b"070701", b"070702"): raise ValidationError("record CPIO invalido")
        try: filesize = int(data[pos + 54:pos + 62], 16); namesize = int(data[pos + 94:pos + 102], 16)
        except ValueError as exc: raise ValidationError("campi CPIO non esadecimali") from exc
        name_end = pos + 110 + namesize
        if not namesize or name_end > len(data): raise ValidationError("nome CPIO fuori file")
        name = data[pos + 110:name_end - 1]
        pos = (name_end + 3) & ~3
        if pos + filesize > len(data): raise ValidationError("payload CPIO troncato")
        pos = (pos + filesize + 3) & ~3; entries += 1
        if name == b"TRAILER!!!": return _result(c, start + pos, "cpio_trailer_and_records", .96, {"entries": entries - 1})
    raise ValidationError("trailer CPIO assente")


def validate_iso(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate ISO9660 primary volume descriptor and declared volume space."""
    start = c["offset"]; pvd = _read(path, start + 32768, 2048)
    if len(pvd) < 2048 or pvd[0] != 1 or pvd[1:6] != b"CD001" or pvd[6] != 1: raise ValidationError("PVD ISO9660 non valido")
    blocks = struct.unpack("<I", pvd[80:84])[0]; block_size = struct.unpack("<H", pvd[128:130])[0]
    length = blocks * block_size
    if block_size not in (512, 1024, 2048, 4096) or not length or length > min(cap, size - start): raise ValidationError("dimensione ISO9660 incoerente")
    return _result(c, start + length, "iso9660_volume_space", .98, {"blocks": blocks, "block_size": block_size})


def validate_xml(path: Path, c: dict, size: int, cap: int) -> dict:
    """Parse bounded XML as inert text and use the parser-consumed document."""
    start = c["offset"]; data = _read(path, start, min(cap, size - start))
    try: ET.fromstring(data)
    except ET.ParseError as exc: raise ValidationError(f"XML non valido: {exc}") from exc
    return _result(c, start + len(data), "xml_parser", .93)


def validate_html(path: Path, c: dict, size: int, cap: int) -> dict:
    """Validate HTML from paired structural tokens without executing active data."""
    start = c["offset"]; data = _read(path, start, min(cap, size - start)); low = data.lower()
    begin = low.find(b"<html")
    end = low.rfind(b"</html>")
    if begin < 0 or end < begin: raise ValidationError("elemento HTML radice incompleto")
    return _result(c, start + end + 7, "html_root_element", .90, {"active_content": b"<script" in low})


def validate_script(path: Path, c: dict, size: int, cap: int) -> dict:
    """Classify a passive script and stop before an appended archive marker."""
    start = c["offset"]; data = _read(path, start, min(cap, size - start)); head = data[:4096]
    text = head.decode("utf-8", "replace").lower()
    indicators = [token for token in ("#!/", "@echo off", "#requires", "powershell", "python", "node", "bash", "perl", "ruby", "import ", "from ", "def ", "function ", "const ", "let ", "var ", "setlocal", "param(") if token in text]
    if not indicators: raise ValidationError("linguaggio script non riconosciuto")
    archive_offsets = [offset for marker in (b"PK\x03\x04", b"\x1f\x8b\x08", b"7z\xbc\xaf'\x1c") if (offset := data.find(marker, 1)) > 0]
    end = min(archive_offsets) if archive_offsets else len(data)
    sample = data[:min(end, 65536)]
    printable = sum(byte in b"\t\r\n" or 32 <= byte < 127 for byte in sample) / max(1, len(sample))
    if printable < .75: raise ValidationError("rapporto testo script insufficiente")
    return _result(c, start + end, "static_script_envelope", .90, {"indicators": indicators, "printable_ratio": round(printable, 3), "executed": False})
