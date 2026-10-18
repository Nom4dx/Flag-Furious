#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import mmap
import re
import shutil
import struct
import subprocess
import sys
import zlib
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence


CHUNK_SIZE = 1024 * 1024
MAGIC_PREVIEW_SIZE = 56
SHAKE_OUTPUT_BYTES = 32
VERSION = "1.0.0"

COMMON_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")

ALL_ALGORITHMS = (
    "sha256",
    "sha512",
    "sha3_256",
    "sha3_512",
    "blake2b",
    "sha384",
    "sha224",
    "sha3_224",
    "sha3_384",
    "shake_128",
    "shake_256",
    "sm3",
    "ripemd160",
    "sha1",
    "md5",
    "md5-sha1",
    "whirlpool",
    "md4",
)


@dataclass(frozen=True, slots=True)
class HashReport:
    digests: dict[str, str]
    unsupported: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Detection:
    description: str
    source: str
    offset: int | None = None


@dataclass(frozen=True, slots=True)
class StructureCheck:
    name: str
    description: str
    evidence: tuple[str, ...]
    repair_offset: int | None = None
    repair_magic: str | None = None


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    path: str
    size: int
    magic_preview: str
    hashes: dict[str, str]
    unsupported_hashes: tuple[str, ...]
    hash_matches: tuple[str, ...]
    detections: tuple[Detection, ...]
    structures: tuple[StructureCheck, ...]
    metadata: dict[str, str]


@dataclass(frozen=True, slots=True)
class RepairResult:
    source: str
    output: str
    format: str
    offset: int
    old_magic: str
    new_magic: str


def calculate_hashes(
    file_path: str | Path,
    algorithms: Sequence[str] = COMMON_ALGORITHMS,
    chunk_size: int = CHUNK_SIZE,
) -> HashReport:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    hashers: dict[str, Any] = {}
    unsupported: list[str] = []

    for algorithm in dict.fromkeys(name.lower() for name in algorithms):
        try:
            hashers[algorithm] = hashlib.new(algorithm, usedforsecurity=False)
        except (TypeError, ValueError):
            unsupported.append(algorithm)

    with Path(file_path).open("rb") as file:
        while chunk := file.read(chunk_size):
            for hasher in hashers.values():
                hasher.update(chunk)

    digests = {
        algorithm: (
            hasher.hexdigest(SHAKE_OUTPUT_BYTES)
            if algorithm.startswith("shake_")
            else hasher.hexdigest()
        )
        for algorithm, hasher in hashers.items()
    }
    return HashReport(digests=digests, unsupported=tuple(unsupported))


def normalize_digest(value: str) -> str:
    digest = value.strip().lower()
    if digest.startswith("0x"):
        digest = digest[2:]
    digest = digest.replace(":", "").replace(" ", "")
    if not digest or re.fullmatch(r"[0-9a-f]+", digest) is None:
        raise ValueError("the expected hash must be a hexadecimal string")
    return digest


def find_hash_matches(expected: str, digests: dict[str, str]) -> tuple[str, ...]:
    normalized = normalize_digest(expected)
    return tuple(
        algorithm
        for algorithm, digest in digests.items()
        if hmac.compare_digest(normalized, digest.lower())
    )


def read_magic_preview(file_path: str | Path, size: int = MAGIC_PREVIEW_SIZE) -> bytes:
    if size < 0:
        raise ValueError("size cannot be negative")
    with Path(file_path).open("rb") as file:
        return file.read(size)


MAGIC_SIGNATURES = (
    ("23 21", "0", "Script or data to be passed to the program following the shebang (#!)"),
    ("02 00 5A 57 52 54 00 00 00 00 00 00 00 00 00 00", "0", "cwk — Claris Works word processing doc"),
    ("00 00 02 00 06 04 06 00 08 00 00 00 00 00", "0", "wk1 — Lotus 1-2-3 spreadsheet (v1) file"),
    ("00 00 1A 00 00 10 04 00 00 00 00 00", "0", "wk3 — Lotus 1-2-3 spreadsheet (v3) file"),
    ("00 00 1A 00 02 10 04 00 00 00 00 00", "0", "wk4 wk5 — Lotus 1-2-3 spreadsheet (v4, v5) file"),
    ("00 00 1A 00 05 10 04", "0", "123 — Lotus 1-2-3 spreadsheet (v9) file"),
    ("00 00 03 F3", "0", "Amiga Hunk executable file"),
    ("00 00 49 49 58 50 52", "0", "qxd — Quark Express document"),
    ("00 00 4D 4D 58 50 52", "0", "qxd — Quark Express document"),
    ("50 57 53 33", "0", "psafe3 — Password Gorilla Password Database"),
    ("D4 C3 B2 A1", "0", "pcap — Libpcap File Format"),
    ("4D 3C B2 A1", "0", "pcap — Libpcap File Format (nanosecond-resolution)"),
    ("0A 0D 0D 0A", "0", "pcapng — PCAP Next Generation Dump File Format"),
    ("ED AB EE DB", "0", "rpm — RedHat Package Manager (RPM) package"),
    ("53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00", "0", "sqlitedb sqlite db — SQLite Database"),
    ("53 50 30 31", "0", "bin — Amazon Kindle Update Package"),
    ("49 57 41 44", "0", "wad — internal WAD (main resource file of Doom )"),
    ("00", "0", "PIC PIF SEA YTR — IBM Storyboard bitmap file Windows Program Information File Mac Stuffit Self-Extracting Archive IRIS OCR data file"),
    ("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", "11", "PDB — PalmPilot Database/Document File"),
    ("BE BA FE CA", "0", "DBA — Palm Desktop Calendar Archive"),
    ("00 01 42 44", "0", "DBA — Palm Desktop To Do Archive"),
    ("00 01 44 54", "0", "TDA — Palm Desktop Calendar Archive"),
    ("54 44 46 24", "0", "TDF$ — Telegram Desktop File"),
    ("54 44 45 46", "0", "TDEF — Telegram Desktop Encrypted File"),
    ("00 01 00 00", "0", "Palm Desktop Data File ( Access format)"),
    ("00 00 01 00", "0", "ico — Computer icon encoded in ICO file format"),
    ("69 63 6E 73", "0", "icns — Apple Icon Image format"),
    ("66 74 79 70 33 67", "4", "3gp 3g2 — 3rd Generation Partnership Project 3GPP and 3GPP2 multimedia files"),
    ("66 74 79 70 68 65 69 63", "4", "heic — High Efficiency Image Container (HEIC)"),
    ("66 74 79 70 6D", "4", "heic — High Efficiency Image Container (HEIC)"),
    ("1F 9D", "0", "z tar.z — compressed file (often tar zip) using Lempel-Ziv-Welch algorithm"),
    ("1F A0", "0", "z tar.z — Compressed file (often tar zip) using LZH algorithm"),
    ("2D 6C 68 30 2D", "2", "lzh — Lempel Ziv Huffman archive file Method 0 (No compression)"),
    ("2D 6C 68 35 2D", "2", "lzh — Lempel Ziv Huffman archive file Method 5 (8 KiB sliding window)"),
    ("42 41 43 4B 4D 49 4B 45 44 49 53 4B", "0", "bac — AmiBack Amiga Backup data file"),
    ("49 4E 44 58", "0", "idx — AmiBack Amiga Backup index file"),
    ("62 70 6C 69 73 74", "0", "plist — Binary Property List file"),
    ("42 5A 68", "0", "bz2 — Compressed file using Bzip2 algorithm"),
    ("47 49 46 38 37 61", "0", "gif — Image file encoded in the Graphics Interchange Format (GIF)"),
    ("47 49 46 38 39 61", "0", "gif — Image file encoded in the Graphics Interchange Format (GIF)"),
    ("49 49 2A 00", "0", "tif tiff — Tagged Image File Format (TIFF)"),
    ("49 49 2B 00", "0", "tif tiff — BigTIFF"),
    ("49 49 2A 00 10 00 00 00 43 52", "0", "cr2 — Canon RAW Format Version 2  Canon's RAW format is based on TIFF."),
    ("80 2A 5F D7", "0", "cin — Kodak Cineon image"),
    ("52 4E 43 01", "0", "Compressed file using Rob Northen Compression (version 1 and 2) algorithm"),
    ("52 4E 43 02", "0", "Compressed file using Rob Northen Compression (version 1 and 2) algorithm"),
    ("4E 55 52 55 49 4D 47", "0", "nui nup — nuru ASCII/ANSI image and palette files"),
    ("4E 55 52 55 50 41 4C", "0", "nui nup — nuru ASCII/ANSI image and palette files"),
    ("53 44 50 58", "0", "dpx — SMPTE DPX image"),
    ("76 2F 31 01", "0", "exr — OpenEXR image"),
    ("42 50 47 FB", "0", "bpg — Better Portable Graphics format"),
    ("FF D8 FF DB", "0", "jpg jpeg — JPEG raw or in the JFIF or Exif file format"),
    ("FF D8 FF E0", "0", "jpg — JPEG raw or in the JFIF or Exif file format"),
    ("00 00 00 0C 6A 50 20 20 0D 0A 87 0A", "0", "jp2 j2k jpf jpm jpg2 j2c jpc jpx mj2 — JPEG 2000 format"),
    ("71 6F 69 66", "0", "qoi — QOI - The “Quite OK Image Format”"),
    ("46 4F 52 4D ?? ?? ?? ?? 49 4C 42 4D", "0 any", "ilbm lbm ibm iff — IFF Interleaved Bitmap Image"),
    ("46 4F 52 4D ?? ?? ?? ?? 38 53 56 58", "0 any", "8svx 8sv svx snd iff — IFF 8-Bit Sampled Voice"),
    ("46 4F 52 4D ?? ?? ?? ?? 41 43 42 4D", "0 any", "acbm iff — Amiga Contiguous Bitmap"),
    ("46 4F 52 4D ?? ?? ?? ?? 41 4E 42 4D", "0 any", "anbm iff — IFF Animated Bitmap"),
    ("46 4F 52 4D ?? ?? ?? ?? 41 4E 49 4D", "0 any", "anim iff — IFF CEL Animation"),
    ("46 4F 52 4D ?? ?? ?? ?? 46 41 58 58", "0 any", "faxx fax iff — IFF Facsimile Image"),
    ("46 4F 52 4D ?? ?? ?? ?? 46 54 58 54", "0 any", "ftxt iff — IFF Formatted Text"),
    ("46 4F 52 4D ?? ?? ?? ?? 53 4D 55 53", "0 any", "smus smu mus iff — IFF Simple Musical Score"),
    ("46 4F 52 4D ?? ?? ?? ?? 43 4D 55 53", "0 any", "cmus mus iff — IFF Musical Score"),
    ("46 4F 52 4D ?? ?? ?? ?? 59 55 56 4E", "0 any", "yuvn yuv iff — IFF YUV Image"),
    ("46 4F 52 4D ?? ?? ?? ?? 46 41 4E 54", "0 any", "iff — Amiga Fantavision Movie"),
    ("46 4F 52 4D ?? ?? ?? ?? 41 49 46 46", "0 any", "aiff aif aifc snd iff — Audio Interchange File Format"),
    ("4C 5A 49 50", "0", "lz — lzip compressed file"),
    ("30 37 30 37 30 31", "0", "cpio — cpio \"new\" ASCII archive file"),
    ("30 37 30 37 30 32", "0", "cpio — cpio ASCII archive file with crc"),
    ("30 37 30 37 30 37", "0", "cpio — cpio ASCII archive file"),
    ("4D 5A", "0", "exe dll mui sys scr cpl ocx ax iec ime rs tsp fon efi — DOS MZ executable and its descendants (including NE and PE )"),
    ("53 4D 53 4E 46 32 30 30", "0", "ssp — SmartSniff Packets File"),
    ("5A 4D", "0", "exe — DOS ZM executable and its descendants (rare)"),
    ("50 4B 03 04", "0", "zip aar apk docx epub ipa jar kmz maff msix odp ods odt pk3 pk4 pptx usdz vsdx xlsx xpi whl — zip file format and formats based on it, such as EPUB , JAR , ODF , OOXML"),
    ("50 4B 05 06", "0", "zip aar apk docx epub ipa jar kmz maff msix odp ods odt pk3 pk4 pptx usdz vsdx xlsx xpi whl — zip file format and formats based on it, such as EPUB , JAR , ODF , OOXML"),
    ("50 4B 07 08", "0", "zip aar apk docx epub ipa jar kmz maff msix odp ods odt pk3 pk4 pptx usdz vsdx xlsx xpi whl — zip file format and formats based on it, such as EPUB , JAR , ODF , OOXML"),
    ("52 61 72 21 1A 07 00", "0", "rar — Roshal ARchive compressed archive v1.50 onwards"),
    ("52 61 72 21 1A 07 01 00", "0", "rar — Roshal ARchive compressed archive v5.00 onwards"),
    ("7F 45 4C 46", "0", "none, .axf, .bin, .elf, .o, .out, .prx, .puff, .ko, .mod, .so — Executable and Linkable Format"),
    ("89 50 4E 47 0D 0A 1A 0A", "0", "png — Image encoded in the Portable Network Graphics format"),
    ("0E 03 13 01", "0", "hdf4 h4 — Data stored in version 4 of the Hierarchical Data Format ."),
    ("89 48 44 46 0D 0A 1A 0A", "0, 512, 1024, 2048, ...", "hdf5 h5 — Data stored in version 5 of the Hierarchical Data Format ."),
    ("C9", "0", "com — CP/M 3 and higher with overlays"),
    ("CA FE BA BE", "0", "class — Java class file , Mach-O Fat Binary"),
    ("EF BB BF", "0", "txt others — UTF-8 byte order mark , commonly seen in text files."),
    ("FF FE", "0", "txt others — UTF-16LE byte order mark, commonly seen in text files."),
    ("FE FF", "0", "txt others — UTF-16BE byte order mark, commonly seen in text files."),
    ("FF FE 00 00", "0", "txt others — UTF-32LE byte order mark for text"),
    ("00 00 FE FF", "0", "txt others — UTF-32BE byte order mark for text"),
    ("2B 2F 76 38", "0", "UTF-7 byte order mark for text"),
    ("2B 2F 76 39", "0", "UTF-7 byte order mark for text"),
    ("2B 2F 76 2B", "0", "UTF-7 byte order mark for text"),
    ("2B 2F 76 2F", "0", "UTF-7 byte order mark for text"),
    ("0E FE FF", "0", "txt others — SCSU byte order mark for text"),
    ("DD 73 66 73", "0", "UTF-EBCDIC byte order mark for text"),
    ("FE ED FA CE", "0 0x1000", "Mach-O binary (32-bit)"),
    ("FE ED FA CF", "0 0x1000", "Mach-O binary (64-bit)"),
    ("FE ED FE ED", "0", "JKS Javakey Store"),
    ("CE FA ED FE", "0", "Mach-O binary (reverse byte ordering scheme, 32-bit)"),
    ("CF FA ED FE", "0", "Mach-O binary (reverse byte ordering scheme, 64-bit)"),
    ("25 21 50 53", "0", "ps — PostScript document"),
    ("25 21 50 53 2D 41 64 6F 62 65 2D 33 2E 30 20 45 50 53 46 2D 33 2E 30", "0", "eps epsf — Encapsulated PostScript file version 3.0"),
    ("25 21 50 53 2D 41 64 6F 62 65 2D 33 2E 31 20 45 50 53 46 2D 33 2E 30", "0", "eps epsf — Encapsulated PostScript file version 3.1"),
    ("49 54 53 46 03 00 00 00 60 00 00 00", "0", "chm — MS Windows HtmlHelp Data"),
    ("3F 5F", "0", "hlp — Windows 3.x/95/98 Help file"),
    ("25 50 44 46 2D", "0", "pdf — PDF document"),
    ("30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C", "0", "asf wma wmv — Advanced Systems Format"),
    ("24 53 44 49 30 30 30 31", "0", "System Deployment Image , a disk image format used by Microsoft"),
    ("4F 67 67 53", "0", "ogg oga ogv — Ogg , an open source media container format"),
    ("38 42 50 53", "0", "psd — Photoshop Document file, Adobe Photoshop 's native file format"),
    ("52 49 46 46 ?? ?? ?? ?? 57 41 56 45", "0", "wav — Waveform Audio File Format"),
    ("52 49 46 46 ?? ?? ?? ?? 41 56 49 20", "0", "avi — Audio Video Interleave video format"),
    ("FF FB", "0", "mp3 — MPEG-1 Layer 3 file without an ID3 tag or with an ID3v 1 tag (which is appended at the end of the file)"),
    ("FF F3", "0", "mp3 — MPEG-1 Layer 3 file without an ID3 tag or with an ID3v 1 tag (which is appended at the end of the file)"),
    ("FF F2", "0", "mp3 — MPEG-1 Layer 3 file without an ID3 tag or with an ID3v 1 tag (which is appended at the end of the file)"),
    ("49 44 33", "0", "mp3 — MP3 file with an ID3v2 container"),
    ("42 4D", "0", "bmp dib — BMP file, a bitmap format used mostly in the Windows world"),
    ("43 44 30 30 31", "0x8001 0x8801 0x9001", "iso — ISO9660 CD/DVD image file"),
    ("43 44 30 30 31", "0x5EAC9", "cdi — CD-i CD image file"),
    ("6D 61 69 6E 2E 62 73", "0", "mgw — Nintendo Game & Watch image file"),
    ("4E 45 53", "0", "nes — Nintendo Entertainment System image file"),
    ("A0 32 41 A0 A0 A0", "0x165A4", "d64 — Commodore 64 1541 disk image (D64 format)"),
    ("47 53 52 2D 31 35 34 31", "0", "g64 — Commodore 64 1541 disk image (G64 format)"),
    ("A0 33 44 A0 A0", "0x61819", "d81 — Commodore 64 1581 disk image (D81 format)"),
    ("43 36 34 20 74 61 70 65 20 69 6D 61 67 65 20 66 69 6C 65", "0", "t64 — Commodore 64 tape image"),
    ("43 36 34 20 43 41 52 54 52 49 44 47 45 20 20 20", "0", "crt — Commodore 64 cartridge image"),
    ("53 49 4D 50 4C 45 20 20 3D 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 54", "0", "fits — Flexible Image Transport System ( FITS )"),
    ("66 4C 61 43", "0", "flac — Free Lossless Audio Codec"),
    ("4D 54 68 64", "0", "mid midi — MIDI sound file"),
    ("D0 CF 11 E0 A1 B1 1A E1", "0", "doc xls ppt msi msg — Compound File Binary Format , a container format defined by Microsoft COM. It can contain the equivalent of files and directories. It is used by Windows Installer and for documents in older versions of Microsoft Office .  It can be used by other programs as well that rely on the COM and OLE API's. ( 0xD0CF11E0 visually resembles \"DOCFILE\".  )"),
    ("64 65 78 0A 30 33 35 00", "0", "dex — Dalvik Executable"),
    ("4B 44 4D", "0", "vmdk — VMDK files"),
    ("23 20 44 69 73 6B 20 44 65 73 63 72 69 70 74 6F", "0", "vmdk — VMware 4 Virtual Disk description file (split disk)"),
    ("43 72 32 34", "0", "crx — Google Chrome extension  or packaged app"),
    ("41 47 44 33", "0", "fh8 — FreeHand 8 document"),
    ("05 07 00 00 42 4F 42 4F 05 07 00 00 00 00 00 00 00 00 00 00 00 01", "0", "cwk — AppleWorks 5 document"),
    ("06 07 E1 00 42 4F 42 4F 06 07 E1 00 00 00 00 00 00 00 00 00 00 01", "0", "cwk — AppleWorks 6 document"),
    ("45 52 02 00 00 00", "0", "toast — Roxio Toast disc image file"),
    ("6B 6F 6C 79", "end–512", "dmg — Apple Disk Image file"),
    ("78 61 72 21", "0", "xar — eXtensible ARchive format"),
    ("50 4D 4F 43 43 4D 4F 43", "0", "dat — Windows Files And Settings Transfer Repository  See also USMT 3.0 (Win XP)  and USMT 4.0 (Win 7)  User Guides"),
    ("4E 45 53 1A", "0", "nes — Nintendo Entertainment System ROM file"),
    ("75 73 74 61 72 00 30 30", "257", "tar — tar archive"),
    ("75 73 74 61 72 20 20 00", "257", "tar — tar archive"),
    ("4F 41 52 ??", "0", "oar — OAR file archive format, where ?? is the format version."),
    ("74 6F 78 33", "0", "tox — Open source portable voxel file"),
    ("4D 4C 56 49", "0", "MLV — Magic Lantern Video file"),
    ("44 43 4D 01 50 41 33 30", "0", "Windows Update Binary Delta Compression file"),
    ("50 41 33 30", "0", "Windows Update Binary Delta Compression file"),
    ("37 7A BC AF 27 1C", "0", "7z — 7-Zip File Format"),
    ("1F 8B", "0", "gz tar.gz — GZIP compressed file"),
    ("FD 37 7A 58 5A 00", "0", "xz tar.xz — XZ compression utility using LZMA2 compression"),
    ("04 22 4D 18", "0", "lz4 — LZ4 Frame Format  Remark: LZ4 block format does not offer any magic bytes."),
    ("4D 53 43 46", "0", "cab — Microsoft Cabinet file"),
    ("53 5A 44 44 88 F0 27 33", "0", "?? _ — Microsoft compressed file in Quantum format, used prior to Windows XP. File can be decompressed using Extract.exe or Expand.exe distributed with earlier versions of Windows. After compression, the last character of the original filename extension is replaced with an underscore , e.g. ‘Setup.exe’ becomes ‘Setup.ex_’."),
    ("46 4C 49 46", "0", "flif — Free Lossless Image Format"),
    ("1A 45 DF A3", "0", "mkv mka mks mk3d webm — Matroska media container, including WebM"),
    ("4D 49 4C 20", "0", "stg — \"SEAN : Session Analysis\" Training file. Also used in compatible software \"Rpw : Rowperfect for Windows\" and \"RP3W : ROWPERFECT3 for Windows\"."),
    ("41 54 26 54 46 4F 52 4D ?? ?? ?? ?? 44 4A 56", "0", "djvu djv — DjVu document The following byte is either 55 ( U ) for single-page or 4D ( M ) for multi-page documents."),
    ("2D 2D 2D 2D 2D 42 45 47 49 4E 20 43 45 52 54 49 46 49 43 41 54 45 2D 2D 2D 2D 2D", "0", "crt pem — PEM encoded X.509 certificate"),
    ("2D 2D 2D 2D 2D 42 45 47 49 4E 20 43 45 52 54 49 46 49 43 41 54 45 20 52 45 51 55 45 53 54 2D 2D 2D 2D 2D", "0", "csr pem — PEM encoded X.509 Certificate Signing Request"),
    ("2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D", "0", "key pem — PEM encoded X.509 PKCS#8 private key"),
    ("2D 2D 2D 2D 2D 42 45 47 49 4E 20 44 53 41 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D", "0", "key pem — PEM encoded X.509 PKCS#1 DSA private key"),
    ("2D 2D 2D 2D 2D 42 45 47 49 4E 20 52 53 41 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D", "0", "key pem — PEM encoded X.509 PKCS#1 RSA private key"),
    ("50 75 54 54 59 2D 55 73 65 72 2D 4B 65 79 2D 46 69 6C 65 2D 32 3A", "0", "ppk — PuTTY private key file version 2"),
    ("50 75 54 54 59 2D 55 73 65 72 2D 4B 65 79 2D 46 69 6C 65 2D 33 3A", "0", "ppk — PuTTY private key file version 3"),
    ("2D 2D 2D 2D 2D 42 45 47 49 4E 20 4F 50 45 4E 53 53 48 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D", "0", "OpenSSH private key file"),
    ("2D 2D 2D 2D 2D 42 45 47 49 4E 20 53 53 48 32 20 4B 45 59 2D 2D 2D 2D 2D", "0", "pub — OpenSSH public key file"),
    ("44 49 43 4D", "128", "dcm — DICOM Medical File Format"),
    ("77 4F 46 46", "0", "woff — WOFF File Format 1.0"),
    ("77 4F 46 32", "0", "woff2 — WOFF File Format 2.0"),
    ("3C 3F 78 6D 6C 20", "0 after BOM", "xml ( UTF-8 or other 8-bit encodings) — eXtensible Markup Language"),
    ("00 61 73 6D", "0", "wasm — WebAssembly binary format"),
    ("CF 84 01", "0", "lep — Lepton compressed JPEG image"),
    ("43 57 53", "0", "swf — Adobe Flash .swf"),
    ("21 3C 61 72 63 68 3E 0A", "0", "deb — linux deb file"),
    ("C0 3B 39 98", "0", "Linux EXT3 / EXT4 jbd2 filesystem Journal"),
    ("52 49 46 46 ?? ?? ?? ?? 57 45 42 50", "0", "webp — Google WebP image file, where ?? ?? ?? ?? is the file size. More information on WebP File Header"),
    ("27 05 19 56", "0", "U-Boot / uImage. Das U-Boot Universal Boot Loader."),
    ("7B 5C 72 74 66 31", "0", "rtf — Rich Text Format"),
    ("54 41 50 45", "0", "Microsoft Tape Format"),
    ("47", "0 0xBC 0x178 ... (every 188th byte)", "ts tsv tsa mpg mpeg — MPEG Transport Stream (MPEG-2 Part 1)"),
    ("00 00 01 BA", "0", "m2p vob mpg mpeg — MPEG Program Stream (MPEG-1 Part 1 (essentially identical) and MPEG-2 Part 1)"),
    ("00 00 01 B3", "0", "mpg mpeg — MPEG-1 video and MPEG-2 video (MPEG-1 Part 2 and MPEG-2 Part 2)"),
    ("66 74 79 70 69 73 6F 6D", "4", "mp4 — ISO Base Media file (MPEG-4)"),
    ("66 74 79 70 4D 53 4E 56", "4", "mp4 — MPEG-4 video file"),
    ("78 01", "0", "zlib — No Compression (no preset dictionary)"),
    ("62 76 78 32", "0", "lzfse — LZFSE - Lempel-Ziv style data compression algorithm using Finite State Entropy coding. OSS by Apple."),
    ("4F 52 43", "0", "orc — Apache ORC (Optimized Row Columnar) file format"),
    ("4F 62 6A 01", "0", "avro — Apache Avro binary file format"),
    ("53 45 51 36", "0", "rc — RCFile columnar file format"),
    ("3C 72 6F 62 6C 6F 78 21", "0", "rbxl — Roblox place file"),
    ("65 87 78 56", "0", "p25 obt — PhotoCap Object Templates"),
    ("55 55 AA AA", "0", "pcv — PhotoCap Vector"),
    ("78 56 34", "0", "pbt pdt pea peb pet pgt pict pjt pkt pmt — PhotoCap Template"),
    ("50 41 52 31", "0", "Apache Parquet columnar file format"),
    ("45 4D 58 32", "0", "ez2 — Emulator Emaxsynth samples"),
    ("45 4D 55 33", "0", "ez3 iso — Emulator III synth samples"),
    ("1B 4C 75 61", "0", "luac — Lua bytecode"),
    ("62 6F 6F 6B 00 00 00 00 6D 61 72 6B 00 00 00 00", "0", "alias — macOS file Alias  ( Symbolic link )"),
    ("62 6F 6F 6B", "0", "macOS bookmark format"),
    ("5B 5A 6F 6E 65 54 72 61 6E 73 66 65 72 5D", "0", "Identifier — Microsoft Zone Identifier for URL Security Zones"),
    ("52 65 63 65 69 76 65 64 3A", "0", "eml — Email Message var5 [ citation needed ]"),
    ("20 02 01 62 A0 1E AB 07 02 00 00 00", "0", "tde — Tableau Datasource"),
    ("37 48 03 02 00 00 00 00 58 35 30 39 4B 45 59", "0", "kdb — KDB file"),
    ("85 ?? ?? 03", "0", "pgp — PGP file"),
    ("28 B5 2F FD", "0", "zst — Zstandard compress"),
    ("52 53 56 4B 44 41 54 41", "0", "rs — QuickZip rs compressed archive"),
    ("3A 29 0A", "0", "sml — Smile file"),
    ("4A 6F 79 21", "0", "Preferred Executable Format"),
    ("34 12 AA 55", "0", "vpk — VPK file, used to store game data for some Source Engine games"),
    ("2A 2A 41 43 45 2A 2A", "7", "ace — ACE (compressed file format) [ citation needed ]"),
    ("60 EA", "0", "arj — ARJ"),
    ("49 53 63 28", "0", "cab — InstallShield CAB Archive File"),
    ("4B 57 41 4A", "0", "??_ — Windows 3.1x Compressed File"),
    ("53 5A 44 44", "0", "??_ — Windows 9x Compressed File"),
    ("5A 4F 4F", "0", "zoo — Zoo (file format)"),
    ("50 31 0A", "0", "pbm — Portable bitmap ASCII"),
    ("50 34 0A", "0", "pbm — Portable bitmap binary"),
    ("50 32 0A", "0", "pgm — Portable Gray Map ASCII"),
    ("50 35 0A", "0", "pgm — Portable Gray Map binary"),
    ("50 33 0A", "0", "ppm — Portable Pixmap ASCII"),
    ("50 36 0A", "0", "ppm — Portable Pixmap binary"),
    ("D7 CD C6 9A", "0", "wmf — Windows Metafile"),
    ("67 69 6D 70 20 78 63 66", "0", "xcf — XCF (file format)"),
    ("2F 2A 20 58 50 4D 20 2A 2F", "0", "xpm — X PixMap"),
    ("41 46 46", "0", "aff — Advanced Forensics Format"),
    ("45 56 46 32", "0", "Ex01 — EnCase EWF version 2 format"),
    ("45 56 46", "0", "e01 — EnCase EWF version 1 format"),
    ("51 46 49", "0", "qcow — qcow file format"),
    ("52 49 46 46 ?? ?? ?? ?? 41 43 4F 4E", "0", "ani — Animated cursor"),
    ("52 49 46 46 ?? ?? ?? ?? 43 44 44 41", "0", "cda — .cda file"),
    ("52 49 46 46 ?? ?? ?? ?? 51 4C 43 4D", "0", "qcp — Qualcomm PureVoice file format"),
    ("52 49 46 58 ?? ?? ?? ?? 46 47 44 4D", "0", "dcr — Adobe Shockwave"),
    ("52 49 46 58 ?? ?? ?? ?? 4D 56 39 33", "0", "dir dxr drx — Macromedia Director file format"),
    ("46 4C 56", "0", "flv — Flash Video file"),
    ("3C 3C 3C 20 4F 72 61 63 6C 65 20 56 4D 20 56 69 72 74 75 61 6C 42 6F 78 20 44 69 73 6B 20 49 6D 61 67 65 20 3E 3E 3E", "0", "vdi — VirtualBox Virtual Hard Disk file format"),
    ("63 6F 6E 65 63 74 69 78", "0", "vhd — Windows Virtual PC Virtual Hard Disk file format"),
    ("76 68 64 78 66 69 6C 65", "0", "vhdx — Windows Virtual PC Windows 8 Virtual Hard Disk file format"),
    ("49 73 5A 21", "0", "isz — Compressed ISO image"),
    ("44 41 41", "0", "daa — Direct Access Archive PowerISO"),
    ("4C 66 4C 65", "0", "evt — Windows Event Viewer file format"),
    ("45 6C 66 46 69 6C 65", "0", "evtx — Windows Event Viewer XML file format"),
    ("73 64 62 66", "8", "sdb — Windows customized database"),
    ("50 4D 43 43", "0", "grp — Windows 3.x Program Manager Program Group file format"),
    ("4B 43 4D 53", "0", "icm — ICC profile"),
    ("72 65 67 66", "0", "dat hiv — Windows Registry file"),
    ("21 42 44 4E", "0", "pst — Microsoft Outlook Personal Storage Table file"),
    ("44 52 41 43 4F", "0", "drc — 3D model compressed with Google Draco"),
    ("47 52 49 42", "0", "grib grib2 — Gridded data (commonly weather observations or forecasts) in the WMO GRIB or GRIB2 format"),
    ("42 4C 45 4E 44 45 52", "0", "blend — Blender File Format"),
    ("00 00 00 0C 4A 58 4C 20 0D 0A 87 0A", "0", "jxl — Image encoded in the JPEG XL format"),
    ("00 01 00 00 00", "0", "ttf tte dfont — TrueType font"),
    ("4F 54 54 4F", "0", "otf — OpenType font"),
    ("23 25 4D 6F 64 75 6C 65", "0", "Modulefile for Environment Modules"),
    ("4D 53 57 49 4D 00 00 00 D0 00 00 00 00", "0", "wim swm esd — Windows Imaging Format file"),
    ("21 2D 31 53 4C 4F 42 1F", "0", "slob — Slob (sorted list of Object storages ) is a read-only, compressed data store with dictionary-like interface"),
    ("AC ED", "0", "Serialized Java Data"),
    ("43 72 65 61 74 69 76 65 20 56 6F 69 63 65 20 46 69 6C 65 1A 1A 00", "0", "voc — Creative Voice file"),
    ("2E 73 6E 64", "0", "au snd — Au audio file format"),
    ("DB 0A CE 00", "0", "OpenGL Iris Perfomer .PFB (Performer Fast Binary)"),
    ("48 5A 4C 52 00 00 00 18", "0", "hazelrules — Noodlesoft Hazel"),
    ("46 4C 68 64", "0", "flp — FL Studio Project File"),
    ("31 30 4C 46", "0", "flm — FL Studio Mobile Project File"),
    ("52 4B 4D 43 32 31 30", "0", "Vormetric Encryption DPM Version 2.1 Header"),
    ("00 01 00 00 4D 53 49 53 41 4D 20 44 61 74 61 62 61 73 65", "0", "mny — Microsoft Money file"),
    ("00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45 20 44 42", "0", "accdb — Microsoft Access 2007 Database"),
    ("00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42", "0", "mdb — Microsoft Access Database"),
    ("01 FF 02 04 03 02", "0", "drw — Micrografx vector graphic file"),
    ("02 64 73 73", "0", "dss — Digital Speech Standard (Olympus, Grundig, & Phillips) v2"),
    ("03 64 73 73", "0", "dss — Digital Speech Standard (Olympus, Grundig, & Phillips) v3"),
    ("03 00 00 00 41 50 50 52", "0", "adx — Approach index file"),
    ("06 06 ED F5 D8 1D 46 E5 BD 31 EF E7 FE 74 B7 1D", "0", "indd — Adobe InDesign document"),
    ("06 0E 2B 34 02 05 01 01 0D 01 02 01 01 02", "0-65535 (run-in)", "mxf — Material Exchange Format file"),
    ("07 53 4B 46", "0", "skf — SkinCrafter skin file"),
    ("07 64 74 32 64 64 74 64", "0", "dtd — DesignTools 2D Design file"),
    ("0A 16 6F 72 67 2E 62 69 74 63 6F 69 6E 2E 70 72", "0", "wallet — MultiBit Bitcoin wallet file"),
    ("0D 44 4F 43", "0", "doc — DeskMate Document file"),
    ("0E 4E 65 72 6F 49 53 4F", "0", "nri — Nero CD Compilation"),
    ("0E 57 4B 53", "0", "wks — DeskMate Worksheet"),
    ("0F 53 49 42 45 4C 49 55 53", "0", "sib — Sibelius Music - Score file"),
    ("23 20 4D 69 63 72 6F 73 6F 66 74 20 44 65 76 65 6C 6F 70 65 72 20 53 74 75 64 69 6F", "0", "dsp — Microsoft Developer Studio project file"),
    ("23 21 41 4D 52", "0", "amr — Adaptive Multi-Rate ACELP (Algebraic Code Excited Linear Prediction) Codec, commonly audio format with GSM cell phones."),
    ("23 21 53 49 4C 4B 0A", "0", "sil — Audio compression format developed by Skype"),
    ("23 3F 52 41 44 49 41 4E 43 45 0A", "0", "hdr — Radiance High Dynamic Range image file"),
    ("23 40 7E 5E", "0", "vbe — VBScript Encoded script"),
    ("0D F0 1D C0", "0", "cdb — MikroTik WinBox Connection Database (Address Book)"),
    ("23 45 58 54 4D 33 55", "0", "m3u m3u8 — Multimedia playlist"),
    ("6D 64 66 00", "0", "m — M2 Archive, used by game developer M2"),
    ("4B 50 4B 41", "0", "pak — Capcom RE Engine game data archives"),
    ("41 52 43", "0", "arc — Capcom MT Framework game data archives"),
    ("41 72 43", "0", "arc cdx — FreeArc file"),
    ("D0 4F 50 53", "0", "pl — Interleaf PrinterLeaf / WorldView document format (now Broadvision QuickSilver)"),
    ("6E 2B 31 00", "344", "nii — Single file NIfTI format, used extensively in biomedical imaging."),
    ("6E 69 31 00", "344", "hdr — Header file of a .hdr/.img pair in NIfTI format, used extensively in biomedical imaging."),
    ("52 41 46 36 34", "0", "Report Builder file from Digital Metaphors"),
    ("56 49 53 33", "0", "Resource file Visionaire 3.x Engine"),
    ("4D 53 48 7C", "0", "hl7 — Health Level Seven (HL7) Standard for electronic data exchange"),
    ("42 53 48 7C", "0", "hl7 — Health Level Seven (HL7) Standard for electronic data exchange"),
    ("70 77 72 64 61 74 61", "0", "pwrdata — SAP Power Monitor (version 1.1.0 and higher) data file"),
    ("1A 08", "0", "arc — ARC archive file"),
    ("2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 47 50 20 50 55 42 4C 49 43 20 4B 45 49 20 42 4C 4F 43 4B 2D 2D 2D 2D 2D", "0", "asc — Armored PGP public key"),
    ("3A 42 61 73 65 20", "0", "cnt — Windows 3.x - Windows 95 Help Contents"),
    ("52 49 46 46 ?? ?? ?? ?? 56 44 52 4D", "0", "vdr — VirtualDub"),
    ("52 59 46 46 ?? ?? ?? ?? 54 52 49 44", "0", "trd — TrID"),
    ("52 49 46 46 ?? ?? ?? ?? 73 68 77 34", "0", "shw — Corel SHOW! 4.0"),
    ("52 49 46 46 ?? ?? ?? ?? 73 68 77 35", "0", "shw — Corel SHOW! 5.0"),
    ("52 49 46 46 ?? ?? ?? ?? 73 68 72 35", "0", "shr — Corel SHOW! 5.0 player"),
    ("52 49 46 46 ?? ?? ?? ?? 73 68 62 35", "0", "shb — Corel SHOW! 5.0 background"),
    ("52 49 46 46 ?? ?? ?? ?? 52 4D 4D 50", "0", "mmm — MacroMind Multimedia Movie or Microsoft Multimedia Movie"),
    ("41 53 54 4D 2D 45 35 37", "0", "e57 — ASTM E57 3D file format"),
    ("AA AA AA AA", "0", "sys — Crowdstrike Channel File"),
    ("8C 0A 00", "0", "ucas — Unreal Engine Compressed Asset Storage file"),
    ("2D 3D 3D 2D 2D 3D 3D 2D 2D 3D 3D 2D 2D 3D 3D 2D", "0", "utoc — Unreal Engine Table of Contents file"),
    ("43 36 34 46 69 6C 65 00", "0", "P00 (P01, P02,...) — Commodore 64 binary file (source: *.P00 format for Power64 emulator )"),
    ("44 55 43 4B", "8", "DuckDB database file (source: Source code )"),
    ("4C 50 4B 53 48 48 52 48", "0", "journal — journald log file"),
    ("E0 01 00 EA", "0", "Ion (serialization format) binary encoding"),
    ("42 53 44 49 46 46 34 30", "0", "bsdiff binary patch"),
    ("7C 61 8A B2", "0", "hpapp hpprgm hpsettings — HP Prime graphing calculator file"),
    ("43 5A 50 58", "0", "czx — Czip X encrypted archive (v4.x)"),
    ("43 50 43 48", "0", "pch — Clang pre-compiled header"),
    ("67 6C 54 46", "0", "glb — Binary glTF file"),
    ("00 00 00 18 66 74 79 70 68 65 69 63 00 00 00 00", "0", "heif — Apple HEIF image file"),
    ("21 3C 73 79 6D 6C 69 6E 6B 3E", "0", "Cygwin symlinks"),
    ("A1 B2 C3 D4", "0", "pcap — Libpcap File Format"),
    ("A1 B2 3C 4D", "0", "pcap — Libpcap File Format (nanosecond-resolution)"),
    ("4D 4D 00 2A", "0", "tif tiff — Tagged Image File Format (TIFF)"),
    ("4D 4D 00 2B", "0", "tif tiff — BigTIFF"),
    ("66 74 79 70 63 72 78 43 52", "0", "cr3"),
    ("58 50 44 53", "0", "dpx — SMPTE DPX image"),
    ("FF D8 FF E0 00 10 4A 46 49 46 00 01", "0", "jpg jpeg — JPEG raw or in the JFIF or Exif file format"),
    ("FF D8 FF EE", "0", "jpg jpeg — JPEG raw or in the JFIF or Exif file format"),
    ("FF D8 FF E1 ?? ?? 45 78 69 66 00 00", "0", "jpg jpeg — JPEG raw or in the JFIF or Exif file format"),
    ("FF 4F FF 51", "0", "jp2 j2k jpf jpm jpg2 j2c jpc jpx mj2 — JPEG 2000 format"),
    ("8B 45 52 02 00 00 00", "0", "toast — Roxio Toast disc image file"),
    ("3C 00 3F 00 78 00 6D 00 6C 00 20", "0 after BOM", "xml ( UTF-16LE ) — eXtensible Markup Language"),
    ("00 3C 00 3F 00 78 00 6D 00 6C 00 20", "0 after BOM", "xml ( UTF-16BE ) — eXtensible Markup Language"),
    ("3C 00 00 00 3F 00 00 00 78 00 00 00 6D 00 00 00 6C 00 00 00 20 00 00 00", "0 after BOM", "xml ( UTF-32LE ) — eXtensible Markup Language"),
    ("00 00 00 3C 00 00 00 3F 00 00 00 78 00 00 00 6D 00 00 00 6C 00 00 00 20", "0 after BOM", "xml ( UTF-32BE ) — eXtensible Markup Language"),
    ("4C 6F A7 94 93 40", "0 after BOM", "xml ( EBCDIC ) — eXtensible Markup Language"),
    ("46 57 53", "0", "swf — Adobe Flash .swf"),
    ("78 5E", "0", "zlib — Best speed (no preset dictionary)"),
    ("78 9C", "0", "zlib — Default Compression (no preset dictionary)"),
    ("78 DA", "0", "zlib — Best Compression (no preset dictionary)"),
    ("78 20", "0", "zlib — No Compression (with preset dictionary)"),
    ("78 7D", "0", "zlib — Best speed (with preset dictionary)"),
    ("78 BB", "0", "zlib — Default Compression (with preset dictionary)"),
    ("78 F9", "0", "zlib — Best Compression (with preset dictionary)"),
    ("58 46 49 52 ?? ?? ?? ?? 4D 44 47 46", "0", "dcr — Adobe Shockwave"),
    ("58 46 49 52 ?? ?? ?? ?? 33 39 56 4D", "0", "dir dxr drx — Macromedia Director file format"),
    ("FF 0A", "0", "jxl — Image encoded in the JPEG XL format"),
)

WILDCARD_TOKENS = {"??", "XX"}


@dataclass(frozen=True, slots=True)
class MagicRule:

    tokens: tuple[int | None, ...]
    offset_rule: str
    description: str
    fixed_bytes: int


def _compile_magic_rules() -> tuple[MagicRule, ...]:
    rules = []
    for pattern, offset_rule, description in MAGIC_SIGNATURES:
        tokens = tuple(
            None if token in WILDCARD_TOKENS else int(token, 16)
            for token in pattern.split()
        )
        rules.append(
            MagicRule(
                tokens=tokens,
                offset_rule=offset_rule,
                description=description,
                fixed_bytes=sum(token is not None for token in tokens),
            )
        )

    return tuple(
        sorted(
            rules,
            key=lambda rule: (
                rule.fixed_bytes
                * (3 if "every 188th byte" in rule.offset_rule.lower() else 1),
                len(rule.tokens),
            ),
            reverse=True,
        )
    )


COMPILED_MAGIC_RULES = _compile_magic_rules()


def _pattern_matches(data: Any, tokens: tuple[int | None, ...], offset: int) -> bool:
    if offset < 0 or offset + len(tokens) > len(data):
        return False
    return all(
        expected is None or data[offset + index] == expected
        for index, expected in enumerate(tokens)
    )


def _candidate_offsets(data: Any, offset_rule: str) -> Sequence[int]:
    rule = offset_rule.lower().replace("–", "-")

    if "end-512" in rule:
        return (len(data) - 512,)
    if "0-65535" in rule:
        return range(0, min(65535, len(data)) + 1)
    if "every 188th byte" in rule:
        return range(0, min(188, len(data)))
    if "0, 512, 1024, 2048" in rule:
        offsets = [0]
        offset = 512
        while offset < len(data):
            offsets.append(offset)
            offset *= 2
        return offsets

    offsets = {
        int(value, 16) if value.lower().startswith("0x") else int(value)
        for value in re.findall(r"0x[0-9a-f]+|\d+", rule)
    }

    if "after bom" in rule:
        for bom in (
            b"\xef\xbb\xbf",
            b"\xff\xfe\x00\x00",
            b"\x00\x00\xfe\xff",
            b"\xff\xfe",
            b"\xfe\xff",
        ):
            if data[: len(bom)] == bom:
                offsets.add(len(bom))

    return tuple(sorted(offsets or {0}))


def _matches_offset_rule(data: Any, rule: MagicRule, offset: int) -> bool:
    if "every 188th byte" in rule.offset_rule.lower():
        return all(
            _pattern_matches(data, rule.tokens, sync_offset)
            for sync_offset in (offset, offset + 188, offset + 376)
        )
    return _pattern_matches(data, rule.tokens, offset)


def _longest_anchor(tokens: tuple[int | None, ...]) -> tuple[bytes, int]:
    best: tuple[int, ...] = ()
    best_start = 0
    current: list[int] = []
    current_start = 0

    for index, token in enumerate(tokens):
        if token is None:
            if len(current) > len(best):
                best = tuple(current)
                best_start = current_start
            current = []
        else:
            if not current:
                current_start = index
            current.append(token)

    if len(current) > len(best):
        best = tuple(current)
        best_start = current_start
    return bytes(best), best_start


def find_magic_match(data: Any, scan_embedded: bool = False) -> Detection | None:
    for rule in COMPILED_MAGIC_RULES:
        # Single-byte signatures are too weak for reliable identification.
        if rule.fixed_bytes < 2:
            continue
        for offset in _candidate_offsets(data, rule.offset_rule):
            if _matches_offset_rule(data, rule, offset):
                return Detection(rule.description, "magic", offset)

    if not scan_embedded:
        return None

    for rule in COMPILED_MAGIC_RULES:
        if rule.fixed_bytes < 4:
            continue

        anchor, anchor_start = _longest_anchor(rule.tokens)
        if not anchor:
            continue

        anchor_offset = data.find(anchor)
        while anchor_offset != -1:
            embedded_offset = anchor_offset - anchor_start
            if _pattern_matches(data, rule.tokens, embedded_offset):
                return Detection(rule.description, "embedded", embedded_offset)
            anchor_offset = data.find(anchor, anchor_offset + 1)

    return None


def check_known_magic_bytes(
    magic_bytes: str | bytes | bytearray,
    scan_embedded: bool = False,
) -> str | None:

    if isinstance(magic_bytes, str):
        try:
            data = bytes.fromhex(magic_bytes)
        except ValueError:
            return None
    else:
        data = magic_bytes

    match = find_magic_match(data, scan_embedded=scan_embedded)
    if match is None:
        return None
    if match.source == "embedded":
        return f"{match.description} (embedded signature at offset {match.offset})"
    return match.description


def check_png_raw_structure(data: Any) -> bool:
    if len(data) < 45 or data[8:16] != b"\x00\x00\x00\x0dIHDR":
        return False

    offset = 8
    found_iend = False
    while offset + 12 <= len(data):
        chunk_length = int.from_bytes(data[offset:offset + 4], "big")
        chunk_end = offset + 12 + chunk_length
        if chunk_end > len(data):
            return False

        chunk_data = data[offset + 4:offset + 8 + chunk_length]
        stored_crc = int.from_bytes(
            data[offset + 8 + chunk_length:chunk_end], "big"
        )
        if zlib.crc32(chunk_data) != stored_crc:
            return False

        if chunk_data[:4] == b"IEND":
            found_iend = chunk_length == 0
            break
        offset = chunk_end

    return found_iend


def check_7z_raw_structure(data: Any) -> bool:
    if len(data) < 32 or data[6] != 0:
        return False

    stored_start_crc = int.from_bytes(data[8:12], "little")
    if zlib.crc32(data[12:32]) != stored_start_crc:
        return False

    next_offset = int.from_bytes(data[12:20], "little")
    next_size = int.from_bytes(data[20:28], "little")
    stored_next_crc = int.from_bytes(data[28:32], "little")
    next_start = 32 + next_offset
    next_end = next_start + next_size

    if next_size == 0 or next_end > len(data):
        return False
    return zlib.crc32(data[next_start:next_end]) == stored_next_crc


def check_zip_raw_structure(data: Any) -> bool:
    eocd_offset = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if eocd_offset < 0 or eocd_offset + 22 > len(data):
        return False

    comment_length = int.from_bytes(data[eocd_offset + 20:eocd_offset + 22], "little")
    central_offset = int.from_bytes(
        data[eocd_offset + 16:eocd_offset + 20], "little"
    )
    central_size = int.from_bytes(
        data[eocd_offset + 12:eocd_offset + 16], "little"
    )
    if eocd_offset + 22 + comment_length != len(data):
        return False

    if central_offset == 0 and central_size == 0:
        return True

    # ZIP64 uses separate records for these values.
    if central_offset == 0xFFFFFFFF or central_size == 0xFFFFFFFF:
        return False

    # Directory offsets in self-extracting archives are relative to the ZIP data.
    archive_start = eocd_offset - central_size - central_offset
    if archive_start < 0:
        return False
    central_start = archive_start + central_offset
    central_end = central_start + central_size
    return (
        central_end == eocd_offset
        and data[central_start:central_start + 4] == b"PK\x01\x02"
    )


def check_pdf_raw_structure(data: Any) -> bool:
    tail = data[-8192:]

    has_object_definition = re.search(
        rb"(?m)(?:^|[\r\n])\s*\d+\s+\d+\s+obj\b", data
    ) is not None
    has_object_end = data.find(b"endobj") >= 0
    has_document_tree = any(
        data.find(keyword) >= 0
        for keyword in (b"/Type", b"/Catalog", b"/Pages", b"/Root")
    )
    has_cross_reference = (
        data.find(b"xref") >= 0
        or data.find(b"/Type/XRef") >= 0
        or data.find(b"/Type /XRef") >= 0
    )
    has_startxref = b"startxref" in tail
    has_eof = b"%%EOF" in tail

    return all(
        (
            has_object_definition,
            has_object_end,
            has_document_tree,
            has_cross_reference,
            has_startxref,
            has_eof,
        )
    )


def check_jpeg_raw_structure(data: Any) -> bool:
    if len(data) < 32:
        return False
    tail = bytes(data[max(0, len(data) - 256) :]).rstrip(b"\x00\r\n\t ")
    if not tail.endswith(b"\xff\xd9"):
        return False
    metadata = bytes(data[:256])
    metadata_offset = max(metadata.find(b"JFIF\x00"), metadata.find(b"Exif\x00\x00"))
    if metadata_offset < 6:
        return False
    segment_length = int.from_bytes(data[metadata_offset - 2:metadata_offset], "big")
    if segment_length < 7 or metadata_offset - 4 + 2 + segment_length > len(data):
        return False

    has_scan = data.find(b"\xff\xda") >= 0
    has_frame = False
    for marker in range(0xC0, 0xD0):
        if marker in (0xC4, 0xC8, 0xCC):
            continue
        offset = data.find(bytes((0xFF, marker)))
        if offset >= 0 and offset + 9 <= len(data):
            frame_length = int.from_bytes(data[offset + 2:offset + 4], "big")
            height = int.from_bytes(data[offset + 5:offset + 7], "big")
            width = int.from_bytes(data[offset + 7:offset + 9], "big")
            if frame_length >= 8 and width and height and offset + 2 + frame_length <= len(data):
                has_frame = True
                break
    return has_scan and has_frame


def check_gif_raw_structure(data: Any) -> bool:

    if len(data) < 14 or data[-1] != 0x3B:
        return False
    width = int.from_bytes(data[6:8], "little")
    height = int.from_bytes(data[8:10], "little")
    packed = data[10]
    if not (width and height) or packed & 0x70 > 0x70:
        return False
    table_size = 3 * (2 ** ((packed & 0x07) + 1)) if packed & 0x80 else 0
    block_start = 13 + table_size
    return block_start < len(data) and data[block_start] in (0x21, 0x2C, 0x3B)


def check_bmp_raw_structure(data: Any) -> bool:

    if len(data) < 30:
        return False
    declared_size = int.from_bytes(data[2:6], "little")
    pixel_offset = int.from_bytes(data[10:14], "little")
    dib_size = int.from_bytes(data[14:18], "little")
    if dib_size not in {12, 16, 40, 52, 56, 64, 108, 124}:
        return False
    if declared_size not in (0, len(data)) or pixel_offset < 14 + dib_size:
        return False
    return pixel_offset <= len(data)


def check_riff_raw_structure(data: Any) -> bool:

    if len(data) < 12 or bytes(data[8:12]) not in {b"WAVE", b"AVI ", b"WEBP"}:
        return False
    declared_end = int.from_bytes(data[4:8], "little") + 8
    if declared_end > len(data) or declared_end < 12:
        return False
    return declared_end == len(data) or len(data) - declared_end <= 1


def check_elf_raw_structure(data: Any) -> bool:

    if len(data) < 52 or data[4] not in (1, 2) or data[5] not in (1, 2):
        return False
    if data[6] != 1:
        return False
    endian = "little" if data[5] == 1 else "big"
    is_64 = data[4] == 2
    header_size = int.from_bytes(data[52:54] if is_64 else data[40:42], endian)
    if header_size != (64 if is_64 else 52):
        return False
    phoff = int.from_bytes(data[32:40] if is_64 else data[28:32], endian)
    shoff = int.from_bytes(data[40:48] if is_64 else data[32:36], endian)
    phentsize = int.from_bytes(data[54:56] if is_64 else data[42:44], endian)
    phnum = int.from_bytes(data[56:58] if is_64 else data[44:46], endian)
    shentsize = int.from_bytes(data[58:60] if is_64 else data[46:48], endian)
    shnum = int.from_bytes(data[60:62] if is_64 else data[48:50], endian)
    return (
        (not phoff or phoff + phentsize * phnum <= len(data))
        and (not shoff or shoff + shentsize * shnum <= len(data))
    )


def check_pe_raw_structure(data: Any) -> bool:

    if len(data) < 0x40:
        return False
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        return False
    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        return False
    sections = int.from_bytes(data[pe_offset + 6:pe_offset + 8], "little")
    optional_size = int.from_bytes(data[pe_offset + 20:pe_offset + 22], "little")
    optional = pe_offset + 24
    if not (1 <= sections <= 96) or optional + optional_size > len(data):
        return False
    return optional_size == 0 or data[optional:optional + 2] in (b"\x0b\x01", b"\x0b\x02")


def check_tar_raw_structure(data: Any) -> bool:

    if len(data) < 512 or data[257:262] != b"ustar":
        return False
    try:
        stored = int(bytes(data[148:156]).strip(b"\x00 ") or b"0", 8)
    except ValueError:
        return False
    header = bytearray(data[:512])
    header[148:156] = b" " * 8
    return sum(header) == stored


def check_svg_raw_structure(data: Any) -> bool:

    head = bytes(data[:65536])
    tail = bytes(data[max(0, len(data) - 65536):])
    root = re.search(
        rb"^\s*(?:<\?xml[^>]*>\s*)?(?:<!--.*?-->\s*)*<svg(?:\s|>)",
        head,
        re.DOTALL,
    )
    return root is not None and re.search(rb"</svg\s*>", tail) is not None


@dataclass(frozen=True, slots=True)
class StructuralRule:
    name: str
    description: str
    validator: Any
    evidence: tuple[str, ...]
    repair_offset: int | None = None
    repair_magic: bytes | None = None


STRUCTURAL_RULES = (
    StructuralRule(
        "png", "PNG image", check_png_raw_structure,
        ("Chunk order, CRC values, and IEND are valid.",),
        0, b"\x89PNG\r\n\x1a\n",
    ),
    StructuralRule(
        "7z", "7-Zip archive", check_7z_raw_structure,
        ("Start and next-header CRC values are valid.",),
        0, b"7z\xbc\xaf'\x1c",
    ),
    StructuralRule(
        "zip", "ZIP archive", check_zip_raw_structure,
        ("The central directory and EOCD record are consistent.",),
        0, b"PK\x03\x04",
    ),
    StructuralRule(
        "pdf", "PDF document", check_pdf_raw_structure,
        ("Objects, cross-reference data, startxref, and EOF are present.",),
        0, b"%PDF-",
    ),
    StructuralRule(
        "jpeg", "JPEG image", check_jpeg_raw_structure,
        ("JFIF/Exif metadata, frame, scan, and EOI are consistent.",),
        0, b"\xff\xd8\xff\xe0",
    ),
    StructuralRule(
        "gif", "GIF image", check_gif_raw_structure,
        ("The screen descriptor, data blocks, and trailer are valid.",),
        0, b"GIF89a",
    ),
    StructuralRule(
        "bmp", "BMP image", check_bmp_raw_structure,
        ("The DIB header, file size, and pixel offset are consistent.",),
        0, b"BM",
    ),
    StructuralRule(
        "riff", "RIFF container", check_riff_raw_structure,
        ("The WAVE, AVI, or WebP type and container size are valid.",),
        0, b"RIFF",
    ),
    StructuralRule(
        "elf", "ELF executable", check_elf_raw_structure,
        ("The ELF header and table boundaries are valid.",),
        0, b"\x7fELF",
    ),
    StructuralRule(
        "pe", "Windows PE executable", check_pe_raw_structure,
        ("The PE, COFF, and optional headers are consistent.",),
        0, b"MZ",
    ),
    StructuralRule(
        "tar", "POSIX tar archive", check_tar_raw_structure,
        ("The ustar signature and header checksum are valid.",),
    ),
    StructuralRule(
        "svg", "SVG image", check_svg_raw_structure,
        ("The document contains a complete SVG root element.",),
    ),
)


def inspect_structures(data: Any) -> tuple[StructureCheck, ...]:

    checks = []
    for rule in STRUCTURAL_RULES:
        try:
            matched = bool(rule.validator(data))
        except (IndexError, OverflowError, TypeError, ValueError, zlib.error):
            matched = False
        if matched:
            repair_magic = rule.repair_magic
            description = rule.description
            if rule.name == "jpeg" and b"Exif\x00\x00" in data[:256]:
                repair_magic = b"\xff\xd8\xff\xe1"
            if rule.name == "zip" and len(data) == 22:
                repair_magic = b"PK\x05\x06"
            if rule.name == "riff" and data[8:12] == b"WEBP":
                description = "WebP image"
            checks.append(
                StructureCheck(
                    name=rule.name,
                    description=description,
                    evidence=rule.evidence,
                    repair_offset=rule.repair_offset,
                    repair_magic=(repair_magic.hex(" ").upper() if repair_magic else None),
                )
            )
    return tuple(checks)


STRUCTURAL_SIGNATURES = tuple(
    (f"{rule.name} — {rule.description}", rule.validator)
    for rule in STRUCTURAL_RULES
)


def find_structural_matches(data: Any) -> tuple[Detection, ...]:

    return tuple(
        Detection(description=f"{check.name} — {check.description}", source="structure")
        for check in inspect_structures(data)
    )


def check_raw_data_signatures(data: Any) -> str | None:

    matches = find_structural_matches(data)
    if not matches:
        return None
    return (
        f"{matches[0].description} recognized from raw internal data "
        "(initial magic bytes may be altered)"
    )


@contextmanager
def mapped_file(file_path: str | Path) -> Iterator[Any]:
    path = Path(file_path)
    with path.open("rb") as file:
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)
        if size == 0:
            yield b""
            return
        with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
            yield data


def identify_file(
    file_path: str | Path,
    scan_embedded: bool = True,
) -> tuple[Detection, ...]:

    with mapped_file(file_path) as data:
        detections: list[Detection] = []
        magic_match = find_magic_match(data)
        if magic_match is not None:
            detections.append(magic_match)

        detections.extend(find_structural_matches(data))

        if not detections and scan_embedded:
            embedded_match = find_magic_match(data, scan_embedded=True)
            if embedded_match is not None:
                detections.append(embedded_match)

    return tuple(detections)


def check_signature(file_path: str | Path) -> str | None:

    detections = identify_file(file_path)
    return detections[0].description if detections else None


EXIF_TAGS = {
    0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model",
    0x0112: "Orientation", 0x011A: "XResolution", 0x011B: "YResolution",
    0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist",
    0x8298: "Copyright", 0x829A: "ExposureTime", 0x829D: "FNumber",
    0x8827: "ISO", 0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
    0x9201: "ShutterSpeedValue", 0x9202: "ApertureValue",
    0x9204: "ExposureBiasValue", 0x9209: "Flash", 0x920A: "FocalLength",
    0x927C: "MakerNote", 0x9286: "UserComment", 0xA001: "ColorSpace",
    0xA002: "PixelXDimension", 0xA003: "PixelYDimension",
    0xA405: "FocalLengthIn35mmFilm", 0xA420: "ImageUniqueID",
    0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef", 0x0006: "GPSAltitude",
    0x001D: "GPSDateStamp",
}
EXIF_POINTERS = {0x8769: "Exif", 0x8825: "GPS", 0xA005: "Interop"}
TIFF_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _format_exif_value(raw: bytes, value_type: int, count: int, endian: str) -> str:

    prefix = "<" if endian == "little" else ">"
    if value_type == 2:
        return raw.rstrip(b"\x00").decode("utf-8", "replace")
    if value_type in (1, 7):
        if count <= 16:
            return " ".join(f"{byte:02X}" for byte in raw)
        return f"<{count} bytes>"
    codes = {3: "H", 4: "I", 9: "i"}
    if value_type in codes:
        values = struct.unpack(prefix + codes[value_type] * count, raw)
        return ", ".join(str(value) for value in values)
    if value_type in (5, 10):
        code = "II" if value_type == 5 else "ii"
        values = []
        for index in range(count):
            numerator, denominator = struct.unpack_from(prefix + code, raw, index * 8)
            values.append(
                f"{numerator}/{denominator} ({numerator / denominator:.6g})"
                if denominator else f"{numerator}/0"
            )
        return ", ".join(values)
    return raw[:32].hex(" ").upper()


def parse_exif_tiff(tiff: bytes) -> dict[str, str]:

    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return {}
    endian = "little" if tiff[:2] == b"II" else "big"
    if int.from_bytes(tiff[2:4], endian) != 42:
        return {}

    metadata: dict[str, str] = {}
    queue: list[tuple[str, int]] = [("IFD0", int.from_bytes(tiff[4:8], endian))]
    visited: set[int] = set()
    while queue and len(visited) < 16:
        group, offset = queue.pop(0)
        if offset in visited or offset < 8 or offset + 2 > len(tiff):
            continue
        visited.add(offset)
        entries = int.from_bytes(tiff[offset:offset + 2], endian)
        if entries > 1024 or offset + 2 + entries * 12 > len(tiff):
            continue

        for index in range(entries):
            entry = offset + 2 + index * 12
            tag = int.from_bytes(tiff[entry:entry + 2], endian)
            value_type = int.from_bytes(tiff[entry + 2:entry + 4], endian)
            count = int.from_bytes(tiff[entry + 4:entry + 8], endian)
            unit_size = TIFF_TYPE_SIZES.get(value_type)
            if unit_size is None or count > 100_000:
                continue
            size = unit_size * count
            if size <= 4:
                raw = tiff[entry + 8:entry + 8 + size]
            else:
                value_offset = int.from_bytes(tiff[entry + 8:entry + 12], endian)
                if value_offset < 0 or value_offset + size > len(tiff):
                    continue
                raw = tiff[value_offset:value_offset + size]

            if tag in EXIF_POINTERS and size <= 4:
                child_offset = int.from_bytes(raw, endian)
                queue.append((EXIF_POINTERS[tag], child_offset))
                continue
            name = EXIF_TAGS.get(tag)
            if name is None:
                continue
            try:
                value = _format_exif_value(raw, value_type, count, endian)
            except (struct.error, UnicodeError, ZeroDivisionError):
                continue
            if value:
                metadata[f"{group}.{name}"] = value

        next_field = offset + 2 + entries * 12
        if group == "IFD0" and next_field + 4 <= len(tiff):
            next_offset = int.from_bytes(tiff[next_field:next_field + 4], endian)
            if next_offset:
                queue.append(("IFD1", next_offset))

    def coordinate(value: str, reference: str) -> float | None:
        fractions = re.findall(r"(-?\d+)/([1-9]\d*)", value)
        if len(fractions) < 3:
            return None
        degrees, minutes, seconds = (
            int(numerator) / int(denominator)
            for numerator, denominator in fractions[:3]
        )
        result = degrees + minutes / 60 + seconds / 3600
        if reference.strip("\x00 ").upper() in {"S", "W"}:
            result = -result
        return result

    latitude = coordinate(
        metadata.get("GPS.GPSLatitude", ""),
        metadata.get("GPS.GPSLatitudeRef", ""),
    )
    longitude = coordinate(
        metadata.get("GPS.GPSLongitude", ""),
        metadata.get("GPS.GPSLongitudeRef", ""),
    )
    if latitude is not None and longitude is not None:
        metadata["GPS.Coordinates"] = f"{latitude:.8f}, {longitude:.8f}"
    return metadata


def extract_exif(file_path: str | Path) -> dict[str, str]:

    with Path(file_path).open("rb") as file:
        data = file.read(32 * 1024 * 1024)
    candidates: list[bytes] = []
    if data[:2] in (b"II", b"MM"):
        candidates.append(data)
    marker = data.find(b"Exif\x00\x00")
    if marker >= 0:
        candidates.append(data[marker + 6:])
    exif_chunk = data.find(b"eXIf")
    if exif_chunk >= 4:
        length = int.from_bytes(data[exif_chunk - 4:exif_chunk], "big")
        candidates.append(data[exif_chunk + 4:exif_chunk + 4 + length])
    for candidate in candidates:
        metadata = parse_exif_tiff(candidate)
        if metadata:
            return metadata
    return {}


IMAGE_FORMATS = {
    "acbm", "anbm", "avif", "bmp", "bpg", "cin", "cr2", "dcr", "dib",
    "dng", "dpx", "drw", "exr", "fax", "faxx", "fits", "flif", "gif",
    "hdr", "heic", "heif", "ico", "icns", "iff", "ilbm", "jpeg", "jpg",
    "jp2", "jxl", "lbm", "lep", "nui", "nup", "pbm", "pcv", "png",
    "psd", "qoi", "svg", "tif", "tiff", "webp", "wmf", "xcf", "yuv",
    "yuvn",
}


def is_recognized_image(
    detections: Sequence[Detection],
    structures: Sequence[StructureCheck],
) -> bool:

    if any(check.name in IMAGE_FORMATS for check in structures):
        return True
    if any(
        set(re.findall(r"[a-z0-9]+", check.description.lower())) & IMAGE_FORMATS
        for check in structures
    ):
        return True
    for detection in detections:
        format_list = detection.description.split("—", 1)[0].lower()
        tokens = set(re.findall(r"[a-z0-9]+", format_list))
        if tokens & IMAGE_FORMATS:
            return True
    return False


def _display_metadata_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    elif value is True:
        rendered = "true"
    elif value is False:
        rendered = "false"
    elif value is None:
        rendered = "null"
    else:
        rendered = str(value)
    rendered = " ".join(rendered.replace("\x00", "").splitlines()).strip()
    return rendered if len(rendered) <= 1000 else f"{rendered[:997]}..."


def add_decimal_gps(metadata: dict[str, str]) -> None:

    def decimal(value: str, reference: str) -> float | None:
        match = re.search(
            r"(-?\d+(?:\.\d+)?)\s*deg\s*(\d+(?:\.\d+)?)'\s*"
            r"(\d+(?:\.\d+)?)",
            value,
        )
        if match is None:
            return None
        degrees, minutes, seconds = (float(part) for part in match.groups())
        result = abs(degrees) + minutes / 60 + seconds / 3600
        if degrees < 0 or reference[:1].upper() in {"S", "W"}:
            result = -result
        return result

    latitude = decimal(
        metadata.get("GPS:GPSLatitude", ""),
        metadata.get("GPS:GPSLatitudeRef", ""),
    )
    longitude = decimal(
        metadata.get("GPS:GPSLongitude", ""),
        metadata.get("GPS:GPSLongitudeRef", ""),
    )
    if latitude is not None and longitude is not None:
        metadata["Derived:GPSCoordinates"] = f"{latitude:.8f}, {longitude:.8f}"


def extract_image_metadata(
    file_path: str | Path,
    detections: Sequence[Detection],
    structures: Sequence[StructureCheck],
) -> dict[str, str]:

    if not is_recognized_image(detections, structures):
        return {}

    exiftool = shutil.which("exiftool")
    if exiftool is not None:
        process: subprocess.CompletedProcess[str] | None = None
        try:
            process = subprocess.run(
                [exiftool, "-j", "-G1", "-s", "-a", "-u", "-ee", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            records = json.loads(process.stdout) if process.stdout.strip() else []
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            records = []
        if process is not None and process.returncode == 0 and records:
            ignored = {
                "SourceFile", "ExifTool:ExifToolVersion", "System:FileName",
                "System:Directory", "System:FileSize", "System:FileModifyDate",
                "System:FileAccessDate", "System:FileInodeChangeDate",
                "System:FilePermissions",
            }
            metadata = {}
            for key, value in records[0].items():
                rendered = _display_metadata_value(value)
                if key not in ignored and rendered:
                    metadata[key] = rendered
            if metadata:
                add_decimal_gps(metadata)
                return metadata

    return extract_exif(file_path)


VALID_REPAIR_MAGICS = {
    "zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    "jpeg": (b"\xff\xd8\xff\xdb", b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1", b"\xff\xd8\xff\xee"),
    "gif": (b"GIF87a", b"GIF89a"),
}


def has_valid_magic(check: StructureCheck, prefix: bytes) -> bool:

    offset = check.repair_offset or 0
    alternatives = VALID_REPAIR_MAGICS.get(
        check.name,
        (bytes.fromhex(check.repair_magic),) if check.repair_magic else (),
    )
    return any(prefix[offset:offset + len(magic)] == magic for magic in alternatives)


def needs_magic_repair(
    file_path: str | Path,
    structures: Sequence[StructureCheck],
) -> bool:

    repairable = [check for check in structures if check.repair_magic is not None]
    if not repairable:
        return False
    preview_size = max(
        (check.repair_offset or 0) + len(bytes.fromhex(check.repair_magic or ""))
        for check in repairable
    )
    with Path(file_path).open("rb") as file:
        prefix = file.read(preview_size)
    return any(not has_valid_magic(check, prefix) for check in repairable)


def repair_magic_bytes(
    file_path: str | Path,
    structures: Sequence[StructureCheck],
    output: str | Path | None = None,
    *,
    overwrite: bool = False,
) -> RepairResult:

    source = Path(file_path).expanduser().resolve()
    candidates = [check for check in structures if check.repair_magic is not None]
    with source.open("rb") as file:
        prefix = file.read(16)
    selected: StructureCheck | None = None
    replacement = b""
    for check in candidates:
        candidate_magic = bytes.fromhex(check.repair_magic or "")
        if not has_valid_magic(check, prefix):
            selected = check
            replacement = candidate_magic
            break
    if selected is None:
        raise ValueError("no damaged, safely repairable magic bytes were found")

    destination = (
        Path(output).expanduser().resolve()
        if output is not None
        else source.with_name(f"{source.stem}.repaired{source.suffix}")
    )
    if destination == source:
        raise ValueError("refusing to overwrite the evidence file; choose another output")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"output already exists: {destination} (use --force)")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    offset = selected.repair_offset or 0
    with destination.open("r+b") as repaired:
        repaired.seek(offset)
        old = repaired.read(len(replacement))
        repaired.seek(offset)
        repaired.write(replacement)

    with mapped_file(destination) as repaired_data:
        rule = next(rule for rule in STRUCTURAL_RULES if rule.name == selected.name)
        if not rule.validator(repaired_data):
            destination.unlink(missing_ok=True)
            raise ValueError("the repaired copy failed structural validation")
    return RepairResult(
        source=str(source), output=str(destination), format=selected.name,
        offset=offset, old_magic=old.hex(" ").upper(),
        new_magic=replacement.hex(" ").upper(),
    )


def analyze_file(
    file_path: str | Path,
    expected_hash: str | None = None,
    algorithms: Sequence[str] | None = None,
    scan_embedded: bool = True,
) -> AnalysisReport:

    path = Path(file_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"file not found: {path}")

    if algorithms is not None:
        selected_algorithms = algorithms
    elif expected_hash is not None:
        selected_algorithms = ALL_ALGORITHMS
    else:
        selected_algorithms = COMMON_ALGORITHMS
    hash_report = calculate_hashes(path, algorithms=selected_algorithms)
    matches = (
        find_hash_matches(expected_hash, hash_report.digests)
        if expected_hash is not None
        else ()
    )
    with mapped_file(path) as data:
        structures = inspect_structures(data)
    detections = identify_file(path, scan_embedded=scan_embedded)

    return AnalysisReport(
        path=str(path.resolve()),
        size=path.stat().st_size,
        magic_preview=read_magic_preview(path).hex(" ").upper(),
        hashes=hash_report.digests,
        unsupported_hashes=hash_report.unsupported,
        hash_matches=matches,
        detections=detections,
        structures=structures,
        metadata=extract_image_metadata(path, detections, structures),
    )


ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "green": "\033[92m",
    "red": "\033[31m",
    "blue": "\033[34m",
    "cyan": "\033[96m",
    "magenta": "\033[95m",
    "yellow": "\033[33m",
    "white": "\033[37m",
}


def paint(text: str, color: str, enabled: bool) -> str:

    if not enabled:
        return text
    return f"{ANSI[color]}{text}{ANSI['reset']}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "CTF file inspector: hashes, magic bytes, internal structures, "
            "embedded image metadata, and non-destructive signature repair."
        )
    )
    parser.add_argument("file", type=Path, help="file to analyze")
    parser.add_argument(
        "-e",
        "--expect",
        metavar="HASH",
        help="expected hexadecimal digest",
    )
    parser.add_argument(
        "-a",
        "--algorithm",
        action="append",
        dest="algorithms",
        metavar="NAME",
        help="hash algorithm to calculate; repeat the option for multiple values",
    )
    parser.add_argument(
        "--all-hashes",
        action="store_true",
        help="print every calculated digest instead of the common set",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "run the complete workflow: all hashes, embedded scan, structural "
            "checks, image metadata, and automatic repair when needed"
        ),
    )
    parser.add_argument(
        "--no-embedded",
        action="store_true",
        help="disable the fallback scan for embedded signatures",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a machine-readable JSON report",
    )
    parser.add_argument(
        "--repair", action="store_true",
        help="repair damaged magic bytes in a new copy using structural evidence",
    )
    parser.add_argument(
        "-o", "--output", type=Path,
        help="destination for --repair (default: NAME.repaired.EXT)",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="allow --repair to replace an existing output copy",
    )
    parser.add_argument(
        "--color", choices=("auto", "always", "never"), default="auto",
        help="color mode (default: auto)",
    )
    parser.add_argument(
        "--no-color", action="store_true", help=argparse.SUPPRESS,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def print_section(title: str, colors: bool) -> None:
    print()
    rule = "━" * max(2, 58 - len(title))
    print(paint(f"━━ {title.upper()} {rule}", "cyan", colors))


def print_report(
    report: AnalysisReport,
    *,
    expected_hash: str | None,
    all_hashes: bool,
    colors: bool,
) -> None:
    print(paint("Magic Wrapper — CTF File Inspector", "magenta", colors))
    print_section("File", colors)
    print(paint(f"[•] Path  : {report.path}", "white", colors))
    print(paint(f"[•] Size  : {report.size:,} bytes", "white", colors))
    preview = report.magic_preview or "<empty file>"
    print(paint(f"[•] Header: {preview}", "blue", colors))

    print_section("Hash", colors)
    if expected_hash is not None:
        if report.hash_matches:
            algorithms = ", ".join(report.hash_matches)
            print(paint(f"[OK] Hash matched: {algorithms}", "green", colors))
        else:
            print(paint("[NO] Expected hash did not match", "red", colors))

    visible_hashes = (
        report.hashes
        if all_hashes
        else {
            name: digest
            for name, digest in report.hashes.items()
            if name in {"md5", "sha1", "sha256", "sha512"}
        }
    )
    for algorithm, digest in visible_hashes.items():
        print(paint(f"[=] {algorithm:<10} {digest}", "blue", colors))

    if report.unsupported_hashes:
        unavailable = ", ".join(report.unsupported_hashes)
        print(paint(f"[!] Unsupported hashes: {unavailable}", "yellow", colors))

    print_section("Identification", colors)
    direct_detections = tuple(
        detection for detection in report.detections if detection.source != "structure"
    )
    if direct_detections:
        for detection in direct_detections:
            offset = (
                f" @ offset {detection.offset}"
                if detection.offset is not None
                else ""
            )
            print(
                paint(
                    f"[OK] {detection.source.title()}{offset}: {detection.description}",
                    "green",
                    colors,
                )
            )
    else:
        print(paint("[!] No reliable direct signature found.", "yellow", colors))

    print_section("File structure", colors)
    if report.structures:
        preview_bytes = bytes.fromhex(report.magic_preview) if report.magic_preview else b""
        for check in report.structures:
            print(paint(f"[OK] {check.name.upper()} — {check.description}", "green", colors))
            for evidence in check.evidence:
                print(paint(f"     {evidence}", "green", colors))
            if check.repair_magic:
                if not has_valid_magic(check, preview_bytes):
                    print(paint(
                        f"     Damaged signature; expected {check.repair_magic}.",
                        "yellow", colors,
                    ))
    else:
        print(paint("[—] No supported file structure was validated.", "dim", colors))

    print_section("Image metadata", colors)
    if report.metadata:
        for name, value in report.metadata.items():
            separator = ":" if ":" in name else "."
            group, found, tag = name.partition(separator)
            if not found:
                group, tag = "Metadata", name
            color = "yellow" if "gps" in name.lower() else "magenta"
            print(paint(f"[{group}] {tag:<28} {value}", color, colors))
    else:
        print(paint("[—] No embedded image metadata found.", "dim", colors))


def print_repair(result: RepairResult, colors: bool) -> None:
    print_section("Repair", colors)
    print(paint(f"[OK] Format: {result.format.upper()}", "green", colors))
    print(paint(f"[OK] Output: {result.output}", "green", colors))
    print(paint(
        f"[→] Offset {result.offset}: {result.old_magic or '<vuoto>'} → {result.new_magic}",
        "yellow", colors,
    ))
    print(paint("[i] The original file was not modified.", "blue", colors))


def print_repair_not_needed(colors: bool) -> None:
    print_section("Repair", colors)
    print(paint("[OK] No signature repair is needed.", "green", colors))


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if (args.output is not None or args.force) and not (args.repair or args.all):
        parser.error("--output and --force require --repair or --all")
    colors = not args.json and not args.no_color and (
        args.color == "always" or (args.color == "auto" and sys.stdout.isatty())
    )
    if args.all:
        algorithms = ALL_ALGORITHMS
    elif args.algorithms:
        algorithms = tuple(args.algorithms)
    elif args.all_hashes or args.expect is not None:
        algorithms = ALL_ALGORITHMS
    else:
        algorithms = COMMON_ALGORITHMS

    try:
        report = analyze_file(
            args.file,
            expected_hash=args.expect,
            algorithms=algorithms,
            scan_embedded=args.all or not args.no_embedded,
        )
        run_repair = args.repair or (
            args.all and needs_magic_repair(args.file, report.structures)
        )
        repair = (
            repair_magic_bytes(
                args.file, report.structures, args.output, overwrite=args.force
            )
            if run_repair else None
        )
    except (OSError, ValueError) as error:
        print(paint(f"[ERROR] {error}", "red", colors), file=sys.stderr)
        return 2

    if args.json:
        payload = asdict(report)
        payload["repair"] = asdict(repair) if repair else None
        payload["all_mode"] = args.all
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_report(
            report,
            expected_hash=args.expect,
            all_hashes=args.all_hashes or args.all,
            colors=colors,
        )
        if repair is not None:
            print_repair(repair, colors)
        elif args.all:
            print_repair_not_needed(colors)

    return 1 if args.expect is not None and not report.hash_matches else 0


if __name__ == "__main__":
    raise SystemExit(main())
