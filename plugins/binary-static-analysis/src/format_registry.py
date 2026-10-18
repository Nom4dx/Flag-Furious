"""Declarative binary signature registry.

Entries describe candidate starts; validation is delegated to structural parsers.
A signature hit alone never becomes a validated format. New formats can be added
by appending a ``FormatSignature`` and a validator in ``magic_detection``.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class FormatSignature:
    """One byte marker, relative offset and validator name."""

    name: str
    value: bytes
    validator: str
    relative_offset: int = 0
    executable: bool = False
    firmware: bool = False
    filesystem: bool = False


SIGNATURES = (
    FormatSignature("elf", b"\x7fELF", "elf", executable=True),
    FormatSignature("dos_pe", b"MZ", "pe", executable=True),
    FormatSignature("macho32_be", b"\xfe\xed\xfa\xce", "macho", executable=True),
    FormatSignature("macho32_le", b"\xce\xfa\xed\xfe", "macho", executable=True),
    FormatSignature("macho64_be", b"\xfe\xed\xfa\xcf", "macho", executable=True),
    FormatSignature("macho64_le", b"\xcf\xfa\xed\xfe", "macho", executable=True),
    FormatSignature("macho_fat", b"\xca\xfe\xba\xbe", "macho", executable=True),
    FormatSignature("macho_fat64", b"\xca\xfe\xba\xbf", "macho", executable=True),
    FormatSignature("java_class", b"\xca\xfe\xba\xbe", "java", executable=True),
    FormatSignature("wasm", b"\x00asm", "wasm", executable=True),
    FormatSignature("uefi_fv", b"_FVH", "uefi", relative_offset=40, firmware=True),
    FormatSignature("uboot_legacy", b"\x27\x05\x19\x56", "uboot", firmware=True),
    FormatSignature("fdt_fit", b"\xd0\x0d\xfe\xed", "fdt", firmware=True),
    FormatSignature("android_boot", b"ANDROID!", "android_boot", firmware=True),
    FormatSignature("android_vendor_boot", b"VNDRBOOT", "android_vendor", firmware=True),
    FormatSignature("trx", b"HDR0", "trx", firmware=True),
    FormatSignature("squashfs_le", b"hsqs", "squashfs", firmware=True, filesystem=True),
    FormatSignature("squashfs_be", b"sqsh", "squashfs", firmware=True, filesystem=True),
    FormatSignature("cramfs_le", b"E=\xcd(", "cramfs", firmware=True, filesystem=True),
    FormatSignature("cramfs_be", b"(\xcd=E", "cramfs", firmware=True, filesystem=True),
    FormatSignature("ubi", b"UBI#", "ubi", firmware=True, filesystem=True),
    FormatSignature("ubifs", b"\x31\x18\x10\x06", "ubifs", firmware=True, filesystem=True),
    FormatSignature("erofs", b"\xe2\xe1\xf5\xe0", "erofs", relative_offset=1024, filesystem=True),
    FormatSignature("ext2_ext3_ext4", b"\x53\xef", "ext", relative_offset=1080, filesystem=True),
    FormatSignature("ntfs", b"NTFS    ", "ntfs", relative_offset=3, filesystem=True),
    FormatSignature("fat16", b"FAT16   ", "fat", relative_offset=54, filesystem=True),
    FormatSignature("fat32", b"FAT32   ", "fat", relative_offset=82, filesystem=True),
    FormatSignature("hfs_plus", b"H+", "hfs", relative_offset=1024, filesystem=True),
    FormatSignature("apfs", b"NXSB", "apfs", relative_offset=32, filesystem=True),
    FormatSignature("cpio_newc", b"070701", "cpio", firmware=True),
    FormatSignature("cpio_crc", b"070702", "cpio", firmware=True),
    FormatSignature("gzip", b"\x1f\x8b\x08", "gzip"),
    FormatSignature("xz", b"\xfd7zXZ\x00", "xz"),
    FormatSignature("bzip2", b"BZh", "bzip2"),
    FormatSignature("zstd", b"\x28\xb5\x2f\xfd", "zstd"),
    FormatSignature("lz4", b"\x04\x22\x4d\x18", "lz4"),
    FormatSignature("zip", b"PK\x03\x04", "zip"),
    FormatSignature("7z", b"7z\xbc\xaf'\x1c", "7z"),
    FormatSignature("rar4", b"Rar!\x1a\x07\x00", "rar"),
    FormatSignature("rar5", b"Rar!\x1a\x07\x01\x00", "rar"),
    FormatSignature("png", b"\x89PNG\r\n\x1a\n", "png"),
    FormatSignature("jpeg", b"\xff\xd8\xff", "jpeg"),
    FormatSignature("gif87a", b"GIF87a", "gif"),
    FormatSignature("gif89a", b"GIF89a", "gif"),
    FormatSignature("bmp", b"BM", "bmp"),
    FormatSignature("tiff_le", b"II\x2a\x00", "tiff"),
    FormatSignature("tiff_be", b"MM\x00\x2a", "tiff"),
    FormatSignature("pdf", b"%PDF-", "pdf"),
    FormatSignature("sqlite", b"SQLite format 3\x00", "sqlite"),
    FormatSignature("ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    FormatSignature("pcap_le", b"\xd4\xc3\xb2\xa1", "pcap"),
    FormatSignature("pcap_be", b"\xa1\xb2\xc3\xd4", "pcap"),
    FormatSignature("pcapng", b"\x0a\x0d\x0d\x0a", "pcapng"),
    FormatSignature("riff", b"RIFF", "riff"),
    FormatSignature("tar", b"ustar", "tar", relative_offset=257),
    FormatSignature("iso9660", b"CD001", "iso9660", relative_offset=32769, filesystem=True),
)

MAX_SIGNATURE = max(len(item.value) + item.relative_offset for item in SIGNATURES)
