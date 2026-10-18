"""UEFI firmware-volume header validation.

The ``_FVH`` marker occurs at offset 40 within a firmware-volume header. Length,
header length, signature and 16-bit checksum are validated. FFS iteration remains
an optional external-tool task because compression GUID semantics are extensive.
"""

from pathlib import Path
import struct


def analyze(path:Path,offset:int)->dict:
    """Validate one UEFI FV range and return passive GUID/header metadata."""
    size=path.stat().st_size
    with path.open("rb") as source:source.seek(offset);head=source.read(96)
    if len(head)<56 or head[40:44]!=b"_FVH":raise ValueError("Firma UEFI FV assente")
    volume_length=struct.unpack_from("<Q",head,32)[0];attributes=struct.unpack_from("<I",head,44)[0];header_length=struct.unpack_from("<H",head,48)[0]
    if volume_length<header_length or header_length<56 or offset+volume_length>size:raise ValueError("Limiti UEFI FV incoerenti")
    with path.open("rb") as source:source.seek(offset);header=source.read(header_length)
    checksum=sum(struct.unpack("<"+"H"*(len(header)//2),header[:len(header)//2*2]))&0xffff
    return {"format":"uefi_firmware_volume","validated":checksum==0,"start_offset":offset,"end_offset":offset+volume_length,"length":volume_length,"header":{"filesystem_guid":head[16:32].hex(),"volume_length":volume_length,"attributes":hex(attributes),"header_length":header_length,"checksum_valid":checksum==0},"confidence":.99 if checksum==0 else .72}
