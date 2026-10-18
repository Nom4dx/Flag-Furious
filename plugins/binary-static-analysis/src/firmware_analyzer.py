"""Bounded parsers for common firmware and boot-image headers.

U-Boot, FIT/device-tree and Android boot sizes are validated against physical
bounds. Vendor-specific payloads are inventoried but never decompressed or run
unless a separate safe extractor validates them.
"""

from pathlib import Path
import struct
import zlib


def analyze(path:Path,candidate:dict)->dict:
    """Validate one firmware candidate and return header, end and checksums."""
    offset=candidate["offset"];size=path.stat().st_size
    with path.open("rb") as source:source.seek(offset);head=source.read(4096)
    kind=candidate["validator"]
    if kind=="uboot":
        if len(head)<64 or head[:4]!=b"\x27\x05\x19\x56":raise ValueError("Header U-Boot troncato")
        header_crc,timestamp,payload_size,load,entry,data_crc,os_id,arch,image_type,compression=struct.unpack_from(">IIIIII4B",head,4)
        end=offset+64+payload_size
        if end>size:raise ValueError("Payload U-Boot oltre EOF")
        crc_header=bytearray(head[:64]);crc_header[4:8]=b"\0"*4
        header_ok=zlib.crc32(crc_header)&0xffffffff==header_crc
        return {"format":"uboot_legacy","validated":header_ok,"start_offset":offset,"end_offset":end,"length":end-offset,"header":{"timestamp":timestamp,"payload_size":payload_size,"load_address":load,"entrypoint":entry,"data_crc32":f"{data_crc:08x}","os":os_id,"architecture":arch,"image_type":image_type,"compression":compression,"header_crc_valid":header_ok},"confidence":.99 if header_ok else .72}
    if kind=="fdt":
        if len(head)<40 or head[:4]!=b"\xd0\x0d\xfe\xed":raise ValueError("Header FDT troncato")
        total,off_struct,off_strings,off_reserve,version,last_comp,boot_cpu,size_strings,size_struct=struct.unpack_from(">9I",head,4)
        if total<40 or offset+total>size or max(off_struct+size_struct,off_strings+size_strings,off_reserve)>total:raise ValueError("Offset FDT/FIT incoerenti")
        return {"format":"fdt_fit","validated":True,"start_offset":offset,"end_offset":offset+total,"length":total,"header":{"total_size":total,"structure_offset":off_struct,"strings_offset":off_strings,"reserve_offset":off_reserve,"version":version,"last_compatible_version":last_comp,"boot_cpu":boot_cpu,"strings_size":size_strings,"structure_size":size_struct},"confidence":.99}
    if kind in {"android_boot","android_vendor"}:
        magic=b"ANDROID!" if kind=="android_boot" else b"VNDRBOOT"
        if not head.startswith(magic) or len(head)<44:raise ValueError("Header Android boot troncato")
        kernel_size=struct.unpack_from("<I",head,8)[0];ramdisk_size=struct.unpack_from("<I",head,16)[0];page_size=struct.unpack_from("<I",head,36)[0] if kind=="android_boot" else 4096
        if page_size<512 or page_size>65536 or page_size&(page_size-1):raise ValueError("Page size Android non valida")
        aligned=lambda value:((value+page_size-1)//page_size)*page_size
        total=page_size+aligned(kernel_size)+aligned(ramdisk_size)
        if offset+total>size:raise ValueError("Componenti Android boot oltre EOF")
        return {"format":kind,"validated":True,"start_offset":offset,"end_offset":offset+total,"length":total,"header":{"kernel_size":kernel_size,"ramdisk_size":ramdisk_size,"page_size":page_size},"confidence":.95}
    if kind=="trx":
        if len(head)<28 or head[:4]!=b"HDR0":raise ValueError("Header TRX troncato")
        total,crc,flags_version,*partitions=struct.unpack_from("<III3I",head,4)
        if total<28 or offset+total>size:raise ValueError("Dimensione TRX incoerente")
        # TRX CRC covers bytes after the CRC field; vendor variants may differ,
        # therefore failure lowers confidence without silently validating it.
        with path.open("rb") as source:source.seek(offset+12);body=source.read(total-12)
        crc_ok=(zlib.crc32(body)&0xffffffff)==crc
        if not crc_ok:raise ValueError("CRC TRX non valido")
        return {"format":"trx","validated":True,"start_offset":offset,"end_offset":offset+total,"length":total,"header":{"length":total,"crc32":f"{crc:08x}","flags_version":hex(flags_version),"partition_offsets":partitions,"crc_valid":True},"confidence":.98}
    raise ValueError("Formato firmware non gestito")
