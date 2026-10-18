"""Validation of embedded filesystem and container superblocks.

Only stable header fields and physical bounds are parsed internally. APFS, HFS,
YAFFS and full inode traversal require optional specialist tools and are reported
as unsupported rather than guessed.
"""

from pathlib import Path
import struct


def analyze(path:Path,candidate:dict)->dict:
    """Validate a SquashFS, CramFS, UBI/UBIFS, EROFS or ISO candidate."""
    offset=candidate["offset"];kind=candidate["validator"];physical=path.stat().st_size
    with path.open("rb") as source:source.seek(offset);head=source.read(2048)
    if kind=="squashfs":
        endian="<" if head[:4]==b"hsqs" else ">";inode_count=struct.unpack_from(endian+"I",head,4)[0];block_size=struct.unpack_from(endian+"I",head,12)[0];bytes_used=struct.unpack_from(endian+"Q",head,40)[0]
        if len(head)<96 or block_size<4096 or block_size>1024*1024 or bytes_used<96 or offset+bytes_used>physical:raise ValueError("Superblock SquashFS incoerente")
        return _result("squashfs",offset,bytes_used,{"inode_count":inode_count,"block_size":block_size,"bytes_used":bytes_used,"endian":"little" if endian=="<" else "big"},.99)
    if kind=="cramfs":
        # CramFS stores 0x28cd3d45 in the byte order used by the image.
        endian="<" if head[:4]==b"E=\xcd(" else ">";length=struct.unpack_from(endian+"I",head,4)[0]
        if length<64 or offset+length>physical:raise ValueError("Dimensione CramFS incoerente")
        return _result("cramfs",offset,length,{"size":length,"endian":"little" if endian=="<" else "big"},.96)
    if kind=="erofs":
        start=offset-1024
        if start<0 or len(head)<64:raise ValueError("Superblock EROFS non valido")
        return _result("erofs",start,physical-start,{"superblock_offset":offset},.82)
    if kind in {"ubi","ubifs"}:
        if len(head)<64:raise ValueError("Header flash filesystem troncato")
        return _result(kind,offset,physical-offset,{"header_magic":head[:4].hex(),"boundary":"physical_eof_fallback"},.76)
    if kind=="iso9660":
        start=offset;descriptor=offset+32768
        if descriptor+2048>physical:raise ValueError("Volume descriptor ISO fuori EOF")
        with path.open("rb") as source:source.seek(descriptor);block=source.read(2048)
        if block[1:6]!=b"CD001":raise ValueError("Descriptor ISO non valido")
        blocks=struct.unpack_from("<I",block,80)[0];block_size=struct.unpack_from("<H",block,128)[0];length=blocks*block_size
        if block_size not in (512,1024,2048,4096) or length<=0 or start+length>physical:raise ValueError("Dimensioni ISO incoerenti")
        return _result("iso9660",start,length,{"volume_blocks":blocks,"block_size":block_size,"volume_id":block[40:72].decode("ascii","replace").strip()},.98)
    if kind=="ext":
        if len(head)<1128 or head[1080:1082]!=b"\x53\xef":raise ValueError("Superblock ext assente")
        blocks=struct.unpack_from("<I",head,1028)[0];log_block=struct.unpack_from("<I",head,1048)[0];block_size=1024<<log_block
        length=blocks*block_size
        if block_size not in (1024,2048,4096,8192,16384,32768,65536) or length<=0 or offset+length>physical:raise ValueError("Dimensioni ext incoerenti")
        features=struct.unpack_from("<III",head,1116)
        family="ext4" if features[1] or features[2] else "ext2/ext3"
        return _result(family,offset,length,{"block_count":blocks,"block_size":block_size,"feature_compat":hex(features[0]),"feature_incompat":hex(features[1]),"feature_ro_compat":hex(features[2])},.98)
    if kind in {"ntfs","fat"}:
        if len(head)<512 or head[510:512]!=b"\x55\xaa":raise ValueError("Boot sector senza firma finale")
        bytes_per_sector=struct.unpack_from("<H",head,11)[0];sectors_per_cluster=head[13]
        if bytes_per_sector not in (512,1024,2048,4096) or sectors_per_cluster==0 or sectors_per_cluster&(sectors_per_cluster-1):raise ValueError("Geometria filesystem non plausibile")
        if kind=="ntfs":
            if head[3:11]!=b"NTFS    ":raise ValueError("OEM NTFS assente")
            sectors=struct.unpack_from("<Q",head,40)[0]
        else:
            sectors=struct.unpack_from("<H",head,19)[0] or struct.unpack_from("<I",head,32)[0]
        length=sectors*bytes_per_sector
        if length<=0 or offset+length>physical:raise ValueError("Dimensione filesystem oltre EOF")
        return _result(kind,offset,length,{"bytes_per_sector":bytes_per_sector,"sectors_per_cluster":sectors_per_cluster,"sector_count":sectors},.97)
    if kind=="hfs":
        if len(head)<1100 or head[1024:1026] not in (b"H+",b"HX"):raise ValueError("Volume header HFS+ assente")
        block_size=struct.unpack_from(">I",head,1064)[0];blocks=struct.unpack_from(">I",head,1068)[0];length=block_size*blocks
        if block_size<512 or block_size&(block_size-1) or length<=0 or offset+length>physical:raise ValueError("Dimensioni HFS+ incoerenti")
        return _result("hfs_plus",offset,length,{"block_size":block_size,"block_count":blocks},.95)
    if kind=="apfs":
        if len(head)<80 or head[32:36]!=b"NXSB":raise ValueError("NX superblock APFS assente")
        block_size=struct.unpack_from("<I",head,36)[0];blocks=struct.unpack_from("<Q",head,40)[0];length=block_size*blocks
        if block_size not in (4096,8192,16384,32768,65536) or length<=0 or offset+length>physical:raise ValueError("Dimensioni APFS incoerenti")
        return _result("apfs",offset,length,{"block_size":block_size,"block_count":blocks,"container_uuid":head[72:88].hex()},.93)
    raise ValueError("File system non gestito")


def _result(kind,offset,length,header,confidence):return {"format":kind,"validated":True,"start_offset":offset,"end_offset":offset+length,"length":length,"header":header,"confidence":confidence,"filesystem":True}
