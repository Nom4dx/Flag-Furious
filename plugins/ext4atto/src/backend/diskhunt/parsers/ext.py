import struct


def parse_ext_superblock(data: bytes) -> dict:
    if len(data) < 1024 or data[56:58] != b"\x53\xef": raise ValueError("invalid ext superblock")
    inodes, blocks, free_blocks, free_inodes = struct.unpack_from("<IIII", data, 0)
    log_block = struct.unpack_from("<I", data, 24)[0]
    state, errors = struct.unpack_from("<HH", data, 58)
    compat, incompat, ro_compat = struct.unpack_from("<III", data, 92)
    return {"type": "ext4" if incompat & 0x40 else "ext3" if compat & 0x4 else "ext2",
            "inodes": inodes, "blocks": blocks, "free_blocks": free_blocks, "free_inodes": free_inodes,
            "block_size": 1024 << log_block, "blocks_per_group": struct.unpack_from("<I", data, 32)[0],
            "inodes_per_group": struct.unpack_from("<I", data, 40)[0], "inode_size": struct.unpack_from("<H", data, 88)[0],
            "state": state, "errors_policy": errors, "features": {"compat": compat, "incompat": incompat, "ro_compat": ro_compat},
            "uuid": data[104:120].hex(), "volume_label": data[120:136].decode("utf-8", "replace").rstrip("\x00")}
