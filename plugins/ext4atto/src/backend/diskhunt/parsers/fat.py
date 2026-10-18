import struct


def parse_fat_boot(data: bytes) -> dict:
    if len(data) < 512 or data[510:512] != b"\x55\xaa": raise ValueError("invalid FAT boot sector")
    bps, spc, reserved, fats = struct.unpack_from("<HBHB", data, 11)
    root_entries, total16, fat16 = struct.unpack_from("<HHH", data, 17)
    total32 = struct.unpack_from("<I", data, 32)[0]
    fat32 = struct.unpack_from("<I", data, 36)[0]
    total = total16 or total32; fat_size = fat16 or fat32
    root_sectors = ((root_entries * 32) + bps - 1) // bps
    data_sectors = total - (reserved + fats * fat_size + root_sectors)
    clusters = data_sectors // spc if spc else 0
    kind = "FAT12" if clusters < 4085 else "FAT16" if clusters < 65525 else "FAT32"
    label_at = 71 if kind == "FAT32" else 43
    return {"type": kind, "bytes_per_sector": bps, "sectors_per_cluster": spc,
            "cluster_size": bps * spc, "reserved_sectors": reserved, "fat_count": fats,
            "fat_size_sectors": fat_size, "root_entries": root_entries, "total_sectors": total,
            "volume_label": data[label_at:label_at+11].decode("ascii", "replace").strip(),
            "serial": f"{struct.unpack_from('<I', data, label_at-4)[0]:08X}"}

