# Formats and offsets

The detector recognizes RAW/split images, VHD footer/header cookies, the VHDX
file identifier, MBR, GPT and BitLocker/FVE. BitLocker is confirmed by the OEM
identifier `-FVE-FS-` at VBR offset 3 plus a plausible BIOS parameter block.
The common metadata-offset slots at VBR offsets `0xb0`, `0xb8` and `0xc0` are
treated as relative offsets and bounded by the declared volume. They are evidence
locations, not decoded secrets. NTFS, FAT, exFAT and ext are identified after a
successful decrypted export.

VHD/VHDX require `qemu-img` conversion to a separate RAW file. The conversion is
skipped when its virtual size exceeds the workspace budget.
