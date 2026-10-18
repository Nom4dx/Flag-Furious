# Formats and offsets

The detector recognizes RAW/split images, VHD footer/header cookies, the VHDX
file identifier, MBR, GPT and BitLocker/FVE. BitLocker is confirmed by the OEM
identifier `-FVE-FS-` at VBR offset 3 plus a plausible BIOS parameter block.
The common metadata-offset slots at VBR offsets `0xb0`, `0xb8` and `0xc0` are
treated as relative offsets and bounded by the declared volume. They are evidence
locations, not decoded secrets. NTFS, FAT, exFAT and ext are identified after a
successful decrypted export.

Numbered RAW segments must form one unambiguous, regular-file sequence from
`.001` with no later segment after a gap. The family inventory is capped at
10,000 segment files and 100,000 directory entries. Merge output is temporary
until every segment is copied within budget and unchanged during its read; a
gap, symlink, oversized family or read error leaves the source unmerged and
marks coverage incomplete.

VHD/VHDX require `qemu-img` inspection and conversion to a separate RAW file.
The adapter validates the reported internal format (`vpc` for VHD and
`vhdx` for VHDX), rejects external backing files and refuses truncated
inspection. Conversion output is written to a temporary file, bounded by the
workspace limit, checked against the reported virtual size and promoted
atomically only when complete.
