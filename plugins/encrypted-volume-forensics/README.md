# Encrypted Volume Forensics

`encrypted-volume-forensics` performs offline, read-only triage of disk images,
partitions and encrypted volumes. BitLocker/FVE is the priority format. The
plugin detects a volume independently of its extension, parses its partition
context, inventories FVE metadata and key protectors, extracts password hashes
when the local tool is available, creates a manual request for `bruteforce`, and
can export a decrypted filesystem only after an explicit credential action.

For memory-assisted cases such as picoCTF 2025 Bitlocker-2, `.mem`, `.dmp`,
`.vmem` and `.lime` inputs are scanned for the documented Windows `None`,
`Cngb` and `FVEc` BitLocker pool layouts. Candidates become 66-byte Dislocker
FVEK artifacts. A pool hit is never called a valid key until the operator links
the encrypted volume and candidate to **Sblocco BitLocker read-only** and the
decrypted filesystem passes structural validation.
An exported volume records `key_verified` separately from `password_verified`;
using an FVEK cannot be reported as password verification. Incomplete libbde
exports are deleted before the attempt returns.

## Analysis pipeline

1. Calculate full MD5, SHA-1 and SHA-256 over the original.
2. Identify RAW, split RAW, VHD, VHDX or BEK input.
3. Parse MBR or GPT and verify the primary and backup GPT structures.
4. Search partition starts and a bounded byte view for the `-FVE-FS-` OEM ID.
5. Parse public BitLocker metadata with `pybde`; retain a conservative boot
   record fallback when the binding is absent or metadata are damaged.
6. Compare bounded pages at the three metadata offsets declared by the VBR.
7. Inventory key-protector type and GUID without key material.
8. Run `bitlocker2john` on a bounded partition copy when necessary and store the
   resulting `$bitlocker$` lines as derived artifacts.
9. Emit an unlock request for the connector-only `bruteforce` plugin.
10. On explicit `unlock`, verify a user password or numerical recovery password
    with libbde or Dislocker and export a separate decrypted volume.
11. Detect the unlocked filesystem and use pytsk3 to inventory and selectively
    extract files under count, size and output budgets.
12. Search flags in accessible sources and build a provenance graph and timeline.

Automatic analysis never starts John, Hashcat or a wordlist attack. Those tools
require an explicit connector workflow and confirmation. It also never asks the
host TPM for secrets.

## Inputs and configuration

Supported inputs include `.raw`, `.img`, `.dd`, `.001`, `.vhd`, `.vhdx`, `.bin`,
`.bde`, `.fve` and `.bek`. Content determines compatibility. VHD/VHDX conversion
uses `qemu-img` only when the reported virtual size fits the workspace limit.

Plugin options are nested below `encrypted-volume-forensics`:

```json
{
  "extract_hash": true,
  "unlock": true,
  "password": "ephemeral value",
  "recovery_key": "563200-...",
  "unlock_engine": "libbde",
  "max_unlocked_bytes": 536870912,
  "filesystem": {
    "extract": true,
    "max_files": 5000,
    "max_extract_files": 64,
    "max_single_file": 33554432,
    "extensions": [".txt", ".pdf", ".png"],
    "name_contains": "flag"
  }
}
```

The password fields must come from the connector secret form. They are consumed
in memory and omitted from results, reports and command audit.

## Dependencies

The internal RAW/MBR/GPT/FVE detector uses the Python standard library. Optional
Python bindings are `pybde` for BitLocker and `pytsk3` for filesystem access.
Optional binaries are Dislocker, `bitlocker2john`, John, Hashcat, `qemu-img` and
Sleuth Kit. Missing tools produce warnings and preserve metadata-only results.
Any coverage warning from hash extraction, filesystem recovery or flag scanning
keeps the result `partial`. Hash extraction is reported as `skipped` when disabled
explicitly by the case options.
Runtime scan, output and workspace budgets are clamped to documented ceilings;
malformed values fall back to defaults, while a zero byte budget produces a
partial scan instead of an unbounded read.

The filesystem walk uses a deque and stops as soon as `max_files` is reached.
Its capped entry inventory, skipped oversized files, extraction count and
cumulative output budget are reported as coverage warnings. Repeated file
contents are stored once under full SHA-256 artifact IDs and filenames, with up
to 100 distinct source path/inode records retained on the artifact and an
omission count beyond that. Registered decrypted files use the same dedup path.

## Output and artifacts

The mapped sections include identity, partition table, BitLocker metadata,
backup copies, protectors, encryption method, hash artifacts, broker requests,
unlock attempts, read-only volume, filesystem inventory, files, deleted entries,
ADS, timeline, graph, flags, findings, tools and metrics. Every stored artifact
has SHA-256, parent, method and immutable status. The report never embeds a raw
password or recovery key.

## Safety and limits

The plugin does not mount volumes, execute recovered content, use the network or
write to evidence. A decrypted export is a separate file. Full-volume extraction
is unavailable: pytsk3 only exports matching files within explicit budgets.
Split and virtual-image materialization is refused if it exceeds the workspace.
TPM protectors can be identified but cannot be used offline unless key material
is already contained in an authorized artifact supplied by the operator.
Explicit John/Hashcat launchers limit each run to 32 wordlists, a bounded cumulative
timeout and 16 MiB recovery files. Their per-run directories and child-created files
use private permissions; platforms without file-size limits report incomplete status.

## Bitlocker-1 and Bitlocker-2

The implemented routes cover the techniques described by these challenge names:
Bitlocker-1 uses FVE detection, `bitlocker2john`, an explicit wordlist/John or
Hashcat connector, credential verification and read-only export. Bitlocker-2
adds a memory-evidence path: the plugin carves documented Windows BitLocker pool
layouts into 66-byte FVEK candidates, and the workflow connects both the disk
image and those candidates to `Sblocco BitLocker read-only`. Every candidate is
tried against the volume; only a candidate that produces a structurally valid
filesystem is accepted. Challenge binaries are not bundled with the plugin, so
automatic tests use structurally representative synthetic images and an
optional local Bitlocker-1 regression skips when its authorized fixture or
Dislocker is unavailable.

## Extending formats

Add a content detector beside `volume_detector.py`, a parser returning normalized
metadata and protector rows, and an explicit read-only unlock adapter. Register
the new protection type in the manifest and `bruteforce` adapter registry. Never
reuse a BitLocker confidence score for a format whose structure was not parsed.

See `docs/` and module docstrings for offset rules, security decisions, output
examples and test coverage.
