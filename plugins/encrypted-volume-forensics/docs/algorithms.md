# Algorithms and validation

MBR entries are validated against physical bounds. GPT processing checks header
and entry-table CRC32 and verifies the backup signature. FVE discovery first
checks trusted partition starts and then scans a bounded view. Libbde provides
volume method, identifier and key-protector types. A fallback reports only fields
that can be bounded from the boot record.

A password is verified only if libbde unlocks the VMK or Dislocker produces a
complete output. Extracting a `$bitlocker$` descriptor does not prove that a
candidate password is correct. Numerical recovery passwords require eight
six-digit groups; every encoded group must be divisible by 11 and fit 16 bits.

Memory triage scans bounded windows for the `None`, `Cngb` and `FVEc` pool
layouts used by the open Volatility-BitLocker method. Pool size, duplicated key
material and cipher identifiers reduce random hits. The emitted Dislocker FVEK
file contains the two-byte encryption-method identifier followed by 64 bytes of
key material. This remains a candidate until `dislocker-file -k` decrypts the
paired volume and the filesystem validator accepts its boot structure.
