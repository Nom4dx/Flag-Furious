# Known limitations

- TPM, TPM+PIN and certificate protectors cannot be satisfied without authorized
  external key material; the plugin only identifies them.
- Internal parsing intentionally delegates detailed VMK/FVEK decoding to libbde.
- Damaged metadata may remain metadata-only even when a signature survives.
- VHD/VHDX must fit the configured conversion workspace; external backing-file
  chains are refused, and only internal formats reported by qemu-img are used.
- Numbered split images are merged only after a bounded scan confirms a
  contiguous, unambiguous regular-file sequence.
- Decrypted volumes larger than the artifact budget are verified but not exported.
- ADS inventory depends on filesystem APIs exposed by pytsk3 and is conservative.
- John/Hashcat recovery is an explicit workflow action, never automatic analysis.
- Memory FVEK scanning covers documented 64-bit Windows pool layouts; compressed,
  paged-out, overwritten or unsupported kernel layouts can yield no candidate.
- A memory pool hit is deliberately untrusted until paired-volume validation.
