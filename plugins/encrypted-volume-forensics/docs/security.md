# Security decisions

- Evidence is opened read-only and never mounted.
- Decrypted output is a separate chmod 0400 file.
- Passwords and recovery keys are ephemeral and masked.
- Tool calls use fixed argv arrays, `shell=False`, timeouts and bounded output.
- John and Hashcat require explicit confirmation in the connector workflow.
- The plugin has no network or root requirement.
- TSK extraction uses sanitized flat names, SHA-256 deduplication, file-count,
  file-size and output-byte limits.
- TPM protectors are inventoried but the host TPM is never queried.
- Generated paths are resolved below the isolated output root.
