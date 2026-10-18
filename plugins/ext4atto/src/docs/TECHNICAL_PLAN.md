# DiskHunt architecture audit and evolution plan

## Baseline audit

The initial version already provided FastAPI/SQLite jobs, a React console, native MBR/GPT/FAT/ext probes, TSK `fsstat`/`fls`/`icat`, raw flag scanning, carving, byte budgets and reports. Its main gaps were: FAT superfloppies mistaken for empty MBRs, raw inputs used as both original and analysis source, no artifact catalog, no recursive extraction, no preview, no case list/delete workflow, limited file search, and excessive false-positive carving.

All subprocesses were already invoked without a shell and images were never mounted or executed. The analysis copy is now physically separated from the original for every input format. Per-command failure remains non-fatal and raw TSK output is retained in the audit log.

## Implemented architecture

```text
immutable original
  -> format adapter / analysis copy
  -> native partition + filesystem probes
  -> TSK image/volume/filesystem triage
  -> recursive file index
  -> allocated/deleted inode recovery
  -> slack + unallocated block export
  -> typed artifact catalog
  -> bounded recursive extraction
  -> flag scanners + heuristic candidates
  -> carving
  -> preview / report / download
```

Each artifact contains provenance, parent artifact, filesystem, partition, inode, generated and original names, MIME, SHA-256, method, status and confidence. This makes archive relationships navigable without challenge-specific rules.

## Remaining long-term work

- Native detailed FAT chain/LFN reconstruction beyond TSK's implementation.
- Full JBD2 transaction replay rather than journal inventory.
- Resumable block-level progress inside external TSK commands.
- Remote NBD transport (validation remains disabled-by-default and allowlist-only).
- Optional distributed queue and object storage for multi-node deployments.

