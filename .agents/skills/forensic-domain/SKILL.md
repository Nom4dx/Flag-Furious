---
name: forensic-domain
description: Extend and review Flag-Furious as a modular digital-forensics suite. Use for domain coverage, forensic findings, plugin design, provenance, case workflows, or forensic result presentation.
---

# Forensic domain work in Flag-Furious

Use this skill when changing forensic coverage, adding plugins/connectors, reviewing
finding logic, or changing how evidence is presented. Read
[`docs/FORENSIC_DOMAIN_ROADMAP.md`](../../../docs/FORENSIC_DOMAIN_ROADMAP.md) and
[`docs/PLUGIN_REFACTOR_PROGRAM.md`](../../../docs/PLUGIN_REFACTOR_PROGRAM.md) first;
they record current coverage, known blind spots, sequencing, and acceptance criteria.

## Required working method

1. Identify the evidence type, supported acquisition/source, parser dependencies,
   and expected finding. Do not claim a whole domain from one format or parser.
2. Check the current plugin manifest, README, schemas, tests, and limitations before
   adding a parallel implementation. Prefer a focused plugin over core domain logic.
3. Preserve evidence bytes. Any repair/decryption/unpacking must create a derived
   asset with parent ID, hashes, method, offsets, and validation status.
4. Treat absent findings as inconclusive when inputs, parsers, or byte budgets were
   incomplete. Report coverage and truncation separately from a clean result.
5. Emit structured findings with stable IDs, source asset, source location, time
   (including timezone/precision when known), evidence excerpt/reference, confidence,
   and limitations. Never elevate a heuristic candidate to a validated fact.
6. Use declared `output_schema.json` and presentation mappings. Put the answer first:
   case outcome, high-priority findings, evidence/provenance, timeline, artifacts,
   coverage gaps, then technical detail. Keep raw plugin JSON available as a secondary
   view; never render plugin data as HTML.
7. Keep parsing offline and read-only by default. A connector is an explicit workflow
   operation; credentials are ephemeral, scoped, and never persisted in workflow JSON.
8. Add format-specific fixtures and tests when implementing a parser. Include malformed,
   boundary, truncated, and ambiguous inputs, and state what the fixtures do not prove.
9. Update the roadmap's maturity and remaining-work table when coverage changes. Avoid
   “complete forensic coverage” claims unless acquisition, parser, validation, and
   known limitations are all documented for the stated scope.

## Plugin boundary

Use `plugin.json` for stable ID, domains, asset types, capabilities, optional tools,
budgets, and dependencies. Use `extensions.json` for bounded compatibility hints.
Keep format parsing in the plugin, orchestration/provenance in the core, and presentation
declarations in `output_schema.json`. A plugin should fail independently and explain
missing optional dependencies. Do not add a domain allowlist to the core.

For new result sections use the shared finding, timeline, entity, artifact, and coverage
conventions described in the roadmap. Make timestamps sortable and provenance links
selectable from tables and charts. Visual encodings must have labels, units, accessible
contrast, and a non-graph textual/table equivalent.
