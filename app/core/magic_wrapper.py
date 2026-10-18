"""Adapter over the preserved Magic Wrapper, including all-match discovery."""

import json
import mimetypes
import time
from dataclasses import asdict
from pathlib import Path
from app.vendor.magic_wrapper import app as legacy


def all_matches(data, context):
    rules = list(legacy.COMPILED_MAGIC_RULES)
    for filename in context.get("signature_files", []):
        for item in json.loads(Path(filename).read_text()):
            tokens = tuple(None if x == "??" else int(x, 16) for x in item["pattern"].split())
            if not tokens or len(tokens) > 4096:
                raise ValueError("Firma esterna non valida")
            rules.append(
                legacy.MagicRule(
                    tokens,
                    str(item.get("offset", 0)),
                    item["description"],
                    sum(x is not None for x in tokens),
                )
            )
    found = []
    known = set()
    start = time.monotonic()
    partial = False
    embedded_limit = min(len(data), int(context.get("embedded_byte_budget", 8 * 1024**2)))
    embedded_cap = max(1, min(64, int(context.get("embedded_matches_per_signature", 16))))
    for rule in rules:
        if rule.fixed_bytes < 2:
            continue
        offsets = [
            (x, "magic")
            for x in legacy._candidate_offsets(data, rule.offset_rule)
            if legacy._matches_offset_rule(data, rule, x)
        ]
        if context.get("scan_embedded", True) and rule.fixed_bytes >= 4:
            anchor, delta = legacy._longest_anchor(rule.tokens)
            # Short anchors are too ambiguous for embedded scans.
            # Homogeneous anchors (all-zero/all-FF padding) occur throughout
            # disk images and cannot prove an embedded file. Treating them as
            # signatures produced hundreds of false PDB detections.
            if len(anchor) >= 4 and len(set(anchor)) > 1:
                offset = data.find(anchor, 0, embedded_limit)
                count = 0
                while offset >= 0 and count < embedded_cap:
                    candidate = offset - delta
                    if legacy._pattern_matches(data, rule.tokens, candidate):
                        offsets.append((candidate, "embedded"))
                    count += 1
                    offset = data.find(anchor, offset + 1, embedded_limit)
                # Reaching the per-signature cap is intentional false-positive
                # control, not an incomplete global scan. Do not surface it as a
                # warning or downgrade the complete top-level identification.
        for offset, source in offsets:
            key = (rule.description, offset)
            if key in known:
                continue
            known.add(key)
            found.append(
                {
                    "description": rule.description,
                    "source": source,
                    "offset": offset,
                    "confidence": min(0.9, 0.45 + rule.fixed_bytes * 0.035) if source == "magic" else 0.5,
                    "evidence": f"{rule.fixed_bytes} byte fissi, offset {offset}, regola {rule.offset_rule}",
                    "structurally_validated": False,
                }
            )
        if len(found) >= 512 or time.monotonic() - start > context.get("scan_timeout", 10):
            partial = True
            break
    return found[:512], partial


def analyze(asset, context, reporter):
    path = Path(asset["path"])
    reporter.phase("Firme e strutture interne")
    scan_context = dict(context)
    # A filesystem image legitimately contains hundreds of file signatures.
    # Ext4atto/GitHappens inventory those structures with filesystem context;
    # a flat embedded scan here is noisy, slow and prone to false positives.
    scan_context.setdefault(
        "scan_embedded",
        "disk_image" not in asset.get("detected_types", [])
        and Path(asset["name"]).suffix.lower() not in {".journal"},
    )
    with legacy.mapped_file(path) as data:
        structures = legacy.inspect_structures(data)
        detections, partial = all_matches(data, scan_context)
    for check in structures:
        detections.insert(
            0,
            {
                "description": check.description,
                "format": check.name,
                "source": "structure",
                "offset": 0,
                "confidence": 0.98,
                "evidence": list(check.evidence),
                "structurally_validated": True,
            },
        )
    extension = Path(asset["name"]).suffix.lower().lstrip(".")
    aliases = {
        "jpeg": {"jpg", "jpeg"},
        "pe": {"exe", "dll", "sys"},
        "elf": {"elf", "so", "o", "bin", ""},
        "riff": {"webp", "wav", "avi"},
        "zip": {"zip", "apk", "jar", "docx", "xlsx", "pptx", "epub"},
    }
    matches = [s for s in structures if extension in aliases.get(s.name, {s.name})]
    mismatch = bool(structures and not matches)
    damaged = legacy.needs_magic_repair(path, structures)
    warnings = []
    if mismatch:
        warnings.append("Estensione non coerente con la struttura rilevata")
    if damaged:
        warnings.append("Magic bytes danneggiati: riparazione disponibile su copia, su richiesta esplicita")
    if partial:
        warnings.append("Scansione firme parziale: limite tempo o risultati raggiunto")
    metadata = legacy.extract_image_metadata(
        path,
        tuple(legacy.Detection(x["description"], x["source"], x["offset"]) for x in detections),
        structures,
    )
    fmt = structures[0].name if structures else None
    mime = (
        mimetypes.guess_type(
            "asset." + ("webp" if structures and structures[0].description == "WebP image" else fmt or "bin")
        )[0]
        or "application/octet-stream"
    )
    return {
        "plugin_id": "magic-wrapper",
        "status": "partial" if partial else "completed",
        "summary": structures[0].description
        if structures
        else (detections[0]["description"] if detections else "Formato non identificato"),
        "confidence": max([x["confidence"] for x in detections], default=0),
        "findings": detections,
        "warnings": warnings,
        "structures": [asdict(x) for x in structures],
        "extension_mismatch": mismatch,
        "repair_available": damaged and not asset.get("partial_input"),
        "magic_preview": legacy.read_magic_preview(path).hex(" ").upper(),
        "metadata": metadata,
        "detected_mime": mime,
        "format": fmt,
        "sections": [
            {"id": "signatures", "title": "Firme e strutture", "type": "table", "data": detections},
            {"id": "metadata", "title": "Metadati", "type": "json", "data": metadata},
        ],
        "metrics": {"bytes_read": path.stat().st_size, "coverage": "bounded input view"},
    }


def repair(asset, context):
    if asset.get("partial_input"):
        raise ValueError("Riparazione rifiutata: struttura completa non disponibile nel byte budget")
    source = Path(asset["path"])
    with legacy.mapped_file(source) as data:
        structures = legacy.inspect_structures(data)
    if (
        len(
            [
                s
                for s in structures
                if s.repair_magic and not legacy.has_valid_magic(s, legacy.read_magic_preview(source))
            ]
        )
        != 1
    ):
        raise ValueError("Riparazione ambigua o nessuna struttura riparabile")
    destination = Path("/work") / ("repaired-" + source.name)
    # Original implementation uses copy2, preserving mode 0400. The sandbox
    # evidence view is 0644 on a read-only mount, so its separate copy is writable.
    result = legacy.repair_magic_bytes(source, structures, destination)
    return {
        "summary": "Copia riparata e validata",
        "repair": asdict(result),
        "artifacts": [
            {
                "path": str(destination),
                "name": destination.name,
                "method": "explicit magic repair",
                "offset": result.offset,
            }
        ],
    }
