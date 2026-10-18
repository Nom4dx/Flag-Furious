"""Orchestration for validated polyglot and embedded-content analysis.

The plugin treats every input as immutable passive evidence. Independent phases
produce normalized sections and continue after recoverable parser failures. No
embedded program, script, document action or extracted file is executed.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from app.core.plugin import BasePlugin

from .src.archive_analyzer import analyze_zip, recover_zip_local_headers
from .src.artifact_store import ArtifactStore
from .src.boundary_detector import detect_boundaries
from .src.carving import carve
from .src.decoy_detector import detect_decoys
from .src.flag_hunter import hunt_flags
from .src.graph_builder import build_graph
from .src.jpeg_analyzer import analyze_jpeg
from .src.overlay_analyzer import analyze_overlay
from .src.payload_decoder import decode_payloads, xor_candidates
from .src.pdf_analyzer import analyze_pdf
from .src.png_analyzer import analyze_png
from .src.polyglot_detector import classify_polyglot
from .src.reporting import finding, section
from .src.script_analyzer import analyze_script
from .src.sfx_analyzer import analyze_sfx
from .src.signatures import SIGNATURES, scan_signatures


class Plugin(BasePlugin):
    """Detect, validate and safely extract multi-format file structures.

    Input is a hub file mounted read-only. Output follows the normalized plugin
    contract and includes validated ranges, uncertain candidates, derived passive
    artifacts, flags and graphs. Parser errors yield ``partial``. Limits come
    from the manifest/context. Example: select the plugin for ``image.png`` with
    a ZIP appended after IEND.
    """

    def can_handle(self, asset, context):
        """Score compatibility from a bounded prefix without a full-file read.

        The hub supplies at most its triage view. A known header gives high
        confidence; a secondary embedded marker is only a proposal. Unreadable
        inputs return incompatible rather than throwing into the loader.
        """
        path = asset.get("path")
        if not path or asset.get("type") not in {None, "file", "archive", "disk_image"}:
            return {"compatible": False, "score": 0, "reasons": ["Il plugin analizza asset file passivi"]}
        try:
            with Path(path).open("rb") as stream:
                data = stream.read(65536)
        except OSError as exc:
            return {"compatible": False, "score": 0, "reasons": [f"Input non leggibile: {exc}"]}
        hits = []
        for signature in SIGNATURES:
            pos = data.find(signature.value)
            if pos >= 0:
                hits.append((signature, pos - signature.relative_offset))
        reasons = [f"Firma candidata {item.format.upper()} a offset {max(0, offset)}" for item, offset in hits[:5]]
        score = .94 if any(offset == 0 for _, offset in hits) else .78 if hits else .42
        if len({item.format for item, _ in hits}) > 1:
            score = .98; reasons.insert(0, "Più firme di formato nella vista limitata")
        if not reasons: reasons = ["File generico: scansione polyglot disponibile"]
        return {"compatible": True, "score": score, "reasons": reasons}

    def validate(self, asset, context):
        """Require a regular, non-symlink file and preserve it read-only.

        Output is the hub ``valid`` response. Directories and symlinks are refused
        to prevent ambiguous traversal. No bytes are modified.
        """
        path = Path(asset.get("path", ""))
        valid = bool(asset.get("path") and path.is_file() and not path.is_symlink())
        return {"valid": valid, "reason": "È richiesto un file regolare non simbolico" if not valid else ""}

    def analyze(self, asset, context, reporter):
        """Run streaming inventory, validation, extraction and flag ranking.

        Each phase is reported to the execution graph. Recoverable errors remain
        visible as warnings and produce ``partial``. Reads and writes respect the
        byte/output budgets; output is JSON serializable and the original remains
        unchanged.
        """
        started = time.monotonic()
        path = Path(asset["path"])
        size = path.stat().st_size
        byte_budget = min(int(context.get("byte_budget", size)), size)
        output_budget = int(context.get("output_bytes", 128 * 1024 * 1024))
        warnings, errors, events = [], [], []

        reporter.phase("Input e hash")
        digest, hashed = self._hash(path, byte_budget)
        reporter.log(f"Input aperto in sola lettura; {hashed} byte coperti dall'hash")
        identity = {"name": asset.get("name", path.name), "physical_size": size, "bytes_available": byte_budget, "sha256": digest, "complete_hash": hashed == size, "original_modified": False}
        if hashed < size:
            warnings.append(f"Analisi limitata a {hashed} di {size} byte dal byte budget")

        reporter.phase("Inventario firme")
        phase = time.monotonic()
        candidates, scan_truncated = scan_signatures(path, byte_budget)
        reporter.log(f"Inventario completato: {len(candidates)} marker candidati")
        events.append(self._event("Inventario firme", phase, "partial" if scan_truncated else "completed"))
        if scan_truncated: warnings.append("Scansione firme parziale: byte budget o limite risultati raggiunto")

        reporter.phase("Validazione formati e confini")
        phase = time.monotonic()
        validated, rejected = detect_boundaries(path, candidates, byte_budget)
        reporter.log(f"Validator: {len(validated)} formati provati, {len(rejected)} marker respinti")
        events.append(self._event("Validazione formati e confini", phase, "completed"))
        classification = classify_polyglot(size, validated)
        overlays = analyze_overlay(size, validated, candidates, path)
        sfx = analyze_sfx(validated)

        findings = []
        if classification["is_polyglot"]:
            findings.append(finding("polyglot-1", "polyglot_detected", f"Classificazione: {classification['primary_classification']}", severity="high", confidence=min((x["confidence"] for x in validated), default=.5)))
        for index, item in enumerate(overlays, 1):
            findings.append(finding(f"overlay-{index}", item["type"], f"Regione {item['type']} di {item['length']} byte", severity="medium", confidence=item["confidence"], offset=item["start_offset"], length=item["length"]))

        reporter.phase("Analisi strutture")
        reporter.log("Avvio parser passivi specifici; script e azioni documento non saranno eseguiti")
        structural = {"pdf": [], "png": [], "jpeg": [], "script": [], "sfx": sfx}
        for item in validated:
            try:
                if item["format"] == "pdf": structural["pdf"].append(analyze_pdf(path, item, min(byte_budget, 64 * 1024 * 1024)))
                elif item["format"] == "png": structural["png"].append(analyze_png(path, item))
                elif item["format"] == "jpeg": structural["jpeg"].append(analyze_jpeg(path, item))
                elif item["format"] in {"script", "shell_script", "python_script", "javascript", "powershell", "batch"}: structural["script"].append(analyze_script(path, item))
            except (OSError, ValueError) as exc:
                warnings.append(f"Analizzatore {item['format']} @{item['start_offset']}: {exc}")

        reporter.phase("Carving ed estrazione sicura")
        reporter.log("Carving limitato agli intervalli strutturalmente validati")
        store = ArtifactStore(Path(context["output_dir"]), output_budget)
        # A whole primary file is already an immutable hub asset. Carving it would
        # create a recursion loop; only secondary/prefixed interpretations are new.
        carve_targets = [item for item in validated if item["start_offset"] > 0 or item["end_offset"] < size]
        artifacts, carve_warnings = carve(path, carve_targets, store, {
            "start_offset": 0, "end_offset": None,
            "formats": sorted({x["format"] for x in carve_targets}),
            "max_object_bytes": min(64 * 1024 * 1024, output_budget),
        })
        warnings.extend(carve_warnings)
        archive_results = []
        archive_limits = {"max_entries": 512, "max_ratio": 100, "max_member_bytes": min(32 * 1024 * 1024, output_budget), "max_total_bytes": min(128 * 1024 * 1024, output_budget)}
        for item in validated:
            if item["format"] != "zip": continue
            try:
                result = analyze_zip(path, item, store, archive_limits)
                archive_results.append({k: v for k, v in result.items() if k != "artifacts"})
                artifacts.extend(result["artifacts"]); warnings.extend(result["warnings"])
            except (OSError, ValueError) as exc:
                warnings.append(f"Estrazione ZIP @{item['start_offset']}: {exc}")
        recovered_offsets = set()
        for candidate in rejected:
            if candidate["format"] != "zip" or candidate["offset"] in recovered_offsets:
                continue
            recovered_offsets.add(candidate["offset"])
            recovery = recover_zip_local_headers(path, candidate, min(byte_budget - candidate["offset"], 64 * 1024 * 1024))
            if recovery["entries"]:
                archive_results.append(recovery)
                warnings.append(recovery["warning"])

        reporter.phase("Payload e flag")
        reporter.log("Ricerca raw e decoded con provenienza e limiti di espansione")
        raw_limit = min(byte_budget, 16 * 1024 * 1024)
        with path.open("rb") as stream: raw = stream.read(raw_limit)
        decoded = decode_payloads(raw)
        decoded.extend(xor_candidates(raw, context.get("prefixes", [])))
        flag_sources = [{"data": raw, "source": asset.get("name", path.name), "format": validated[0]["format"] if validated else "unknown", "confidence": validated[0]["confidence"] if validated else .35, "base_offset": 0, "chain": ["input"]}]
        for payload in decoded:
            flag_sources.append({"data": payload["decoded"], "source": asset.get("name", path.name), "decoder": payload["decoder"], "confidence": .75 if validated else .45, "base_offset": payload.get("offset", 0), "chain": ["input", payload["decoder"]]})
        for artifact in artifacts:
            try:
                artifact_data = Path(artifact["path"]).read_bytes()[:16 * 1024 * 1024]
                flag_sources.append({"data": artifact_data, "source": artifact["name"], "artifact_sha256": artifact["sha256"], "format": artifact.get("format"), "confidence": artifact.get("confidence", .95), "chain": ["input", artifact.get("extraction_method", "carved"), artifact["name"]]})
            except OSError as exc: warnings.append(f"Flag scan artefatto {artifact.get('name')}: {exc}")
        flags = hunt_flags(flag_sources, context.get("prefixes", []))
        # Continue raw flag hunting across the granted view in bounded chunks.
        # A short overlap preserves flags split on a block boundary without
        # retaining the whole evidence in memory.
        with path.open("rb") as stream:
            stream.seek(raw_limit)
            offset = raw_limit
            overlap = raw[-1024:]
            while offset < byte_budget and len(flags) < 256:
                block = stream.read(min(4 * 1024 * 1024, byte_budget - offset))
                if not block: break
                flags.extend(hunt_flags([{"data": overlap + block, "source": asset.get("name", path.name), "format": validated[0]["format"] if validated else "unknown", "confidence": validated[0]["confidence"] if validated else .35, "base_offset": offset - len(overlap), "chain": ["input"]}], context.get("prefixes", []), 256 - len(flags)))
                overlap = block[-1024:]; offset += len(block)
        unique_flags = {}
        for flag in flags:
            unique_flags[(flag["value"], flag.get("source"), flag.get("offset"), flag.get("decoder"))] = flag
        flags = list(unique_flags.values())[:256]
        decoys = detect_decoys(flags, rejected)
        graph = build_graph(asset.get("name", path.name), validated, artifacts, flags, classification["relations"])
        graph_visualization = {"type": "graph", "title": "Catena di estrazione", "data": graph, "palette": "archive", "options": {"interactive": True, "zoom": True, "pan": True}}

        reporter.phase("Generazione report")
        reporter.log("Normalizzazione sezioni, mappa offset e grafo di estrazione")
        sections = [
            section("file_identity", "File identity", 10, [identity]),
            section("signature_inventory", "Signature inventory", 20, candidates),
            section("format_candidates", "Format candidates", 30, rejected, "completed"),
            section("validated_formats", "Validated formats", 40, validated),
            section("boundary_map", "Boundary map", 50, validated),
            section("polyglot_classification", "Polyglot classification", 60, [classification]),
            section("appended_data", "Prepended, appended and overlay data", 70, overlays),
            section("embedded_objects", "Embedded files and carved objects", 80, [{k: v for k, v in x.items() if k != "path"} for x in artifacts]),
            section("archive_analysis", "Archive analysis", 90, archive_results),
            section("pdf_analysis", "PDF analysis", 100, structural["pdf"]),
            section("png_analysis", "PNG analysis", 110, structural["png"]),
            section("jpeg_analysis", "JPEG analysis", 120, structural["jpeg"]),
            section("script_analysis", "Script and SFX analysis", 130, structural["script"] + structural["sfx"]),
            section("decoys", "Decoys", 140, decoys),
            section("payloads", "Payloads", 150, [{k: v for k, v in x.items() if k != "decoded"} for x in decoded]),
            section("flag_candidates", "Flag candidates", 160, flags),
            section("artifact_graph", "Artifact graph", 170, [graph_visualization], visualization=graph_visualization),
        ]
        status = "partial" if warnings or scan_truncated or hashed < size else "completed"
        visualizations = [
            {"type": "offset_map", "title": "Mappa dei formati e degli offset", "data": [{"x": x["start_offset"], "y": x["length"], "start": x["start_offset"], "end": x["end_offset"], "label": x["format"], "status": "validated"} for x in validated], "encoding": {"x": {"field": "x", "type": "number"}, "y": {"field": "y", "type": "number"}}, "palette": "archive", "options": {"interactive": True, "zoom": True, "tooltip": True}},
            graph_visualization,
        ]
        result = {
            "summary": f"{len(validated)} formati validati, {len(artifacts)} artefatti, {len(flags)} flag candidate",
            "status": status, "confidence": max((x["confidence"] for x in validated), default=.25), "phase": "polyglot analysis",
            "findings": findings, "sections": sections, "artifacts": artifacts, "derived_assets": [],
            "visualizations": visualizations, "flags": flags, "timeline": [], "execution_events": events,
            "logs": [], "warnings": warnings, "errors": errors,
            "metrics": {"duration": round(time.monotonic() - started, 4), "bytes_read": byte_budget, "signatures": len(candidates), "validated_formats": len(validated), "rejected_candidates": len(rejected), "artifacts": len(artifacts), "decoded_payloads": len(decoded)},
        }
        report_data = json.dumps({k: v for k, v in result.items() if k not in {"artifacts"}}, ensure_ascii=False, indent=2).encode()
        try: result["artifacts"].append(store.save_bytes("report", "report.json", report_data, {"format": "json", "extraction_method": "plugin_report", "confidence": 1.0}))
        except ValueError as exc: result["warnings"].append(str(exc)); result["status"] = "partial"
        reporter.partial(result)
        return result

    @staticmethod
    def _hash(path: Path, limit: int) -> tuple[str, int]:
        """Hash at most ``limit`` bytes in blocks; returns SHA-256 and byte count."""
        digest = hashlib.sha256(); total = 0
        with path.open("rb") as stream:
            while total < limit:
                block = stream.read(min(1024 * 1024, limit - total))
                if not block: break
                digest.update(block); total += len(block)
        return digest.hexdigest(), total

    @staticmethod
    def _event(name: str, started: float, status: str) -> dict:
        """Create a timed phase event for the hub execution graph."""
        return {"phase": name, "status": status, "duration": round(time.monotonic() - started, 4)}
