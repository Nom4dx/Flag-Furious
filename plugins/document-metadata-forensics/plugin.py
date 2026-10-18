"""Document Metadata Forensics plugin orchestration.

The implementation treats documents as passive byte containers. Each parser is
fault-isolated, reports a visible phase and returns structured evidence. No macro,
PDF action, embedded file, link, HTML or script is executed.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from app.core.plugin import BasePlugin

from .src.artifact_store import ArtifactStore
from .src.flag_hunter import hunt_flags
from .src.hidden_content import analyze_hidden
from .src.html_analyzer import analyze_structured
from .src.identification import bounded_match, identify
from .src.image_analyzer import analyze_image
from .src.inconsistencies import find_inconsistencies
from .src.metadata import extract_metadata
from .src.ole_analyzer import analyze_ole
from .src.ooxml_analyzer import analyze_ooxml
from .src.payload_decoder import decode_payloads
from .src.pdf_analyzer import analyze_pdf
from .src.reporting import ModuleResult, run_module
from .src.rtf_analyzer import analyze_rtf
from .src.timeline import build_timeline


class Plugin(BasePlugin):
    """Analyze document metadata, structure, revisions and hidden payloads.

    Input: hub assets whose path is mounted read-only. Output: normalized plugin
    result, artifacts and flag candidates. Parser failures yield ``partial``.
    Limits: manifest byte/time/memory/output budgets and per-parser caps. Security:
    static analysis only. Example: select this plugin for a PDF in the hub UI.
    """

    def can_handle(self, asset, context):
        """Determine compatibility from at most 64 KiB.

        Input: hub asset/context. Output: score and reasons. Raises only for an
        unreadable path. Security: bounded read-only access; no full-file scan.
        """
        # Validation and analyze require a mounted file. Do not advertise
        # compatibility for in-memory content that this plugin cannot consume.
        if not asset.get("path"):
            return {"compatible": False, "score": 0, "reasons": ["È richiesto un file montato in sola lettura"]}
        return bounded_match(asset["path"], asset.get("name", "asset"))

    def validate(self, asset, context):
        """Verify a readable non-directory asset within the granted view.

        Input: asset/context. Output: ``valid`` plus reason. Security: no writes
        or content interpretation. Example: ``plugin.validate(asset, ctx)``.
        """
        path = asset.get("path")
        valid = bool(path and Path(path).is_file() and not Path(path).is_symlink())
        return {"valid": valid, "reason": "Il plugin richiede un singolo file leggibile" if not valid else ""}

    def analyze(self, asset, context, reporter):
        """Execute the documented modular static-analysis pipeline.

        Input: sandbox asset/context/reporter. Output: JSON-normalizable result.
        Recoverable parser and artifact errors are warnings. Limits: reads only
        the worker-visible byte budget; output respects ``output_bytes``. Security:
        the original is never modified and extracted bytes remain passive.
        """
        path = Path(asset["path"])
        reporter.phase("Input e hash")
        data, digest = self._read_and_hash(path, context["byte_budget"])
        visible_size = path.stat().st_size
        declared_size = int(asset.get("size", visible_size))
        input_partial = bool(asset.get("partial_input")) or len(data) < visible_size or declared_size > len(data)
        reporter.log(f"Acquisiti {len(data)} byte in sola lettura")
        modules: list[ModuleResult] = []
        phases = [
            ("Identificazione formato", lambda: identify(data, asset["name"])),
            ("Inventario struttura PDF", lambda: analyze_pdf(data, asset["name"])),
            ("Estrazione metadata", lambda: extract_metadata(data, asset["name"])),
            ("Analisi Office e contenitori", lambda: analyze_ooxml(data, asset["name"])),
            ("Analisi OLE", lambda: analyze_ole(data, asset["name"])),
            ("Analisi RTF", lambda: analyze_rtf(data, asset["name"])),
            ("Analisi immagini", lambda: analyze_image(data, asset["name"])),
            ("Analisi dati strutturati", lambda: analyze_structured(data, asset["name"])),
            ("Analisi del contenuto nascosto", lambda: analyze_hidden(data, asset["name"])),
        ]
        for name, parser in phases:
            modules.append(run_module(name, parser, reporter))
        evidence = [item for module in modules for item in module.items]
        payloads = run_module(
            "Estrazione payload", lambda: decode_payloads(evidence, asset["name"]), reporter
        )
        modules.append(payloads)
        evidence.extend(payloads.items)
        timeline = run_module("Timeline", lambda: build_timeline(evidence, asset["name"]), reporter)
        inconsistencies = run_module(
            "Verifica incoerenze", lambda: find_inconsistencies(evidence, asset["name"]), reporter
        )
        flags = run_module(
            "Ricerca flag",
            lambda: hunt_flags(
                evidence, context.get("prefixes", []), asset["name"], context.get("patterns", [])
            ),
            reporter,
        )
        modules.extend((timeline, inconsistencies, flags))

        reporter.phase("Salvataggio artefatti")
        store = ArtifactStore(Path(context["output_dir"]), context["output_bytes"])
        artifacts, artifact_warnings = [], []
        for module in modules:
            saved = []
            for item in module.artifacts:
                content = item.pop("content", None)
                if content is None:
                    continue
                try:
                    record = store.save(item.get("category", "raw"), item["name"], content, item)
                    artifacts.append(record)
                    saved.append({k: v for k, v in record.items() if k != "path"})
                except ValueError as exc:
                    artifact_warnings.append(str(exc))
                    module.status = "partial"
            module.artifacts = saved

        findings = [item for module in modules for item in module.findings]
        warnings = [warning for module in modules for warning in module.warnings] + artifact_warnings
        if input_partial:
            warnings.append(
                f"Input parziale: analizzati {len(data)} byte; vista montata {visible_size}, asset dichiarato {declared_size}."
            )
        active = [m for m in modules if m.status != "skipped"]
        failed = [
            {"module": m.name, "error": "; ".join(m.warnings), "recoverable": True}
            for m in active
            if m.status == "partial"
        ]
        status = "partial" if warnings or failed or input_partial else "completed"
        sections = [
            {
                "id": _section_id(module.name),
                "title": module.name,
                "order": index * 10,
                "status": module.status,
                "items": module.items,
                "artifacts": module.artifacts,
                "findings": module.findings,
                "flags": module.items if module is flags else [],
                "timeline": module.timeline,
                "visualization": None,
                "data": module.as_dict(),
            }
            for index, module in enumerate(modules, 1)
            if module.status != "skipped" or module.warnings
        ]
        result = {
            "summary": f"{len(evidence)} elementi, {len(findings)} finding, {len(flags.items)} flag candidate",
            "status": status,
            "confidence": 0.92 if active else 0.3,
            "phase": "document forensics",
            "completed_modules": [m.name for m in active if m.status == "completed"],
            "failed_modules": failed,
            "findings": findings,
            "sections": sections,
            "artifacts": artifacts,
            "derived_assets": [],
            "visualizations": _visualizations(modules, timeline),
            "flags": flags.items,
            "timeline": timeline.timeline,
            "execution_events": [
                {"phase": m.name, "status": m.status, "duration": m.metrics.get("duration_seconds")}
                for m in modules
            ],
            "logs": [],
            "warnings": warnings,
            "errors": [],
            "metrics": {
                "bytes_read": len(data),
                "visible_input_bytes": visible_size,
                "declared_input_bytes": declared_size,
                "sha256": digest,
                "modules": len(active),
                "metadata_values": len(evidence),
                "partial_input": input_partial,
            },
        }
        reporter.phase("Generazione report")
        try:
            report_artifact = store.report(
                {k: v for k, v in result.items() if k not in {"artifacts", "derived_assets"}}
            )
            result["artifacts"].append(report_artifact)
        except ValueError as exc:
            result["warnings"].append(str(exc))
            result["status"] = "partial"
        reporter.partial(result)
        return result

    @staticmethod
    def _read_and_hash(path: Path, limit: int) -> tuple[bytes, str]:
        """Read/hash up to the granted view; output is bytes plus SHA-256.

        Raises ``OSError`` for I/O failure. Limits: ``limit``. Security: read-only.
        """
        digest = hashlib.sha256()
        chunks = []
        total = 0
        with path.open("rb") as source:
            while total < limit:
                block = source.read(min(1024**2, limit - total))
                if not block:
                    break
                chunks.append(block)
                digest.update(block)
                total += len(block)
        return b"".join(chunks), digest.hexdigest()


def _section_id(name: str) -> str:
    """Build a stable section ID from an Italian phase label."""
    return "section-" + "-".join(name.lower().replace("à", "a").split())


def _visualizations(modules: list[ModuleResult], timeline: ModuleResult) -> list[dict]:
    """Describe central-engine charts; no plugin-owned frontend code is emitted."""
    charts = [
        {
            "type": "bar",
            "title": "Risultati per modulo",
            "data": [{"x": m.name, "y": len(m.items) + len(m.findings)} for m in modules],
            "encoding": {"x": {"field": "x", "type": "text"}, "y": {"field": "y", "type": "number"}},
            "options": {"interactive": True, "tooltip": True},
            "palette": "monochrome",
        }
    ]
    if timeline.timeline:
        charts.append(
            {
                "type": "timeline",
                "title": "Cronologia metadata",
                "data": timeline.timeline,
                "palette": "monochrome",
            }
        )
    return charts
