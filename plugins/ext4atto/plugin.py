"""Adapter around the unchanged DiskHunt engine; evidence remains read-only."""

from pathlib import Path
from threading import Event
from unittest.mock import patch
import shutil
from app.core.plugin import BasePlugin
from diskhunt.analyzer import Analyzer
from diskhunt.db import Database
from diskhunt.models import AnalysisOptions
from diskhunt.scanner import DEFAULT_PREFIXES
from diskhunt.source import prepare_image, COMPRESSED_SUFFIXES


def prepare_for_hub(source, workdir):
    # The hub already owns an immutable evidence copy. Raw images need neither
    # another copy nor chmod (which is forbidden on the read-only input mount).
    if source.suffix.lower() not in COMPRESSED_SUFFIXES | {".001", ".vhd", ".vmdk", ".qcow2", ".e01"}:
        return source, "raw disk image (hub read-only evidence)"
    return prepare_image(source, workdir)


def all_results(db, kind):
    rows, offset = [], 0
    while True:
        batch = db.results("analysis", kind, limit=1000, offset=offset)
        rows.extend(batch)
        if len(batch) < 1000:
            return rows
        offset += len(batch)


def hub_flags(rows):
    return [
        {
            **row,
            "value": row["candidate"],
            "confidence": row.get("confidence", 0) / 100,
            "offset": row.get("absolute_offset") if row.get("absolute_offset", -1) >= 0 else None,
        }
        for row in rows
    ]


class Plugin(BasePlugin):
    def can_handle(self, asset, context):
        """Accept disk evidence and reject ordinary compressed recovered files."""
        detected = set(asset.get("detected_types", []))
        signatures = set(asset.get("content_signatures", []))
        name = str(asset.get("name", "")).lower()
        direct_suffixes = (".img", ".dd", ".raw", ".qcow", ".qcow2", ".vhd", ".vmdk", ".e01")
        compressed_images = tuple(
            disk + archive
            for disk in direct_suffixes
            for archive in (".gz", ".xz", ".zst")
        )
        if "disk_image" in detected or signatures.intersection({"filesystem_image", "qcow"}):
            return {
                "compatible": True,
                "score": 0.96,
                "reasons": ["Struttura di immagine disco riconosciuta"],
            }
        if name.endswith(direct_suffixes) or name.endswith(compressed_images):
            return {
                "compatible": True,
                "score": 0.72,
                "reasons": ["Nome compatibile con un'immagine disco"],
            }
        return {
            "compatible": False,
            "score": 0.0,
            "reasons": ["Il file compresso non identifica un'immagine disco"],
        }

    def analyze(self, asset, context, reporter):
        work = Path(context["output_dir"]) / "disk"
        (work / "original").mkdir(parents=True)
        source = work / "original" / Path(asset["path"]).name
        source.symlink_to(Path(asset["path"]).absolute())

        class ObservedDatabase(Database):
            def log(self, job_id, level, message, command=None, raw_output=None):
                reporter.log(message, level, command)
                if str(message).startswith("phase:"):
                    reporter.phase(str(message)[6:])
                    flags = hub_flags(all_results(self, "flag"))
                    if flags:
                        reporter.partial({"status": "partial", "summary": message, "flags": flags})
                super().log(job_id, level, message, command, raw_output)

        db = ObservedDatabase(work / "disk.sqlite3")
        prefixes = context.get("prefixes", [])
        if set(prefixes) == {"flag", "CTF", "HTB", "picoCTF"}:
            prefixes = DEFAULT_PREFIXES
        options = AnalysisOptions(prefixes=prefixes, mode=context.get("mode", "balanced"))
        options.budgets.total = max(512, context["byte_budget"])
        db.create_job("analysis", asset["name"], str(source), options.model_dump())
        with patch("diskhunt.analyzer.prepare_image", prepare_for_hub):
            Analyzer(db, "analysis", Event()).run()
        job = db.get_job("analysis")
        groups = {
            kind: all_results(db, kind)
            for kind in (
                "partition",
                "filesystem",
                "file",
                "deleted",
                "recovered",
                "flag",
                "carved",
                "artifact",
            )
        }
        warnings = list(job["warnings"])
        missing = [
            name
            for name in ("mmls", "fls", "icat", "blkls", "fsstat", "ils", "jls")
            if not shutil.which(name)
        ]
        if missing:
            warnings.append("Funzionalità filesystem incomplete: comandi mancanti " + ", ".join(missing))
        artifacts, total, omitted = [], 0, 0
        root = (work / "artifacts").resolve()
        # Prefer actual recovered files over potentially huge slack/unallocated dumps.
        records = sorted(
            groups["artifact"], key=lambda r: (r.get("method", "").startswith("blkls"), r.get("size", 0))
        )
        seen = set()
        for record in records:
            path = root / record["artifact"]
            if (
                path in seen
                or path.is_symlink()
                or not path.resolve().is_relative_to(root)
                or not path.is_file()
            ):
                continue
            seen.add(path)
            size = path.stat().st_size
            if total + size > context["output_bytes"]:
                omitted += 1
                continue
            total += size
            artifacts.append(
                {
                    **record,
                    "path": str(path),
                    "name": record.get("name_original", path.name),
                    "offset": record.get("absolute_offset"),
                    "confidence": record.get("confidence", 0) / 100,
                }
            )
        if omitted:
            warnings.append(
                f"{omitted} artefatti non esportati: budget output esaurito; catalogo e flag conservati."
            )
        status = {
            "COMPLETED": "completed",
            "PARTIAL": "partial",
            "FAILED": "failed",
            "CANCELLED": "cancelled",
        }.get(job["status"], "partial")
        if status == "completed" and (missing or omitted):
            status = "partial"
        partitions = groups["partition"]
        return {
            "summary": f"Ext4atto: {job['status']}; {len(groups['flag'])} flag candidate, {len(artifacts)} artefatti esportati",
            "status": status,
            "confidence": 0.9,
            "sections": [
                {"id": "inventory", "data": partitions},
                {"id": "analysis", "data": groups},
                {"id": "logs", "data": db.logs("analysis")},
            ],
            "artifacts": artifacts,
            "findings": groups["flag"],
            "flags": hub_flags(groups["flag"]),
            "warnings": warnings,
            "errors": [job["error"]] if job.get("error") else [],
            "metrics": {
                **job["stats"],
                "input_visible_bytes": asset.get("visible_bytes"),
                "native_byte_budget": options.budgets.total,
                "external_reads_metered": False,
                "omitted_artifacts": omitted,
            },
            "visualizations": [
                {
                    "type": "offset_map",
                    "title": "Mappa partizioni",
                    "data": [
                        {
                            "x": p.get("offset_byte", 0),
                            "y": p.get("size", 0),
                            "label": str(p.get("number", "")),
                        }
                        for p in partitions
                    ],
                }
            ],
        }
