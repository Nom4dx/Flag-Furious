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
from diskhunt.source import prepare_image, COMPRESSED_SUFFIXES, QEMU_SUFFIXES


def prepare_for_hub(source, workdir, max_output_bytes=512 * 1024**2):
    # The hub already owns an immutable evidence copy. Raw images need neither
    # another copy nor chmod (which is forbidden on the read-only input mount).
    if source.suffix.lower() not in COMPRESSED_SUFFIXES | {".001", ".e01"} | QEMU_SUFFIXES:
        return source, "raw disk image (hub read-only evidence)"
    return prepare_image(source, workdir, max_output_bytes)


RESULT_LIMITS = {
    "partition": 2_000, "filesystem": 2_000, "file": 5_000,
    "deleted": 5_000, "recovered": 5_000, "flag": 10_000,
    "carved": 5_000, "artifact": 5_000,
}
MAX_LOG_ROWS = 1_000
MAX_LOG_FIELD_CHARS = {"message": 512, "command": 1_024, "raw_output": 4_096}


def all_results(db, kind):
    maximum = RESULT_LIMITS.get(kind, 2_000)
    with db.connect() as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM results WHERE job_id=? AND kind=?", ("analysis", kind)
        ).fetchone()[0]
    rows, offset = [], 0
    while True:
        batch = db.results("analysis", kind, limit=min(1000, maximum - offset), offset=offset)
        rows.extend(batch)
        if len(batch) < min(1000, maximum - offset):
            return rows, total > len(rows)
        offset += len(batch)
        if offset >= maximum:
            return rows, total > len(rows)


def hub_flags(rows):
    return [
        {
            **row,
            "value": row["candidate"],
            "confidence": row.get("confidence", 0) / 100,
            "offset": (
                row["absolute_offset"]
                if isinstance(row.get("absolute_offset"), int) and row["absolute_offset"] >= 0
                else row["artifact_offset"]
                if row.get("source_offset_scope") == "artifact"
                and isinstance(row.get("artifact_offset"), int)
                and row["artifact_offset"] >= 0
                else None
            ),
            "offset_scope": row.get("source_offset_scope") or (
                "disk_image"
                if isinstance(row.get("absolute_offset"), int) and row["absolute_offset"] >= 0
                else None
            ),
            "source": row.get("file_source") or row.get("source"),
        }
        for row in rows
    ]


class Plugin(BasePlugin):
    def can_handle(self, asset, context):
        """Accept disk evidence and reject ordinary compressed recovered files."""
        detected = set(asset.get("detected_types", []))
        signatures = set(asset.get("content_signatures", []))
        name = str(asset.get("name", "")).lower()
        virtual_suffixes = tuple(sorted(QEMU_SUFFIXES))
        direct_suffixes = (".img", ".dd", ".raw", *virtual_suffixes, ".e01")
        compressible_disk_suffixes = (".img", ".dd", ".raw", *virtual_suffixes)
        compressed_images = tuple(
            disk + archive
            for disk in compressible_disk_suffixes
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
                super().log(job_id, level, message, command, raw_output)

        db = ObservedDatabase(work / "disk.sqlite3")
        prefixes = context.get("prefixes", [])
        if set(prefixes) == {"flag", "CTF", "HTB", "picoCTF"}:
            prefixes = DEFAULT_PREFIXES
        options = AnalysisOptions(prefixes=prefixes, mode=context.get("mode", "balanced"))
        options.budgets.total = max(512, context["byte_budget"])
        options.source_hashes = {
            name: value
            for name, value in asset.get("hashes", {}).items()
            if name in {"md5", "sha1", "sha256"} and isinstance(value, str)
        }
        if len(options.source_hashes) != 3:
            options.source_hashes = {}
        else:
            options.source_size = asset.get("size")
        db.create_job("analysis", asset["name"], str(source), options.model_dump())
        def bounded_prepare(source_path, workdir_path):
            return prepare_for_hub(source_path, workdir_path, options.budgets.total)
        with patch("diskhunt.analyzer.prepare_image", bounded_prepare):
            Analyzer(db, "analysis", Event()).run()
        job = db.get_job("analysis")
        rows_with_limits = {
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
        groups = {kind: value[0] for kind, value in rows_with_limits.items()}
        truncated_kinds = [kind for kind, value in rows_with_limits.items() if value[1]]
        warnings = list(job["warnings"])
        warning_coverage = job.get("stats", {}).get("warning_coverage", {})
        if warning_coverage.get("omitted", 0):
            warnings.append(
                f"{warning_coverage['omitted']} warning aggiuntivi omessi; vedere metriche.warning_coverage."
            )
        if truncated_kinds:
            warnings.append("Inventario risultati limitato per payload/memoria: " + ", ".join(truncated_kinds))
        warnings.append("Letture degli strumenti TSK non sono contabilizzate dal byte budget del core.")
        missing = [
            name
            for name in ("mmls", "fls", "icat", "blkls", "fsstat", "ils", "jls")
            if not shutil.which(name)
        ]
        if missing:
            warnings.append("Funzionalità filesystem incomplete: comandi mancanti " + ", ".join(missing))
        with db.connect() as connection:
            log_total = connection.execute(
                "SELECT COUNT(*) FROM logs WHERE job_id=?", ("analysis",)
            ).fetchone()[0]
        logs_omitted = max(0, log_total - MAX_LOG_ROWS)
        logs = db.logs("analysis", limit=MAX_LOG_ROWS, latest=True)
        log_fields_truncated = False
        for entry in logs:
            truncated_fields = []
            for field, limit in MAX_LOG_FIELD_CHARS.items():
                value = entry.get(field)
                if isinstance(value, str) and len(value) > limit:
                    entry[field] = value[:limit] + " …[truncated]"
                    truncated_fields.append(field)
                    log_fields_truncated = True
            if truncated_fields:
                entry["truncated_fields"] = truncated_fields
        if logs_omitted or log_fields_truncated:
            warnings.append(
                f"Log parziali: {logs_omitted} righe omesse; "
                f"campi verbosi troncati={str(log_fields_truncated).lower()}."
            )
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
                    "source_offset": record.get("absolute_offset"),
                    "source_location": record.get("original_path") or record.get("file_source"),
                    "source_asset_id": asset.get("id"),
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
        if status == "completed" and warnings:
            status = "partial"
        partitions = groups["partition"]
        return {
            "summary": f"Ext4atto: {job['status']}; {len(groups['flag'])} flag candidate, {len(artifacts)} artefatti esportati",
            "status": status,
            "confidence": 0.9,
            "sections": [
                {"id": "inventory", "data": partitions},
                {"id": "analysis", "data": groups},
                {"id": "logs", "data": logs},
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
                "logs_total": log_total,
                "logs_exported": len(logs),
                "logs_omitted": logs_omitted,
                "log_fields_truncated": log_fields_truncated,
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
