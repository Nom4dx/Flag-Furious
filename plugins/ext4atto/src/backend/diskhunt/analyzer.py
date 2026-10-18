from __future__ import annotations
import hashlib
import time
from pathlib import Path
from threading import Event
from .budget import ByteBudget, BudgetExhausted
from .artifacts import ArtifactCatalog
from .db import Database
from .extraction import RecursiveExtractor
from .models import AnalysisOptions
from .parsers import inspect_partitions, parse_ext_superblock, parse_fat_boot
from .scanner import carve, compile_flag_patterns, scan_bytes, scan_ranges
from .security import safe_filename
from .source import prepare_image
from .tsk import TSK


class Analyzer:
    PHASES = ["hashing", "image preparation", "image triage", "partition analysis", "filesystem analysis", "file enumeration", "artifact recovery", "filesystem residue", "recursive extraction", "flag search", "carving", "report checkpoint"]

    def __init__(self, db: Database, job_id: str, cancel: Event):
        self.db = db; self.job_id = job_id; self.cancel = cancel; self.completed: list[str] = []; self.warnings: list[str] = []

    def log(self, level, message, command=None, raw_output=None):
        self.db.log(self.job_id, level, message, command, raw_output)

    def phase(self, name: str, progress: float):
        if self.cancel.is_set() or (self.db.get_job(self.job_id) or {}).get("cancel_requested"):
            raise InterruptedError("analysis cancelled")
        self.db.update_job(self.job_id, phase=name, progress=progress, warnings=self.warnings)
        self.log("INFO", f"phase: {name}")

    def run(self):
        job = self.db.get_job(self.job_id)
        if not job: return
        options = AnalysisOptions.model_validate(job["options"])
        source = Path(job.get("original_path") or job["image_path"])
        workdir = source.parent.parent if source.parent.name == "original" else source.parent
        started = time.monotonic()
        b = options.budgets
        budget = ByteBudget(b.total, {"metadata": b.metadata, "search": b.search, "journal": b.journal, "carving": b.carving}, b.cache_size)
        stats: dict = {"completed_phases": [], "incomplete_phases": [], "started_monotonic": started}
        self.db.update_job(self.job_id, status="RUNNING", error=None)
        try:
            self.phase("hashing", 4); hashes, size = self._hash(source); stats.update({"hashes": hashes, "original_hashes": hashes, "size": size})
            self.completed.append("hashing")
            self.phase("image preparation", 9); image, image_type = prepare_image(source, workdir)
            stats["image_type"] = image_type; stats["analysis_size"] = image.stat().st_size; stats["sector_size"] = 512; stats["sectors"] = image.stat().st_size // 512
            if image.resolve() != source.resolve(): stats["analysis_hashes"] = self._hash(image)[0]
            self.db.update_job(self.job_id, image_path=str(image)); self.completed.append("image preparation")
            patterns = compile_flag_patterns(options.prefix, options.prefix_is_regex, options.prefixes)
            catalog = ArtifactCatalog(self.db, self.job_id, workdir / "artifacts", patterns)
            tsk = TSK(image, self.log)
            self.phase("image triage", 13); tsk.image_triage(); self.completed.append("image triage")
            self.phase("partition analysis", 18)
            with image.open("rb") as handle: table, partitions, anomalies = inspect_partitions(handle, image.stat().st_size)
            stats["partition_table"] = table; self.warnings.extend(anomalies)
            self.completed.append("partition analysis")
            self.phase("filesystem analysis", 28); self._filesystem_details(image, partitions, budget, b.max_request)
            for part in partitions: self.db.add_result(self.job_id, "partition", part)
            self.completed.append("filesystem analysis")
            self.phase("file enumeration", 40); self._enumerate(tsk, partitions, workdir, options)
            self.completed.append("file enumeration")
            self.phase("artifact recovery", 50); recovered = self._recover(tsk, partitions, workdir, catalog)
            self.completed.append("artifact recovery")
            self.phase("filesystem residue", 56); recovered.extend(self._filesystem_residue(tsk, partitions, workdir, catalog)); self.completed.append("filesystem residue")
            self.phase("recursive extraction", 62); extractor = RecursiveExtractor(catalog, workdir / "artifacts" / "extracted")
            for record in recovered: extractor.expand(record)
            self.warnings.extend(extractor.warnings); self.completed.append("recursive extraction")
            self.phase("flag search", 70)
            reported = 0
            def report_bytes(count):
                nonlocal reported
                reported += count
                if reported >= 8 * 1024 * 1024:
                    self.db.update_job(self.job_id, stats={**stats, "budget": budget.stats()}); reported = 0
            allocated = [p for p in partitions if p["status"] == "allocated"]
            unallocated = [p for p in partitions if p["status"] == "unallocated"]
            ranges = [(p["offset_byte"], p["size"], p, "filesystem" if p in allocated else "unallocated") for p in allocated + unallocated]
            flags = []
            if budget.can_external(image.stat().st_size, "search"):
                external_flags = tsk.search_strings(patterns)
                if external_flags is not None:
                    flags = external_flags; budget.account_external(image.stat().st_size, "search")
            for flag in flags:
                part = next((p for p in partitions if p["offset_byte"] <= flag["absolute_offset"] < p["offset_byte"] + p["size"] and p["status"] == "allocated"), None)
                if part:
                    flag.update({"partition": part["number"], "partition_offset": flag["absolute_offset"] - part["offset_byte"], "filesystem": part["filesystem"]})
            # Raw fallback also covers UTF-16 and cross-chunk cases when printable-string extraction finds nothing.
            if not flags: flags = scan_ranges(image, ranges, patterns, budget, b.max_request, report_bytes)
            flags = sorted({(f["candidate"], f["absolute_offset"], f["source"]): f for f in flags}.values(), key=lambda f: -f["confidence"])
            for flag in flags: self.db.add_result(self.job_id, "flag", flag)
            if "search" not in budget.exhausted_phases: self.completed.append("flag search")
            self.phase("carving", 85)
            carved = carve(image, workdir / "artifacts" / "carved", ranges, budget, b.max_request, options.custom_signatures, report_bytes)
            for item in carved:
                self.db.add_result(self.job_id, "carved", item)
                target = workdir / "artifacts" / "carved" / item["name"]
                if target.exists(): catalog.register(target, name_original=item["name"], original_path="unallocated/raw", method="magic-byte carving", status=item["status"], confidence=item["confidence"], partition=item.get("partition"), absolute_offset=item["absolute_offset"])
            if "carving" not in budget.exhausted_phases: self.completed.append("carving")
            self.phase("report checkpoint", 96); self.completed.append("report checkpoint")
            stats.update({"budget": budget.stats(), "completed_phases": self.completed, "elapsed_seconds": round(time.monotonic()-started, 3),
                          "partitions": len(partitions), "flags": len(self.db.results(self.job_id, "flag")), "files": len(self.db.results(self.job_id, "file")), "deleted": len(self.db.results(self.job_id, "deleted")), "artifacts": len(self.db.results(self.job_id, "artifact"))})
            exhausted = bool(budget.exhausted_phases) or budget.stats()["remaining"] == 0
            if exhausted:
                stats["incomplete_phases"] = sorted(budget.exhausted_phases)
            self.db.update_job(self.job_id, status="PARTIAL" if exhausted else "COMPLETED", phase="budget exhausted; checkpoint saved" if exhausted else "complete", progress=100, stats=stats, warnings=self.warnings)
        except InterruptedError as exc:
            stats.update({"budget": budget.stats(), "completed_phases": self.completed, "elapsed_seconds": round(time.monotonic()-started, 3)})
            self.db.update_job(self.job_id, status="CANCELLED", phase="cancelled", stats=stats, error=str(exc))
        except Exception as exc:
            self.log("ERROR", f"analysis failed: {type(exc).__name__}: {exc}")
            stats.update({"budget": budget.stats(), "completed_phases": self.completed, "elapsed_seconds": round(time.monotonic()-started, 3)})
            self.db.update_job(self.job_id, status="FAILED", phase="failed", stats=stats, error=f"{type(exc).__name__}: {exc}")

    def _hash(self, path: Path):
        digests = [hashlib.md5(usedforsecurity=False), hashlib.sha1(usedforsecurity=False), hashlib.sha256()]; size = 0
        with path.open("rb") as source:
            while block := source.read(4 * 1024 * 1024):
                if self.cancel.is_set(): raise InterruptedError("analysis cancelled")
                size += len(block)
                for digest in digests: digest.update(block)
        return dict(zip(("md5", "sha1", "sha256"), (d.hexdigest() for d in digests))), size

    def _filesystem_details(self, image, partitions, budget, max_request):
        with image.open("rb") as handle:
            for part in partitions:
                if part["status"] != "allocated": continue
                try:
                    boot = budget.read(handle, part["offset_byte"], min(4096, part["size"]), "metadata", max_request)
                    if part["filesystem"].startswith("FAT"):
                        detail = parse_fat_boot(boot[:512]); copies = []
                        fat_bytes = detail["fat_size_sectors"] * detail["bytes_per_sector"]
                        for index in range(min(detail["fat_count"], 4)):
                            offset = part["offset_byte"] + (detail["reserved_sectors"] * detail["bytes_per_sector"]) + index * fat_bytes
                            remaining = fat_bytes; digest = hashlib.sha256(); sample = bytearray()
                            while remaining:
                                chunk = budget.read(handle, offset + fat_bytes - remaining, min(remaining, max_request), "metadata", max_request)
                                if not chunk: break
                                digest.update(chunk)
                                if len(sample) < 1024 * 1024: sample.extend(chunk[:1024 * 1024-len(sample)])
                                remaining -= len(chunk)
                            copies.append({"number": index + 1, "sha256": digest.hexdigest(), "bytes_read": fat_bytes - remaining, "sample": bytes(sample)})
                        detail["fat_copies"] = [{k:v for k,v in copy.items() if k != "sample"} for copy in copies]
                        if len(copies) > 1:
                            detail["fat_copies_equal"] = copies[0]["sha256"] == copies[1]["sha256"]
                            detail["fat_sample_differences"] = sum(a != b for a,b in zip(copies[0]["sample"], copies[1]["sample"]))
                    elif part["filesystem"].startswith("ext"):
                        sb = budget.read(handle, part["offset_byte"] + 1024, 1024, "metadata", max_request); detail = parse_ext_superblock(sb)
                    else: continue
                    part["filesystem"] = detail["type"]; self.db.add_result(self.job_id, "filesystem", {"partition": part["number"], **detail})
                except (ValueError, BudgetExhausted) as exc: self.warnings.append(f"partition {part['number']}: {exc}")

    def _enumerate(self, tsk, partitions, workdir, options):
        for part in partitions:
            if part["status"] != "allocated" or part["filesystem"] == "unknown": continue
            tsk.filesystem_stats(part["start_sector"])
            if part["filesystem"].startswith("ext"):
                tsk.list_unallocated_inodes(part["start_sector"])
                tsk.journal_listing(part["start_sector"])
            for item in tsk.list_files(part["start_sector"]):
                item.update({"partition": part["number"], "filesystem": part["filesystem"], "offset_sector": part["start_sector"], "offset_byte": part["offset_byte"]})
                self.db.add_result(self.job_id, "deleted" if item["deleted"] else "file", item)

    def _recover(self, tsk, partitions, workdir, catalog):
        artifacts = workdir / "artifacts" / "recovered"; artifacts.mkdir(parents=True, exist_ok=True)
        files = self.db.results(self.job_id, "file", limit=20000) + self.db.results(self.job_id, "deleted", limit=5000)
        interesting = {".txt", ".log", ".conf", ".json", ".xml", ".csv", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".pdf", ".zip", ".tar", ".gz", ".xz", ".7z", ".rar", ".sqlite", ".db", ".elf", ".exe", ".bin"}
        files.sort(key=lambda item: (0 if item.get("deleted") or "flag" in item["name"].lower() or Path(item["name"]).suffix.lower() in interesting else 1, item.get("size", 0)))
        recovered = []; seen = set(); total = 0; max_total = 512 * 1024 * 1024; max_files = 1000
        for item in files:
            if len(recovered) >= max_files:
                self.warnings.append("artifact recovery stopped at the 2500-file safety limit"); break
            if item["type"].startswith(("d/", "V/")) or item["size"] <= 0 or item["size"] > 64 * 1024 * 1024: continue
            key = (item["partition"], item["inode"])
            if key in seen: continue
            if total + item["size"] > max_total:
                self.warnings.append("artifact recovery stopped at the 512 MB safety limit"); break
            seen.add(key)
            part = next((p for p in partitions if p["number"] == item["partition"]), None)
            if not part: continue
            target = artifacts / f"p{part['number']}_i{item['inode']}_{safe_filename(item['name'])}"
            deleted = bool(item["deleted"])
            ok = target.exists() and target.stat().st_size > 0
            if not ok: ok = tsk.recover(part["start_sector"], item["inode"], target, deleted)
            status = "RECOVERED" if deleted and ok else "VISIBLE" if ok else "UNRECOVERABLE"
            item["recovery_status"] = status; item["integrity_percent"] = 80 if deleted and ok else 100 if ok else 0
            if ok:
                total += target.stat().st_size
                record = catalog.register(target, name_original=item["name"], original_path=item.get("original_path", item["name"]), filesystem=part["filesystem"], partition=part["number"], inode=item["inode"], absolute_offset=None, partition_offset=None, partition_base_byte=part["offset_byte"], partition_base_sector=part["start_sector"], method="icat deleted inode" if deleted else "icat filesystem", status=status, confidence=85 if deleted else 100)
                self.db.add_result(self.job_id, "recovered", record); recovered.append(record)
                tsk.inode_stats(part["start_sector"], item["inode"])
            elif deleted:
                self.db.add_result(self.job_id, "recovered", {**item, "status": "UNRECOVERABLE", "confidence": 0})
        return recovered

    def _filesystem_residue(self, tsk, partitions, workdir, catalog):
        records = []; root = workdir / "artifacts" / "residue"
        for part in partitions:
            if part["status"] != "allocated" or part["filesystem"] == "unknown": continue
            for mode, limit in (("slack", 16 * 1024 * 1024), ("unallocated", 64 * 1024 * 1024)):
                target = root / f"p{part['number']}-{mode}.bin"
                if target.exists() and target.stat().st_size == 0: target.unlink()
                ok, truncated = (True, False) if target.exists() else tsk.dump_blocks(part["start_sector"], target, mode, limit)
                if ok:
                    record = catalog.register(target, name_original=target.name, original_path=f"partition {part['number']}/{mode}", filesystem=part["filesystem"], partition=part["number"], inode=None, absolute_offset=None, partition_offset=None, partition_base_byte=part["offset_byte"], partition_base_sector=part["start_sector"], method=f"blkls {mode}", status="PARTIAL" if truncated else "RECOVERED", confidence=65 if mode == "slack" else 55)
                    records.append(record)
        return records
