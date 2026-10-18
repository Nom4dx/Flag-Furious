from __future__ import annotations

import shutil
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from .cases import CaseStore
from .extract import extract_recursive
from .scanner import ScanConfig, generated_regexes, scan_stream
from .util import hashes, iter_files, mime_for, sha256_file
from .modules import cache, git_forensics, history, legacy, reference_diff, slack, virtual

Progress = Callable[[str, int], None]


class Pipeline:
    def __init__(self, store: CaseStore):
        self.store = store
        self.cancelled: set[str] = set()
        self.lock = threading.Lock()

    def cancel(self, case_id: str) -> None:
        with self.lock:
            self.cancelled.add(case_id)

    def _cancelled(self, case_id: str) -> bool:
        with self.lock:
            return case_id in self.cancelled

    def run(self, case_id: str, *, only: str | None = None) -> None:
        manifest = self.store.load(case_id)
        case_dir = self.store.path(case_id)
        evidence = case_dir / manifest["original"]
        reference = case_dir / manifest["reference"] if manifest.get("reference") else None
        output = case_dir / manifest["output"]
        configured = manifest.get("configuration", {})
        prefixes = tuple(item.strip() for item in configured.get("prefixes", "").split(",") if item.strip())
        config = ScanConfig(prefixes=prefixes or ScanConfig().prefixes, regex=configured.get("regex") or None,
                            case_sensitive=bool(configured.get("case_sensitive")))
        config.max_input_bytes = max(0, min(int(configured.get("byte_budget", 256 * 1024 * 1024)), 256 * 1024 * 1024))
        manifest["configuration"]["generated_regexes"] = generated_regexes(config)
        phases = [only] if only else ["metadata", "extract", "virtual", "legacy", "git", "diff", "slack", "cache", "history", "scan"]
        manifest.update(status="running", phase=phases[0], progress=1)
        self.store.save(case_id, manifest)
        try:
            roots = [evidence]
            for index, phase in enumerate(phases):
                if self._cancelled(case_id):
                    manifest.update(status="cancelled", phase="cancelled")
                    break
                manifest["phase"] = phase
                manifest["progress"] = int(index / max(1, len(phases)) * 100)
                manifest["logs"].append({"timestamp": datetime.now(UTC).isoformat(), "module": phase, "message": f"Starting {phase}"})
                self.store.save(case_id, manifest)
                try:
                    if phase == "metadata":
                        manifest["metadata"] = {**hashes(evidence), "name": evidence.name, "mime": mime_for(evidence), "mtime": datetime.fromtimestamp(evidence.stat().st_mtime, UTC).isoformat()}
                    elif phase == "extract":
                        extracted, warnings = extract_recursive(evidence, output / "files")
                        roots = [evidence, *extracted]
                        manifest["warnings"].extend(warnings)
                        for path in extracted:
                            self.store.add_artifact(manifest, case_dir, path, source=str(evidence), module="extract", method="bounded-recursive-extraction")
                    elif phase == "virtual":
                        disk_suffixes = {".qcow", ".qcow2", ".qed", ".vmdk", ".vdi", ".vhd", ".vhdx", ".iso", ".raw", ".img", ".dd"}
                        targets = [path for root in roots for path in iter_files(root)
                                   if virtual.identify(path)["format"] != "raw" or path.suffix.lower() in disk_suffixes]
                        module_result = {"images": []}
                        for path in targets or [evidence]:
                            info = virtual.analyze(path, config)
                            module_result["images"].append(_serial(info))
                            self.store.add_findings(manifest, info["findings"])
                            if info["metadata"].get("format") in {"qcow2", "qcow", "vmdk", "vdi", "vhd", "vhdx", "qed"}:
                                raw, commands, warnings = virtual.materialize_copy(path, output / "qcow" / sha256_file(path)[:12])
                                info["commands"].extend(commands); manifest["warnings"].extend(warnings)
                                if raw:
                                    roots.append(raw)
                                    self.store.add_artifact(manifest, case_dir, raw, source=str(path), module="virtual", method="qemu-img-convert-private-copy", status="snapshot")
                        manifest["modules"][phase] = module_result
                    elif phase == "legacy":
                        compressed_suffixes = {".gz", ".xz", ".zst", ".zip", ".7z", ".rar", ".tar"}
                        images = [path for path in roots if path.is_file() and not (len(roots) > 1 and path.suffix.lower() in compressed_suffixes)]
                        reports = []
                        for path in images:
                            report = legacy.analyze(path, config, output / "legacy" / sha256_file(path)[:12])
                            reports.append(_serial(report)); self.store.add_findings(manifest, report["findings"])
                        known_artifacts = {a["path"] for a in manifest["artifacts"]}
                        for recovered in iter_files(output / "legacy"):
                            relative = str(recovered.relative_to(case_dir))
                            if recovered.is_file() and relative not in known_artifacts:
                                item = self.store.add_artifact(manifest, case_dir, recovered, source=str(evidence), module="legacy", method="tsk_recover-all", status="recovered", confidence=0.9)
                                known_artifacts.add(relative)
                                with recovered.open("rb") as handle:
                                    self.store.add_findings(manifest, scan_stream(handle, source=item.source, path=item.path, module="legacy", config=config))
                        manifest["modules"][phase] = {"images": reports}
                    elif phase == "git":
                        scan_roots = [output / "files", output / "legacy", output / "qcow"]
                        combined = []
                        for root in scan_roots:
                            if root.exists():
                                report = git_forensics.analyze(root, output / "git", config)
                                combined.extend(report["repositories"]); self.store.add_findings(manifest, report["findings"])
                        manifest["modules"][phase] = {"repositories": [_serial(x) for x in combined], "count": len(combined)}
                        for recovered in (output / "git").rglob("*.bin"):
                            if not any(a["path"] == str(recovered.relative_to(case_dir)) for a in manifest["artifacts"]):
                                self.store.add_artifact(manifest, case_dir, recovered, source="git object", module="git", method="git-cat-file", status="recovered", confidence=0.95)
                    elif phase == "diff":
                        report = reference_diff.analyze(evidence, reference, config)
                        manifest["modules"][phase] = _serial(report); self.store.add_findings(manifest, report["findings"])
                    elif phase == "slack":
                        report = slack.analyze(output / "files", config, configured.get("timezone", "Europe/Rome"))
                        manifest["modules"][phase] = _serial(report); self.store.add_findings(manifest, report["findings"])
                    elif phase == "cache":
                        report = cache.analyze(output / "files", output / "cache", config)
                        manifest["modules"][phase] = _serial(report); self.store.add_findings(manifest, report["findings"])
                    elif phase == "history":
                        report = history.analyze(output / "files", output / "history", config)
                        manifest["modules"][phase] = _serial(report); self.store.add_findings(manifest, report["findings"])
                        manifest["timeline"].extend(report["events"])
                    elif phase == "scan":
                        for path in roots:
                            if path.is_file() and path.stat().st_size <= 128 * 1024 * 1024:
                                with path.open("rb") as handle:
                                    self.store.add_findings(manifest, scan_stream(handle, source=str(evidence), path=str(path), module="scan", config=config))
                    manifest["modules"].setdefault(phase, {})["status"] = "complete"
                except Exception as exc:
                    manifest["errors"].append(f"{phase}: {type(exc).__name__}: {exc}")
                    manifest["modules"][phase] = {"status": "error", "error": str(exc)}
            else:
                manifest.update(status="complete", phase="complete", progress=100)
            manifest["result"] = "flags_found" if manifest["findings"] else "no_flags_found"
        except Exception as exc:
            manifest.update(status="failed", phase="failed")
            manifest["errors"].append(f"pipeline: {type(exc).__name__}: {exc}")
        finally:
            manifest["warnings"].extend(config.diagnostics)
            self.store.save(case_id, manifest)
            with self.lock:
                self.cancelled.discard(case_id)


def _serial(value: Any) -> Any:
    if hasattr(value, "dict"):
        return value.dict()
    if isinstance(value, dict):
        return {key: _serial(item) for key, item in value.items() if key != "body"}
    if isinstance(value, list):
        return [_serial(item) for item in value]
    return value
