from pathlib import Path
import os
from app.core.plugin import BasePlugin
from picup_web.cases import CaseStore
from picup_web.pipeline import Pipeline


def _hub_flags(findings):
    """Convert GitHappens flag findings to the normalized Hub contract."""
    flags = []
    for finding in findings:
        value = finding.get("value")
        if not value or finding.get("kind") not in {"flag", "flag_candidate"}:
            continue
        flags.append(
            {
                "value": value,
                "confidence": float(finding.get("confidence", 0.7)),
                "source": finding.get("path") or finding.get("source"),
                "offset": finding.get("offset"),
                "method": finding.get("method", "GitHappens static scan"),
                "classification": "high_confidence"
                if float(finding.get("confidence", 0)) >= 0.85
                else "candidate",
            }
        )
    return flags


def _bounded_artifacts(result, directory, output_bytes):
    """Select useful regular artifacts without losing the structured result.

    GitHappens can recover an entire filesystem. Exporting all recovered bytes
    through JSON IPC would discard the completed analysis when the output budget
    is exceeded. Small and high-confidence artifacts are therefore exported
    first; the complete artifact inventory remains in the analysis section.
    """
    candidates = []
    root = directory.resolve()
    for item in result.get("artifacts", []):
        path = (directory / item.get("path", "")).resolve()
        if path.is_symlink() or not path.is_relative_to(root) or not path.is_file():
            continue
        candidates.append((item, path, path.stat().st_size))
    candidates.sort(
        key=lambda row: (
            0 if row[0].get("module") in {"git", "flag_candidates"} else 1,
            -float(row[0].get("confidence", 0)),
            row[2],
        )
    )
    exported, used, omitted = [], 0, 0
    for item, path, size in candidates:
        if used + size > output_bytes:
            omitted += 1
            continue
        used += size
        exported.append(
            {
                "path": str(path),
                "name": path.name,
                "method": item.get("extraction_method", "GitHappens"),
                "offset": item.get("offset"),
                "confidence": item.get("confidence"),
            }
        )
    return exported, omitted, used


def _bounded_directory_artifacts(directory, output_bytes, source_asset_id):
    candidates, scanned, limited = [], 0, False
    for base, dirs, files in os.walk(directory, followlinks=False):
        dirs[:] = sorted(name for name in dirs if not (Path(base) / name).is_symlink())
        for name in sorted(files):
            scanned += 1
            if scanned > 10_000:
                limited = True
                break
            path = Path(base) / name
            if path.is_symlink() or not path.is_file():
                continue
            try:
                candidates.append((path.stat().st_size, path))
            except OSError:
                continue
        if limited:
            break
    candidates.sort(key=lambda row: (row[0], str(row[1])))
    artifacts, used, omitted = [], 0, int(limited)
    for size, path in candidates:
        if len(artifacts) >= 64 or used + size > output_bytes:
            omitted += 1
            continue
        used += size
        artifacts.append({
            "path": str(path), "name": path.name,
            "method": "GitHappens directory analysis",
            "source_asset_id": source_asset_id, "size": size,
        })
    return artifacts, omitted, used


class Plugin(BasePlugin):
    def can_handle(self, asset, context):
        """Avoid launching the multi-module pipeline on arbitrary binary files."""
        detected = set(asset.get("detected_types", []))
        if asset.get("type") == "directory":
            return {"compatible": True, "score": 0.75, "reasons": ["Albero di file da esaminare"]}
        if "disk_image" in detected:
            return {"compatible": True, "score": 0.9, "reasons": ["Immagine disco identificata"]}
        if "archive" in detected:
            return {"compatible": True, "score": 0.76, "reasons": ["Archivio da esaminare per repository e cache"]}
        extension = str(asset.get("extension", "")).lower()
        if extension in {".bundle", ".git", ".qcow", ".qcow2", ".vmdk", ".vhd", ".vhdx", ".img", ".dd"}:
            return {"compatible": True, "score": 0.72, "reasons": ["Estensione compatibile con immagine o bundle Git"]}
        return {"compatible": False, "score": 0.0, "reasons": []}

    def analyze(self, asset, context, reporter):
        if asset["type"] == "directory":
            from picup_web.modules import git_forensics, cache, history, slack
            from picup_web.scanner import ScanConfig
            from picup_web.pipeline import _serial

            root = Path(asset["path"])
            output = Path(context["output_dir"])
            config = ScanConfig(prefixes=tuple(context.get("prefixes", [])))
            results = {}
            findings = []
            warnings = []
            if asset.get("partial_input"):
                warnings.append("Directory vista solo parziale: alcuni file possono non essere stati acquisiti dal core.")
            timeline = []
            for name, analyze in [
                ("git", lambda: git_forensics.analyze(root, output / "git", config)),
                ("cache", lambda: cache.analyze(root, output / "cache", config)),
                ("history", lambda: history.analyze(root, output / "history", config)),
                ("slack", lambda: slack.analyze(root, config)),
            ]:
                reporter.phase(name)
                try:
                    value = analyze()
                    results[name] = _serial(value)
                    findings.extend(_serial(value.get("findings", [])))
                    timeline.extend(_serial(value.get("events", [])))
                except Exception as exc:
                    warnings.append(f"{name}: {exc}")
            artifacts, omitted, artifact_bytes = _bounded_directory_artifacts(
                output, context["output_bytes"], asset.get("id")
            )
            if omitted:
                warnings.append(f"{omitted} artefatti non esportati: limite 64 file o budget output.")
            return {
                "summary": "Git, cache, history e Slack della directory",
                "status": "partial" if warnings or asset.get("partial_input") or omitted else "completed",
                "confidence": 0.9,
                "sections": [{"id": "analysis", "data": results}],
                "artifacts": artifacts,
                "findings": findings,
                "timeline": timeline,
                "warnings": warnings,
                "metrics": {"artifacts_exported": len(artifacts), "artifacts_omitted": omitted, "artifact_bytes_exported": artifact_bytes},
            }
        previous = [None]

        class ObservedStore(CaseStore):
            def save(self, case_id, manifest):
                if manifest["phase"] != previous[0]:
                    previous[0] = manifest["phase"]
                    reporter.phase(manifest["phase"])
                return super().save(case_id, manifest)

        store = ObservedStore(Path(context["output_dir"]) / "git-cases")
        input_path = Path(asset["path"])
        input_size = input_path.stat().st_size
        class LimitedStream:
            def __init__(self, stream, limit):
                self.stream, self.remaining = stream, limit
            def read(self, size=-1):
                if self.remaining <= 0:
                    return b""
                amount = self.remaining if size < 0 else min(size, self.remaining)
                block = self.stream.read(amount)
                self.remaining -= len(block)
                return block

        with input_path.open("rb") as stream:
            case = store.create(
                asset["name"], asset["name"], LimitedStream(stream, context["byte_budget"]),
                max_bytes=context["byte_budget"],
            )
        case["configuration"] = {"prefixes": ",".join(context.get("prefixes", []))}
        store.save(case["id"], case)
        Pipeline(store).run(case["id"])
        result = store.load(case["id"])
        directory = store.path(case["id"])
        artifacts, omitted, exported_bytes = _bounded_artifacts(
            result, directory, context["output_bytes"]
        )
        warnings = list(result["warnings"])
        input_partial = bool(asset.get("partial_input")) or input_size > context["byte_budget"]
        if input_partial:
            if input_size > context["byte_budget"]:
                warnings.append(
                    f"Input copiato fino al limite di {context['byte_budget']} byte su {input_size}; risultati parziali."
                )
            else:
                warnings.append("Input già parziale nel core; risultati riferiti alla vista disponibile.")
        if omitted:
            warnings.append(
                f"{omitted} artefatti non esportati: budget output; inventario e finding conservati."
            )
        flags = _hub_flags(result["findings"])
        if result["status"] == "failed":
            status = "failed"
        elif result["status"] == "cancelled":
            status = "cancelled"
        elif result["errors"] or warnings or input_partial:
            status = "partial"
        else:
            status = "completed"
        return {
            "summary": f"GitHappens: {result['status']}",
            "status": status,
            "confidence": 0.9,
            "sections": [
                {"id": "analysis", "data": result["modules"]},
                {"id": "timeline", "data": result["timeline"]},
                {"id": "logs", "data": result["logs"]},
            ],
            "artifacts": artifacts,
            "timeline": result["timeline"],
            "findings": result["findings"],
            "flags": flags,
            "warnings": warnings,
            "errors": result["errors"],
            "metrics": {
                "artifacts_catalogued": len(result["artifacts"]),
                "artifacts_exported": len(artifacts),
                "artifacts_omitted": omitted,
                "artifact_bytes_exported": exported_bytes,
            },
        }
