from pathlib import Path
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
            artifacts = [
                {"path": str(p), "name": p.name, "method": "GitHappens directory analysis"}
                for p in output.rglob("*")
                if p.is_file() and not p.is_symlink()
            ]
            return {
                "summary": "Git, cache, history e Slack della directory",
                "status": "partial" if warnings else "completed",
                "confidence": 0.9,
                "sections": [{"id": "analysis", "data": results}],
                "artifacts": artifacts,
                "findings": findings,
                "timeline": timeline,
                "warnings": warnings,
            }
        previous = [None]

        class ObservedStore(CaseStore):
            def save(self, case_id, manifest):
                if manifest["phase"] != previous[0]:
                    previous[0] = manifest["phase"]
                    reporter.phase(manifest["phase"])
                return super().save(case_id, manifest)

        store = ObservedStore(Path(context["output_dir"]) / "git-cases")
        with Path(asset["path"]).open("rb") as stream:
            case = store.create(asset["name"], asset["name"], stream, max_bytes=context["byte_budget"])
        case["configuration"] = {"prefixes": ",".join(context.get("prefixes", []))}
        store.save(case["id"], case)
        Pipeline(store).run(case["id"])
        result = store.load(case["id"])
        directory = store.path(case["id"])
        artifacts, omitted, exported_bytes = _bounded_artifacts(
            result, directory, context["output_bytes"]
        )
        warnings = list(result["warnings"])
        if omitted:
            warnings.append(
                f"{omitted} artefatti non esportati: budget output; inventario e finding conservati."
            )
        flags = _hub_flags(result["findings"])
        return {
            "summary": f"GitHappens: {result['status']}",
            "status": "partial" if result["errors"] else "completed",
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
