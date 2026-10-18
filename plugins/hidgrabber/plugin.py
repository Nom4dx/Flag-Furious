from pathlib import Path
from app.core.plugin import BasePlugin
import HIDGrabber as tool


class Plugin(BasePlugin):
    def can_handle(self, asset, context):
        valid = tool.capture_magic(Path(asset["path"]))
        return {
            "compatible": valid,
            "score": 0.95 if valid else 0,
            "reasons": ["Header PCAP/PCAPNG verificato"] if valid else [],
        }

    def analyze(self, asset, context, reporter):
        output = Path(context["output_dir"]) / "hid"
        output.mkdir(parents=True, exist_ok=True)
        args = tool.build_parser().parse_args(
            [asset["path"], "--json", "--output-dir", str(output), "--timeout", "30", "--color", "never", "--skip-hash", "--no-report-file"]
        )
        args.flag_prefix = context.get("prefixes") or None
        reporter.phase("Decodifica report USB HID")
        result = tool.analyze(args)
        file_info = result.get("file", {})
        analyzed_sha256 = file_info.get("sha256")
        analyzed_size = file_info.get("size")
        file_info.update(
            {
                "path": asset.get("name", file_info.get("path")),
                "sha256": asset.get("hashes", {}).get("sha256", analyzed_sha256),
                "size": asset.get("size", analyzed_size),
                "analyzed_sha256": analyzed_sha256,
                "analyzed_bytes": asset.get("visible_bytes", analyzed_size),
                "partial_input": bool(asset.get("partial_input")),
            }
        )
        flags = []
        for item in result.get("matches", []):
            if item.get("kind") != "flag" or not item.get("value"):
                continue
            source = item.get("source", "")
            layered = "): " in source
            flags.append(
                {
                    "value": item["value"],
                    "source": source,
                    "method": "HID decoded layer" if layered else "HID keyboard layout",
                "text_start": item.get("text_start"),
                "text_end": item.get("text_end"),
                "text_offset_unit": item.get("text_offset_unit"),
                    "confidence": 0.75 if layered else 0.9,
                    "classification": "candidate",
                }
            )
        artifacts, artifact_warnings = [], []
        artifact_budget = max(0, int(context.get("output_bytes", 0)))
        exported_bytes = 0
        output_root = output.resolve()
        for item in result.get("artifacts", []):
            try:
                path = Path(item["path"])
                if path.is_symlink() or not path.resolve().is_relative_to(output_root) or not path.is_file():
                    artifact_warnings.append("Artefatto HID non regolare o fuori dalla directory di output escluso")
                    continue
                size = path.stat().st_size
            except (KeyError, OSError, TypeError):
                artifact_warnings.append("Artefatto HID non accessibile escluso")
                continue
            if exported_bytes + size > artifact_budget or len(artifacts) >= 64:
                artifact_warnings.append("Budget o limite artefatti HID raggiunto; alcuni file non sono stati esportati")
                continue
            exported_bytes += size
            artifacts.append({
                **item,
                "path": str(path),
                "name": path.name,
                "source_asset_id": asset.get("id"),
                "source": "Report HID derivati dalla cattura PCAP/PCAPNG",
                "method": "HIDGrabber decoded report",
                "status": "active",
            })
        return {
            "summary": "Decodifica HID completata" + (" su vista parziale" if asset.get("partial_input") else ""),
            "status": "partial" if asset.get("partial_input") or result.get("diagnostics") or artifact_warnings else "completed",
            "confidence": 0.9,
            "sections": [{"id": "analysis", "data": result, "status": "partial" if asset.get("partial_input") or result.get("diagnostics") or artifact_warnings else "completed"}],
            "artifacts": artifacts,
            "flags": flags,
            "findings": flags,
            "warnings": result.get("diagnostics", []) + artifact_warnings + (
                ["PCAP troncato dal byte budget: i risultati coprono solo i byte visibili."]
                if asset.get("partial_input") else []
            ),
            "metrics": {
                **result.get("inventory", {}),
                "artifacts_exported": len(artifacts),
                "artifact_bytes_exported": exported_bytes,
                "artifact_export_limited": bool(artifact_warnings),
            },
        }
