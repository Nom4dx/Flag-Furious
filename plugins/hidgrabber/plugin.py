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
            [asset["path"], "--json", "--output-dir", str(output), "--timeout", "30", "--color", "never", "--skip-hash"]
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
                    "confidence": 0.75 if layered else 0.9,
                    "classification": "candidate",
                }
            )
        artifacts = [
            {"path": str(p), "name": p.name, "method": "HIDGrabber"}
            for p in output.rglob("*")
            if p.is_file() and not p.is_symlink()
        ]
        return {
            "summary": "Decodifica HID completata" + (" su vista parziale" if asset.get("partial_input") else ""),
            "status": "partial" if asset.get("partial_input") or result.get("diagnostics") else "completed",
            "confidence": 0.9,
            "sections": [{"id": "analysis", "data": result}],
            "artifacts": artifacts,
            "flags": flags,
            "findings": flags,
            "warnings": result.get("diagnostics", []) + (
                ["PCAP troncato dal byte budget: i risultati coprono solo i byte visibili."]
                if asset.get("partial_input") else []
            ),
            "metrics": result.get("inventory", {}),
        }
