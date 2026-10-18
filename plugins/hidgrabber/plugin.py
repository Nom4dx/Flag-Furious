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
        output.mkdir()
        args = tool.build_parser().parse_args(
            [asset["path"], "--json", "--output-dir", str(output), "--timeout", "30", "--color", "never"]
        )
        args.flag_prefix = context.get("prefixes") or None
        reporter.phase("Decodifica report USB HID")
        result = tool.analyze(args)
        flags = [
            {
                "value": item["value"],
                "source": item.get("source"),
                "method": "HID decode: " + item.get("chain", "plain text"),
                "confidence": 0.9 if item.get("chain") in (None, "plain") else 0.75,
                "classification": "candidate",
            }
            for item in result.get("matches", [])
            if item.get("kind") == "flag" and item.get("value")
        ]
        artifacts = [
            {"path": str(p), "name": p.name, "method": "HIDGrabber"}
            for p in output.rglob("*")
            if p.is_file() and not p.is_symlink()
        ]
        return {
            "summary": "Decodifica HID completata",
            "confidence": 0.9,
            "sections": [{"id": "analysis", "data": result}],
            "artifacts": artifacts,
            "flags": flags,
            "findings": flags,
            "warnings": result.get("diagnostics", []),
            "metrics": result.get("inventory", {}),
        }
