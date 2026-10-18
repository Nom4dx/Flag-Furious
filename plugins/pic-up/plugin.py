import importlib.util
import sys
from dataclasses import asdict
from pathlib import Path
from app.core.plugin import BasePlugin

spec = importlib.util.spec_from_file_location(
    "picup_legacy_adapter", Path(__file__).parent / "src" / "pic-up.py"
)
tool = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = tool
spec.loader.exec_module(tool)


class Plugin(BasePlugin):
    def can_handle(self, asset, context):
        """Reject filesystem images handled by the dedicated disk analyzers.

        pic-up is a broad file and stream triage tool. Running it against a complete
        disk image duplicates filesystem carving, consumes the job budget and can
        hide the focused ext4 results under unrelated output.
        """
        detected = set(asset.get("detected_types", []))
        if "disk_image" in detected:
            return {
                "compatible": False,
                "score": 0.0,
                "reasons": ["Immagine disco affidata ai plugin filesystem"],
            }
        extension = str(asset.get("extension", "")).lower()
        focused = extension in {
            ".pcap", ".pcapng", ".cap", ".jpg", ".jpeg", ".png", ".gif",
            ".bmp", ".webp", ".zip", ".7z", ".tar", ".gz",
        }
        return {
            "compatible": True,
            "score": 0.82 if focused else 0.5,
            "reasons": ["Formato supportato dal triage pic-up" if focused else "File generico analizzabile"],
        }

    def analyze(self, asset, context, reporter):
        output = Path(context["output_dir"]) / "picup"
        args = tool.build_parser().parse_args(
            [
                asset["path"],
                "--output-dir",
                str(output),
                "--json",
                "--color",
                "never",
                "--timeout",
                "30",
                "--no-ocr",
            ]
        )
        if context.get("prefixes"):
            args.flag_prefix = context["prefixes"][0]
        tool.validate_inputs(args, tool.build_parser())
        tool.configure_automatic_actions(args)
        reporter.phase("Triage file, stream e carving")
        report = asdict(tool.analyze(args))
        artifacts = [
            {"path": str(p), "name": p.name, "method": "pic-up extraction"}
            for p in output.rglob("*")
            if p.is_file() and not p.is_symlink()
        ]
        return {
            "summary": "Analisi pic-up completata",
            "confidence": 0.85,
            "sections": [{"id": "analysis", "data": report}],
            "artifacts": artifacts,
            "warnings": report.get("warnings", []),
        }
