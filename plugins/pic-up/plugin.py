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
        """Select supported streams, images and archives without matching every file."""
        detected = set(asset.get("detected_types", []))
        if "disk_image" in detected:
            return {
                "compatible": False,
                "score": 0.0,
                "reasons": ["Immagine disco affidata ai plugin filesystem"],
            }
        extension = str(asset.get("extension", "")).lower()
        mime = str(asset.get("mime", "")).lower()
        header = bytes.fromhex(asset.get("header_hex", ""))
        pcap = "pcap" in detected or asset.get("type") == "pcap" or header[:4] in {
            b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a",
            b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
        }
        image = mime.startswith("image/") or header.startswith((
            b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a",
            b"BM", b"RIFF",
        ))
        archive = "archive" in detected or header.startswith((
            b"PK\x03\x04", b"PK\x05\x06", b"7z\xbc\xaf\x27\x1c", b"\x1f\x8b",
        ))
        focused = pcap or image or archive or extension in {
            ".pcap", ".pcapng", ".cap", ".jpg", ".jpeg", ".png", ".gif",
            ".bmp", ".webp", ".zip", ".7z", ".tar", ".gz", ".xz", ".zst",
        }
        return {
            "compatible": focused,
            "score": 0.82 if focused else 0.5,
            "reasons": ["Formato supportato dal triage pic-up"] if focused else [],
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
