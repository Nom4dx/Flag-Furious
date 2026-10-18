import importlib.util
import os
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


def _bounded_artifacts(root, budget, source_asset_id, excluded_paths=(), provenance=None):
    root = root.resolve()
    provenance = provenance or {}
    excluded_paths = {Path(path).resolve() for path in excluded_paths}
    candidates, scanned, limited = [], 0, False
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if not (Path(base) / name).is_symlink())
        for name in sorted(files):
            scanned += 1
            if scanned > 10_000:
                limited = True
                break
            path = Path(base) / name
            if path.is_symlink() or not path.is_file():
                continue
            if path.resolve() in excluded_paths:
                continue
            try:
                candidates.append((path.stat().st_size, path))
            except OSError:
                continue
        if limited:
            break
    candidates.sort(key=lambda row: (row[0], str(row[1])))
    artifacts, used, omitted = [], 0, 0
    for size, path in candidates:
        if len(artifacts) >= 64 or used + size > budget:
            omitted += 1
            continue
        used += size
        source = provenance.get(str(path.resolve()), {})
        kind = source.get("_kind")
        artifacts.append({
            "path": str(path),
            "name": path.name,
            "method": source.get("origin") or ("TShark object export" if kind == "exports" else "pic-up carving"),
            "source_asset_id": source_asset_id,
            "source": source.get("source") or ("PCAP/PCAPNG" if kind == "exports" else "Input byte stream"),
            "encoding": source.get("encoding"),
            "mime": source.get("mime"),
            "sha256": source.get("sha256"),
            "status": "active" if source.get("complete", True) else "partial",
            "size": size,
        })
    return artifacts, omitted + int(limited), used


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
        header = bytes.fromhex(asset.get("header_hex", ""))
        pcap = "pcap" in detected or header[:4] in {
            b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a",
            b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
        }
        image = header.startswith((
            b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a",
            b"BM",
        )) or (header.startswith(b"RIFF") and header[8:12] == b"WEBP")
        archive = "archive" in detected or header.startswith((
            b"PK\x03\x04", b"PK\x05\x06", b"7z\xbc\xaf\x27\x1c", b"\x1f\x8b",
            b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd",
        )) or header[257:262] == b"ustar"
        focused = pcap or image or archive
        return {
            "compatible": focused,
            "score": 0.9 if pcap else 0.84 if image or archive else 0.0,
            "reasons": ["Firma strutturale PCAP/PCAPNG" if pcap else "Firma immagine o archivio supportato"] if focused else [],
        }

    def analyze(self, asset, context, reporter):
        tool.MAX_RAW_SCAN_BYTES = min(tool.MAX_RAW_SCAN_BYTES, max(1, context["byte_budget"]))
        tool.MAX_EXPANDED_BYTES = min(
            tool.MAX_EXPANDED_BYTES,
            max(1, context["byte_budget"]),
            max(1, context["output_bytes"]),
        )
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
        args.flag_prefix = context.get("prefixes") or None
        tool.validate_inputs(args, tool.build_parser())
        tool.configure_automatic_actions(args)
        reporter.phase("Triage file, stream e carving")
        report = asdict(tool.analyze(args))
        file_info = report.get("file", {})
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
        flags = [
            {
                "value": item.get("value"),
                "source": item.get("source"),
                "method": "pic-up decoder: " + item.get("encoding", "plain"),
                "confidence": 0.9 if item.get("encoding", "plain") == "plain" else 0.75,
                "classification": "candidate",
            }
            for item in report.get("matches", [])
            if item.get("kind") == "flag" and item.get("value")
        ]
        warnings = list(report.get("diagnostics", []))
        # The legacy analyzer reports skipped, redacted and capped paths as
        # diagnostics without a stable severity field. Until that contract is
        # typed, any diagnostic means at least one coverage limitation exists.
        partial = bool(asset.get("partial_input") or warnings)
        provenance = {}
        for kind in ("exports", "extracted_files", "images"):
            for record in report.get(kind, []):
                path = record.get("path")
                if not path:
                    continue
                try:
                    provenance[str(Path(path).resolve())] = {**record, "_kind": kind}
                except OSError:
                    continue
        artifacts, omitted, exported_bytes = _bounded_artifacts(
            output, context["output_bytes"], asset.get("id"),
            excluded_paths=[item["path"] for item in report.get("exports", []) if not item.get("complete", True)],
            provenance=provenance,
        )
        if omitted:
            warnings.append(f"{omitted} artefatti non esportati: limite 64 file o budget output.")
            partial = True
        return {
            "summary": "Analisi pic-up completata" + (" con coverage parziale" if partial else ""),
            "status": "partial" if partial else "completed",
            "confidence": 0.85,
            "sections": [{"id": "analysis", "data": report}],
            "artifacts": artifacts,
            "flags": flags,
            "findings": [*report.get("findings", []), *flags],
            "metrics": {
                "artifacts_exported": len(artifacts),
                "artifacts_omitted": omitted,
                "artifact_bytes_exported": exported_bytes,
                "artifact_export_limited": omitted > 0,
            },
            "warnings": warnings + (
                ["Input troncato dal byte budget: i risultati coprono solo i byte visibili."]
                if asset.get("partial_input") else []
            ),
        }
