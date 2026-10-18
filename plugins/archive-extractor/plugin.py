import stat
import zipfile
from pathlib import Path, PurePosixPath
from app.core.plugin import BasePlugin


class Plugin(BasePlugin):
    def can_handle(self, asset, context):
        valid = bool(asset.get("path") and zipfile.is_zipfile(asset["path"]))
        return {
            "compatible": valid,
            "score": 0.98 if valid else 0,
            "reasons": ["Directory ZIP valida"] if valid else [],
        }

    def analyze(self, asset, context, reporter):
        from app.core.unlock_requests import request as unlock_request
        output = Path(context["output_dir"])
        remaining = context["output_bytes"]
        derived = []
        rows = []
        warnings = []
        unlock_requests = []
        with zipfile.ZipFile(asset["path"]) as archive:
            for index, member in enumerate(archive.infolist()):
                if member.is_dir():
                    continue
                if member.flag_bits & 1:
                    unlock_requests.append(unlock_request(asset.get("id", ""), "zipcrypto", "archive-extractor", ["zip_adapter"], internal_path=member.filename))
                    rows.append({"name": member.filename, "size": member.file_size, "status": "encrypted"})
                    continue
                if len(derived) >= 64:
                    warnings.append("Limite 64 membri estratti")
                    break
                name = PurePosixPath(member.filename.replace("\\", "/"))
                if name.is_absolute() or ".." in name.parts or stat.S_ISLNK(member.external_attr >> 16):
                    warnings.append("Membro non sicuro ignorato: " + member.filename)
                    continue
                if member.file_size > remaining or member.file_size > 16 * 1024**2:
                    warnings.append("Budget estrazione: " + member.filename)
                    continue
                target = output / f"{index}-{name.name}"
                try:
                    written = 0
                    with archive.open(member) as source, target.open("xb") as destination:
                        while block := source.read(min(65536, remaining + 1)):
                            written += len(block)
                            remaining -= len(block)
                            if remaining < 0:
                                raise ValueError("Budget estrazione esaurito")
                            destination.write(block)
                    derived.append(
                        {
                            "path": str(target),
                            "name": name.name,
                            "method": "ZIP extraction with CRC verification",
                            "offset": member.header_offset,
                        }
                    )
                    rows.append(
                        {
                            "name": member.filename,
                            "size": written,
                            "crc": f"{member.CRC:08x}",
                            "offset": member.header_offset,
                        }
                    )
                    reporter.phase("Estratto " + member.filename)
                except (ValueError, RuntimeError, zipfile.BadZipFile) as exc:
                    target.unlink(missing_ok=True)
                    warnings.append(str(exc))
        return {
            "summary": f"{len(derived)} file estratti",
            "confidence": 1,
            "derived_assets": derived,
            "sections": [{"id": "inventory", "data": rows}],
            "warnings": warnings,
            "unlock_requests": unlock_requests,
            "status": "partial" if warnings else "completed",
        }
