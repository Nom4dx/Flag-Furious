import stat
import struct
import zipfile
from pathlib import Path, PurePosixPath
from app.core.plugin import BasePlugin


def _protection_type(member):
    """Distinguish WinZip AES extra field from traditional ZipCrypto."""
    extra = member.extra
    cursor = 0
    while cursor + 4 <= len(extra):
        field_id, size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        end = cursor + size
        if end > len(extra):
            break
        # WinZip AES: vendor ID "AE", strength byte, actual compression method.
        if field_id == 0x9901 and size >= 7 and extra[cursor + 2:cursor + 4] == b"AE":
            return "zip_aes"
        cursor = end
    return "zipcrypto"


class Plugin(BasePlugin):
    def can_handle(self, asset, context):
        # Matchers receive only a 64 KiB bounded view. ``is_zipfile`` checks the
        # end of the file for EOCD, so it rejects many valid larger ZIPs when
        # called here. Treat the bounded signature as a candidate and let the
        # full analysis validate the central directory and member CRCs.
        header = bytes.fromhex(asset.get("header_hex", ""))
        signatures = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
        valid = any(header.find(signature) >= 0 for signature in signatures)
        return {
            "compatible": valid,
            "score": 0.82 if valid else 0,
            "reasons": ["Firma ZIP candidata; validazione strutturale in analisi"] if valid else [],
        }

    def analyze(self, asset, context, reporter):
        from app.core.unlock_requests import request as unlock_request
        output = Path(context["output_dir"])
        remaining = context["output_bytes"]
        derived = []
        rows = []
        warnings = []
        unlock_requests = []
        if asset.get("partial_input"):
            warnings.append(
                f"Vista parziale: {asset.get('visible_bytes', 0)} di {asset.get('size', 0)} byte; "
                "l'indice ZIP potrebbe trovarsi oltre il limite di lettura."
            )
        try:
            archive = zipfile.ZipFile(asset["path"])
        except (OSError, EOFError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            warnings.append(f"Indice ZIP non leggibile nella vista disponibile: {exc}")
            return {
                "summary": "Firma ZIP candidata; indice non validato",
                "confidence": 0.35,
                "sections": [{"id": "inventory", "data": rows}],
                "warnings": warnings,
                "status": "partial",
            }
        with archive:
            for index, member in enumerate(archive.infolist()):
                if member.is_dir():
                    continue
                if member.flag_bits & 1:
                    protection = _protection_type(member)
                    unlock_requests.append(unlock_request(asset.get("id", ""), protection, "archive-extractor", ["zip_adapter"], internal_path=member.filename))
                    rows.append({"name": member.filename, "size": member.file_size, "status": "encrypted"})
                    warnings.append("Membro cifrato; l'estrazione richiede una credenziale: " + member.filename)
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
