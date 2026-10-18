import stat
import struct
import zipfile
import hashlib
import zlib
from pathlib import Path, PurePosixPath
from app.core.plugin import BasePlugin

MAX_INVENTORY_MEMBERS = 10_000
MAX_CENTRAL_DIRECTORY_BYTES = 4 * 1024**2
MAX_UNLOCK_REQUESTS = 256
MAX_MEMBER_BYTES = 16 * 1024**2
MAX_COMPRESSION_RATIO = 1_000


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


def _bounded_text(value, limit=512):
    """Bound untrusted ZIP names by UTF-8 bytes before placing them in JSON."""
    return value.replace("\x00", "�").encode("utf-8", errors="replace")[:limit].decode(
        "utf-8", errors="ignore"
    )


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
        omitted_unlock_requests = 0
        if asset.get("partial_input"):
            warnings.append(
                f"Vista parziale: {asset.get('visible_bytes', 0)} di {asset.get('size', 0)} byte; "
                "l'indice ZIP potrebbe trovarsi oltre il limite di lettura."
            )
        try:
            with Path(asset["path"]).open("rb") as source:
                end_record = zipfile._EndRecData(source)
            if end_record is None:
                raise zipfile.BadZipFile("EOCD non trovato")
            central_directory_bytes = int(end_record[zipfile._ECD_SIZE])
            if central_directory_bytes > MAX_CENTRAL_DIRECTORY_BYTES:
                warnings.append(
                    f"Indice ZIP oltre budget: {central_directory_bytes} byte, "
                    f"limite {MAX_CENTRAL_DIRECTORY_BYTES}"
                )
                return {
                    "summary": "Firma ZIP candidata; indice oltre il budget",
                    "confidence": 0.35,
                    "sections": [{"id": "inventory", "data": rows}],
                    "warnings": warnings,
                    "status": "partial",
                }
        except (OSError, EOFError, zipfile.BadZipFile, zipfile.LargeZipFile,
                IndexError, TypeError, ValueError, struct.error, OverflowError) as exc:
            warnings.append(f"Indice ZIP non leggibile nella vista disponibile: {str(exc)[:240]}")
            return {
                "summary": "Firma ZIP candidata; indice non validato",
                "confidence": 0.35,
                "sections": [{"id": "inventory", "data": rows}],
                "warnings": warnings,
                "status": "partial",
            }
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
                if index >= MAX_INVENTORY_MEMBERS:
                    warnings.append(f"Limite inventario: primi {MAX_INVENTORY_MEMBERS} membri")
                    break
                if member.is_dir():
                    continue
                if member.flag_bits & 1:
                    protection = _protection_type(member)
                    if len(unlock_requests) < MAX_UNLOCK_REQUESTS:
                        unlock_requests.append(
                            unlock_request(
                                asset.get("id", ""), protection, "archive-extractor", ["zip_adapter"],
                                internal_path=member.filename,
                            )
                        )
                    else:
                        omitted_unlock_requests += 1
                    rows.append({"name": _bounded_text(member.filename), "size": member.file_size, "status": "encrypted"})
                    warnings.append("Membro cifrato; l'estrazione richiede una credenziale: " + _bounded_text(member.filename, 256))
                    continue
                if len(derived) >= 64:
                    warnings.append("Limite 64 membri estratti")
                    break
                name = PurePosixPath(member.filename.replace("\\", "/"))
                if name.is_absolute() or ".." in name.parts or stat.S_ISLNK(member.external_attr >> 16):
                    warnings.append("Membro non sicuro ignorato: " + _bounded_text(member.filename, 256))
                    continue
                ratio = member.file_size / max(member.compress_size, 1)
                if member.file_size > remaining or member.file_size > MAX_MEMBER_BYTES:
                    warnings.append("Budget estrazione: " + _bounded_text(member.filename, 256))
                    continue
                if ratio > MAX_COMPRESSION_RATIO:
                    warnings.append(
                        f"Rapporto di compressione {ratio:.1f}:1 oltre il limite {MAX_COMPRESSION_RATIO}: "
                        + _bounded_text(member.filename, 256)
                    )
                    continue
                leaf = _bounded_text(name.name, 180) or "member"
                target = output / f"{index}-{leaf}"
                try:
                    written = 0
                    digest = hashlib.sha256()
                    with archive.open(member) as source, target.open("xb") as destination:
                        while block := source.read(min(65536, remaining + 1)):
                            written += len(block)
                            remaining -= len(block)
                            if remaining < 0:
                                raise ValueError("Budget estrazione esaurito")
                            destination.write(block)
                            digest.update(block)
                    derived.append(
                        {
                            "path": str(target),
                            "name": name.name,
                            "method": "ZIP extraction with CRC verification",
                            "source_asset_id": asset.get("id"),
                            "source_member": _bounded_text(member.filename),
                            "source_offset": member.header_offset,
                            "source_size": member.file_size,
                            "compressed_size": member.compress_size,
                            "sha256": digest.hexdigest(),
                        }
                    )
                    rows.append(
                        {
                            "name": _bounded_text(member.filename),
                            "size": written,
                            "crc": f"{member.CRC:08x}",
                            "offset": member.header_offset,
                            "compressed_size": member.compress_size,
                            "compression_ratio": round(ratio, 2),
                            "sha256": digest.hexdigest(),
                        }
                    )
                    reporter.phase("Estratto " + _bounded_text(member.filename, 256))
                except (ValueError, RuntimeError, OSError, EOFError, NotImplementedError, zlib.error, zipfile.BadZipFile) as exc:
                    target.unlink(missing_ok=True)
                    warnings.append(f"Estrazione fallita per {_bounded_text(member.filename, 256)}: {str(exc)[:240]}")
        if omitted_unlock_requests:
            warnings.append(
                f"Richieste di sblocco omesse per limite: {omitted_unlock_requests}"
            )
        return {
            "summary": f"{len(derived)} file estratti",
            "confidence": 1,
            "derived_assets": derived,
            "sections": [{"id": "inventory", "data": rows}],
            "warnings": warnings,
            "unlock_requests": unlock_requests,
            "status": "partial" if warnings else "completed",
        }
