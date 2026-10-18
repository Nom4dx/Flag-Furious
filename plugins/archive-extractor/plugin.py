import stat
import struct
import zipfile
import hashlib
import zlib
from pathlib import Path, PurePosixPath, PureWindowsPath
from app.core.plugin import BasePlugin

MAX_INVENTORY_MEMBERS = 10_000
MAX_CENTRAL_DIRECTORY_BYTES = 4 * 1024**2
MAX_UNLOCK_REQUESTS = 256
MAX_MEMBER_BYTES = 16 * 1024**2
MAX_COMPRESSION_RATIO = 1_000
MAX_WARNINGS = 100


def _protection_type(member):
    """Return a verified ZIP encryption type or an explicit unknown state."""
    extra = member.extra
    cursor = 0
    aes_seen = False
    aes_valid = False
    while cursor + 4 <= len(extra):
        field_id, size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        end = cursor + size
        if field_id == 0x9901:
            aes_seen = True
            if end <= len(extra) and size == 7:
                version = int.from_bytes(extra[cursor:cursor + 2], "little")
                strength = extra[cursor + 4]
                method = int.from_bytes(extra[cursor + 5:cursor + 7], "little")
                aes_valid = (
                    extra[cursor + 2:cursor + 4] == b"AE"
                    and version in {1, 2}
                    and strength in {1, 2, 3}
                    and method != 99
                )
            else:
                return "zip_unknown"
        if end > len(extra):
            break
        cursor = end
    if aes_seen or member.compress_type == 99:
        return "zip_aes" if aes_seen and aes_valid and member.compress_type == 99 else "zip_unknown"
    return "zipcrypto"


def _bounded_text(value, limit=512):
    """Bound untrusted ZIP names by UTF-8 bytes before placing them in JSON."""
    return value.replace("\x00", "�").encode("utf-8", errors="replace")[:limit].decode(
        "utf-8", errors="ignore"
    )


def _name_metadata(value, limit=512):
    """Preserve identity when a displayed member name must be abbreviated."""
    normalized=value.replace("\x00","�")
    encoded=normalized.encode("utf-8",errors="replace")
    return {
        "name":encoded[:limit].decode("utf-8",errors="ignore"),
        "name_truncated":len(encoded)>limit,
        "name_sha256":hashlib.sha256(encoded).hexdigest(),
    }


class Plugin(BasePlugin):
    def can_handle(self, asset, context):
        # An arbitrary ZIP marker inside a binary is weak evidence. A normal
        # archive starts with a local header; SFX and empty archives need an
        # EOCD candidate from the bounded tail view instead.
        try:header=bytes.fromhex(asset.get("header_hex",""))
        except (TypeError,ValueError):header=b""
        if header.startswith(b"PK\x03\x04"):
            valid=True;score=.88;reason="Local header ZIP all'inizio dell'asset"
        else:
            valid=False;score=0;reason=""
            path=Path(asset.get("path",""))
            if path.is_file() and not path.is_symlink():
                try:
                    with path.open("rb") as source:end_record=zipfile._EndRecData(source)
                    valid=end_record is not None
                except (OSError,EOFError,zipfile.BadZipFile,IndexError,TypeError,ValueError,struct.error):
                    valid=False
                if valid:score=.74;reason="Candidato EOCD nella coda; possibile SFX o ZIP vuoto"
        return {
            "compatible": valid,
            "score": score,
            "reasons": [reason] if valid else [],
        }

    def analyze(self, asset, context, reporter):
        from app.core.unlock_requests import request as unlock_request
        output = Path(context["output_dir"])
        remaining = context["output_bytes"]
        derived = []
        rows = []
        warnings = []
        warning_set = set()
        omitted_warnings = 0
        unlock_requests = []
        omitted_unlock_requests = 0

        def warn(message):
            nonlocal omitted_warnings
            if message in warning_set:
                return
            if len(warnings) < MAX_WARNINGS:
                warnings.append(message)
                warning_set.add(message)
            else:
                omitted_warnings += 1
        if asset.get("partial_input"):
            warn(
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
                warn(
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
            warn(f"Indice ZIP non leggibile nella vista disponibile: {str(exc)[:240]}")
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
            warn(f"Indice ZIP non leggibile nella vista disponibile: {str(exc)[:240]}")
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
                    warn(f"Limite inventario: primi {MAX_INVENTORY_MEMBERS} membri")
                    break
                row = {
                    "source_asset_id": asset.get("id"),
                    **_name_metadata(member.filename),
                    "size": member.file_size,
                    "compressed_size": member.compress_size,
                    "crc": f"{member.CRC:08x}",
                    "offset": member.header_offset,
                    "status": "pending",
                }
                rows.append(row)
                name = PurePosixPath(member.filename.replace("\\", "/"))
                windows_name = PureWindowsPath(member.filename)
                unsafe = (
                    name.is_absolute()
                    or windows_name.is_absolute()
                    or bool(windows_name.drive)
                    or ".." in name.parts
                    or stat.S_ISLNK(member.external_attr >> 16)
                )
                if unsafe:
                    row["status"] = "rejected_unsafe_path"
                    warn("Membro non sicuro ignorato: " + _bounded_text(member.filename, 256))
                    continue
                if member.is_dir():
                    row["status"] = "directory"
                    continue
                if member.flag_bits & 1:
                    protection = _protection_type(member)
                    row["protection_type"] = protection
                    if protection == "zip_unknown":
                        row["status"] = "unsupported_encryption"
                        warn("Metadati di cifratura ZIP incoerenti; nessuna richiesta credenziale: " + _bounded_text(member.filename, 256))
                        continue
                    if len(unlock_requests) < MAX_UNLOCK_REQUESTS:
                        unlock_requests.append(
                            unlock_request(
                                asset.get("id", ""), protection, "archive-extractor", ["zip_adapter"],
                                internal_path=member.filename,
                            )
                        )
                    else:
                        omitted_unlock_requests += 1
                    row["status"] = "encrypted"
                    warn("Membro cifrato; l'estrazione richiede una credenziale: " + _bounded_text(member.filename, 256))
                    continue
                ratio = member.file_size / max(member.compress_size, 1)
                row["compression_ratio"] = round(ratio, 2)
                if member.file_size > remaining or member.file_size > MAX_MEMBER_BYTES:
                    row["status"] = "skipped_budget"
                    warn("Budget estrazione: " + _bounded_text(member.filename, 256))
                    continue
                if ratio > MAX_COMPRESSION_RATIO:
                    row["status"] = "skipped_ratio"
                    warn(
                        f"Rapporto di compressione {ratio:.1f}:1 oltre il limite {MAX_COMPRESSION_RATIO}: "
                        + _bounded_text(member.filename, 256)
                    )
                    continue
                if len(derived) >= 64:
                    row["status"] = "skipped_limit"
                    warn("Limite 64 membri estratti; inventario continuato fino al limite dichiarato.")
                    continue
                leaf = _bounded_text(name.name, 180) or "member"
                member_name = _name_metadata(member.filename)
                target = output / f"{index}-{leaf}"
                member_budget = remaining
                try:
                    written = 0
                    digest = hashlib.sha256()
                    with archive.open(member) as source, target.open("xb") as destination:
                        while block := source.read(min(65536, member_budget - written + 1)):
                            written += len(block)
                            if written > member_budget:
                                raise ValueError("Budget estrazione esaurito")
                            destination.write(block)
                            digest.update(block)
                    remaining -= written
                    derived.append(
                        {
                            "path": str(target),
                            "name": _bounded_text(name.name, 180) or "member",
                            "method": "ZIP extraction with CRC verification",
                            "source_asset_id": asset.get("id"),
                            "source_member": member_name["name"],
                            "source_member_truncated": member_name["name_truncated"],
                            "source_member_sha256": member_name["name_sha256"],
                            "source_offset": member.header_offset,
                            "source_size": member.file_size,
                            "compressed_size": member.compress_size,
                            "sha256": digest.hexdigest(),
                        }
                    )
                    row.update(size=written, status="extracted", sha256=digest.hexdigest())
                    reporter.phase("Estratto " + _bounded_text(member.filename, 256))
                except (ValueError, RuntimeError, OSError, EOFError, NotImplementedError, zlib.error, zipfile.BadZipFile) as exc:
                    target.unlink(missing_ok=True)
                    # Failed/CRC-invalid members are deleted, so their bytes do
                    # not consume the cumulative budget available to later files.
                    remaining = member_budget
                    row.update(status="failed", error=str(exc)[:240])
                    warn(f"Estrazione fallita per {_bounded_text(member.filename, 256)}: {str(exc)[:240]}")
        if omitted_unlock_requests:
            warn(
                f"Richieste di sblocco omesse per limite: {omitted_unlock_requests}"
            )
        if omitted_warnings:
            summary = f"Altri warning omessi dopo {MAX_WARNINGS}: {omitted_warnings}"
            if len(warnings) >= MAX_WARNINGS:
                warnings[-1] = summary
            else:
                warnings.append(summary)
        return {
            "summary": f"{len(derived)} file estratti",
            "confidence": 1,
            "derived_assets": derived,
            "sections": [{"id": "inventory", "data": rows}],
            "warnings": warnings,
            "unlock_requests": unlock_requests,
            "status": "partial" if warnings else "completed",
        }
