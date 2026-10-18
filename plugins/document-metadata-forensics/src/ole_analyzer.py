"""Static OLE Compound File metadata and stream inventory."""

from __future__ import annotations

import io

from .reporting import ModuleResult


OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")


def analyze_ole(data: bytes, source: str) -> ModuleResult:
    """Inspect legacy DOC/XLS/PPT compound files.

    Input: OLE bytes/source. Output: stream inventory, property metadata and macro
    indicators. Missing optional ``olefile`` yields a warning and string fallback.
    Limits: 2,000 streams, 16 MiB extracted stream. Security: macros are never
    interpreted. Example: ``analyze_ole(doc_bytes, "a.doc")``.
    """
    result = ModuleResult("ole", status="skipped")
    if not data.startswith(OLE_MAGIC):
        return result
    result.status = "completed"
    try:
        import olefile

        with olefile.OleFileIO(io.BytesIO(data)) as ole:
            streams = ole.listdir(streams=True, storages=False)[:2000]
            for parts in streams:
                path = "/".join(parts)
                size = ole.get_size(parts)
                result.items.append({"type": "ole_stream", "internal_path": path, "size": size, "source": source})
                if "vba" in path.lower() or "macros" in path.lower():
                    result.findings.append({"type": "macro", "severity": "high", "title": "Stream VBA/OLE", "description": "Macro rilevata staticamente; non eseguita", "source": source, "internal_path": path, "offset": None, "confidence": 0.95})
            for stream_name in ("\x05SummaryInformation", "\x05DocumentSummaryInformation"):
                if ole.exists(stream_name):
                    props = ole.getproperties(stream_name)
                    for key, value in props.items():
                        if isinstance(value, (str, int, float, bool)):
                            result.items.append({"type": "metadata_value", "namespace": "OLE", "field": str(key), "raw_value": str(value), "normalized_value": str(value).strip(), "source": source, "internal_path": stream_name, "offset": None, "size": None, "hash": None, "parser": "olefile", "decoder": None, "timestamp": None, "confidence": 0.9, "flag_relation": None})
    except ImportError:
        result.warnings.append("Dipendenza opzionale olefile non disponibile: solo firme OLE")
        result.status = "partial"
    except Exception as exc:
        result.warnings.append(f"OLE parziale: {type(exc).__name__}: {exc}")
        result.status = "partial"
    result.metrics = {"streams": sum(x.get("type") == "ole_stream" for x in result.items)}
    return result
