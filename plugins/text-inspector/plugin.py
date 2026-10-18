import json
import hashlib
import math
from collections import Counter
from pathlib import Path
from app.core.plugin import BasePlugin

MAX_ANALYSIS_BYTES = 64 * 1024**2
PREVIEW_BYTES = 16 * 1024


def _json_string_chunks(value):
    yield '"'
    for offset in range(0, len(value), 2048):
        escaped = json.encoder.encode_basestring_ascii(value[offset:offset + 2048])
        yield escaped[1:-1]
    yield '"'


def _json_chunks(value):
    if isinstance(value, str):
        yield from _json_string_chunks(value)
    elif isinstance(value, dict):
        yield "{"
        for index, (key, item) in enumerate(value.items()):
            if index:
                yield ","
            yield from _json_string_chunks(str(key))
            yield ":"
            yield from _json_chunks(item)
        yield "}"
    elif isinstance(value, (list, tuple)):
        yield "["
        for index, item in enumerate(value):
            if index:
                yield ","
            yield from _json_chunks(item)
        yield "]"
    else:
        yield json.dumps(value, ensure_ascii=True)


class Plugin(BasePlugin):
    def can_handle(self, asset, context):
        """Prefer actual text and structured data during recursive dispatch."""
        if asset.get("type") in {"text", "json", "hex", "url", "structured"}:
            return {"compatible": True, "score": 0.98, "reasons": ["Asset testuale o strutturato"]}
        extension = str(asset.get("extension", "")).lower()
        mime = str(asset.get("mime", "")).lower()
        if mime.startswith("text/") or extension in {
            ".txt", ".log", ".csv", ".xml", ".json", ".yaml", ".yml", ".md", ".ini", ".conf",
        }:
            return {"compatible": True, "score": 0.9, "reasons": ["Contenuto testuale riconosciuto"]}
        return {"compatible": False, "score": 0.0, "reasons": ["Contenuto non testuale"]}

    def about(self, request, context):
        return {"name": "Text Inspector", "contract": "1.0", "network": False}

    def analyze(self, asset, context, reporter):
        reporter.phase("Distribuzione e struttura")
        cap = min(max(0, int(context.get("byte_budget", MAX_ANALYSIS_BYTES))), MAX_ANALYSIS_BYTES)
        inline_input = not asset.get("path")
        if asset.get("path"):
            source = Path(asset["path"])
            visible_input_bytes = source.stat().st_size
            input_bytes = int(asset.get("size", visible_input_bytes))
            with source.open("rb") as handle:
                data = handle.read(cap)
            truncated = visible_input_bytes > len(data)
        else:
            parts = []
            collected = 0
            truncated = False
            for chunk in _json_chunks(asset.get("content")):
                encoded = chunk.encode("ascii")
                if collected + len(encoded) > cap:
                    parts.append(encoded[: cap - collected])
                    truncated = True
                    break
                parts.append(encoded)
                collected += len(encoded)
            data = b"".join(parts)
            input_bytes = int(asset.get("size", len(data)))
            truncated = truncated or input_bytes > len(data)
        histogram = Counter(data)
        entropy = -sum((n / len(data)) * math.log2(n / len(data)) for n in histogram.values()) if data else 0
        preview = data[:PREVIEW_BYTES]
        text = preview.decode("utf-8", errors="replace")
        invalid_utf8 = text.count("\ufffd")
        newline_count = data.count(b"\n") + data.count(b"\r") - data.count(b"\r\n")
        line_count = newline_count + int(bool(data) and data[-1:] not in (b"\n", b"\r"))
        partial = bool(asset.get("partial_input")) or truncated or input_bytes > len(data)
        warnings = []
        if partial:
            if input_bytes > len(data):
                warnings.append(f"Vista parziale: analizzati {len(data)} di almeno {input_bytes} byte; i conteggi descrivono solo la vista.")
            elif inline_input:
                warnings.append(f"Vista parziale: analizzati {len(data)} byte; dimensione totale non derivabile dalla vista inline.")
            else:
                warnings.append(f"Vista parziale: analizzati {len(data)} byte della vista sorgente disponibile.")
        if invalid_utf8:
            warnings.append(f"Anteprima UTF-8 con {invalid_utf8} occorrenze U+FFFD nei primi {len(preview)} byte")
        inventory = [
            {"metric": "Byte analizzati", "value": len(data)},
            {"metric": "Righe", "value": line_count},
            {"metric": "Entropia bit/byte", "value": round(entropy, 4)},
            {"metric": "SHA-256 vista analizzata", "value": hashlib.sha256(data).hexdigest()},
        ]
        return {
            "summary": f"{len(data)} byte, {line_count} righe" + (" (vista parziale)" if partial else ""),
            "status": "partial" if partial else "completed",
            "confidence": 1,
            "sections": [
                {"id": "inventory", "data": inventory},
                # The input can be much larger than the worker's authorized view.
                # Return a bounded preview instead of echoing asset.content into IPC.
                {"id": "analysis", "data": text, "preview_bytes": len(preview), "preview_truncated": len(data) > len(preview)},
            ],
            "visualizations": [
                {
                    "type": "bar",
                    "title": "Frequenza dei byte",
                    "data": [{"x": i, "y": histogram[i]} for i in range(256)],
                    "encoding": {"x": {"field": "x"}, "y": {"field": "y"}},
                    "options": {"interactive": True},
                }
            ],
            "metrics": {
                "bytes_read": len(data),
                "input_bytes": input_bytes,
                "partial_input": partial,
                "analysis_cap_bytes": cap,
            },
            "warnings": warnings,
        }
