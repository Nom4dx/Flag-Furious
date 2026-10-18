import json
import hashlib
import math
import unicodedata
from collections import Counter
from pathlib import Path
from app.core.plugin import BasePlugin

MAX_ANALYSIS_BYTES = 64 * 1024**2
PREVIEW_BYTES = 16 * 1024
MAX_LINE_ROWS = 200
MAX_INVISIBLE_ROWS = 100


def _encoding(data):
    """Choose a deterministic decoder from a BOM, otherwise UTF-8."""
    probe = data[:PREVIEW_BYTES]
    if probe.startswith(b"\x00\x00\xfe\xff"):
        return "UTF-32 BE", "utf-32-be", data[4:], 4
    if probe.startswith(b"\xff\xfe\x00\x00"):
        return "UTF-32 LE", "utf-32-le", data[4:], 4
    if probe.startswith(b"\xfe\xff"):
        return "UTF-16 BE", "utf-16-be", data[2:], 2
    if probe.startswith(b"\xff\xfe"):
        return "UTF-16 LE", "utf-16-le", data[2:], 2
    if probe.startswith(b"\xef\xbb\xbf"):
        return "UTF-8 with BOM", "utf-8", data[3:], 3
    try:
        probe.decode("utf-8")
        return "UTF-8", "utf-8", data, 0
    except UnicodeDecodeError:
        return "UTF-8 with replacement", "utf-8", data, 0


def _newline_counts(data, codec):
    cr, lf = "\r".encode(codec), "\n".encode(codec)
    crlf = cr + lf
    count = data.count(cr) + data.count(lf) - data.count(crlf)
    ends_with_newline = data.endswith(cr) or data.endswith(lf)
    return count, count + int(bool(data) and not ends_with_newline)


def _line_rows(data, codec, base_offset):
    cr, lf = "\r".encode(codec), "\n".encode(codec)
    rows, start, line_number = [], 0, 1
    while start < len(data) and len(rows) < MAX_LINE_ROWS:
        cr_pos = data.find(cr, start)
        lf_pos = data.find(lf, start)
        breaks = [position for position in (cr_pos, lf_pos) if position >= 0]
        if not breaks:
            end, next_start = len(data), len(data)
        else:
            end = min(breaks)
            token = cr if end == cr_pos else lf
            next_start = end + len(token)
            if token == cr and data.startswith(lf, next_start):
                next_start += len(lf)
        value = data[start:end]
        decoded = value.decode(codec, errors="replace")
        truncated = len(decoded) > 1024
        text = decoded[:1024]
        rows.append({"line": line_number, "byte_offset": base_offset + start, "text": text,
                     "line_bytes": len(value), "truncated": truncated})
        line_number += 1
        if next_start <= start:
            break
        start = next_start
    return rows


def _invisible_characters(text, data, codec, base_offset, exact_offsets):
    rows, byte_offset = [], base_offset
    for char_index, char in enumerate(text):
        category = unicodedata.category(char)
        invisible = category == "Cf" or (category == "Cc" and char not in "\t\r\n")
        if invisible and len(rows) < MAX_INVISIBLE_ROWS:
            try:
                name = unicodedata.name(char, "UNNAMED")
            except ValueError:
                name = "UNNAMED"
            rows.append({"codepoint": f"U+{ord(char):04X}", "name": name,
                         "category": category, "character_index": char_index,
                         "byte_offset": byte_offset if exact_offsets else None})
        if byte_offset is not None:
            try:
                byte_offset += len(char.encode(codec))
            except UnicodeEncodeError:
                exact_offsets = False
                byte_offset = None
        if byte_offset is None:
            # Remaining byte offsets cannot be reconstructed after replacement text.
            continue
    return rows, sum(1 for char in text if unicodedata.category(char) == "Cf" or
                     (unicodedata.category(char) == "Cc" and char not in "\t\r\n"))


def _json_string_chunks(value):
    yield '"'
    for offset in range(0, len(value), 2048):
        escaped = json.encoder.encode_basestring(value[offset:offset + 2048])
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
        yield json.dumps(value, ensure_ascii=False)


def _inline_chunks(content):
    """Preserve raw inline text; encode structured values as compact UTF-8 JSON."""
    if isinstance(content, str):
        for offset in range(0, len(content), 4096):
            yield content[offset:offset + 4096].encode("utf-8")
        return
    for chunk in _json_chunks(content):
        yield chunk.encode("utf-8")


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
            for encoded in _inline_chunks(asset.get("content")):
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
        encoding, codec, body, bom_bytes = _encoding(data)
        preview_body = body[:max(0, PREVIEW_BYTES - bom_bytes)]
        try:
            text = preview_body.decode(codec)
            decode_errors = False
        except UnicodeDecodeError:
            text = preview_body.decode(codec, errors="replace")
            decode_errors = True
        newline_count, line_count = _newline_counts(body, codec)
        lines = _line_rows(preview_body, codec, bom_bytes)
        invisible, invisible_count = _invisible_characters(
            text, preview_body, codec, bom_bytes, not decode_errors
        )
        partial = bool(asset.get("partial_input")) or truncated or input_bytes > len(data)
        warnings = []
        if partial:
            if input_bytes > len(data):
                warnings.append(f"Vista parziale: analizzati {len(data)} di almeno {input_bytes} byte; i conteggi descrivono solo la vista.")
            elif inline_input:
                warnings.append(f"Vista parziale: analizzati {len(data)} byte; dimensione totale non derivabile dalla vista inline.")
            else:
                warnings.append(f"Vista parziale: analizzati {len(data)} byte della vista sorgente disponibile.")
        if decode_errors:
            warnings.append(f"Sequenze {encoding} non valide nei primi {len(preview)} byte; offset Unicode non disponibili")
        inventory = [
            {"metric": "Byte analizzati", "value": len(data)},
            {"metric": "Righe", "value": line_count},
            {"metric": "Entropia bit/byte", "value": round(entropy, 4)},
            {"metric": "SHA-256 vista analizzata", "value": hashlib.sha256(data).hexdigest()},
            {"metric": "Decodifica", "value": encoding},
            {"metric": "Caratteri invisibili/control", "value": invisible_count},
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
                {"id": "lines", "data": lines, "status": "partial" if len(data) > len(preview) or len(lines) >= MAX_LINE_ROWS else "completed"},
                {"id": "invisible-characters", "data": invisible, "status": "partial" if len(data) > len(preview) or invisible_count > len(invisible) or decode_errors else "completed"},
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
                "encoding": encoding,
                "encoding_scope_bytes": len(preview_body),
                "line_count": line_count,
                "newline_count": newline_count,
                "line_preview_bytes": len(preview_body),
                "line_preview_rows": len(lines),
                "invisible_character_count": invisible_count,
                "invisible_character_preview_rows": len(invisible),
                "invisible_scan_bytes": len(preview_body),
            },
            "warnings": warnings,
        }
