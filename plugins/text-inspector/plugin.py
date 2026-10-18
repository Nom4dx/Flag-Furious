import json
import math
from collections import Counter
from pathlib import Path
from app.core.plugin import BasePlugin


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
        if asset.get("path"):
            with Path(asset["path"]).open("rb") as handle:
                data = handle.read(context["byte_budget"])
        else:
            data = json.dumps(asset.get("content")).encode()
        histogram = Counter(data)
        entropy = -sum((n / len(data)) * math.log2(n / len(data)) for n in histogram.values()) if data else 0
        text = data.decode("utf-8", errors="replace")
        newline_count = data.count(b"\n") + data.count(b"\r") - data.count(b"\r\n")
        line_count = newline_count + int(bool(data) and data[-1:] not in (b"\n", b"\r"))
        partial = bool(asset.get("partial_input"))
        warnings = []
        if partial:
            warnings.append(
                f"Vista parziale: {asset.get('visible_bytes', len(data))} di "
                f"{asset.get('size', len(data))} byte; i conteggi descrivono solo la vista analizzata."
            )
        inventory = [
            {"metric": "Byte", "value": len(data)},
            {"metric": "Righe", "value": line_count},
            {"metric": "Entropia bit/byte", "value": round(entropy, 4)},
        ]
        return {
            "summary": f"{len(data)} byte, {line_count} righe" + (" (vista parziale)" if partial else ""),
            "status": "partial" if partial else "completed",
            "confidence": 1,
            "sections": [
                {"id": "inventory", "data": inventory},
                # The input can be much larger than the worker's authorized view.
                # Return a bounded preview instead of echoing asset.content into IPC.
                {"id": "analysis", "data": text[:16384]},
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
                "input_bytes": asset.get("size", len(data)),
                "partial_input": partial,
            },
            "warnings": warnings,
        }
