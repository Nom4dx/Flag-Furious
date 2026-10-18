"""Static PDF object, stream, attachment and action inventory."""

from __future__ import annotations

import re
import zlib

from .reporting import ModuleResult


def analyze_objects(data: bytes, source: str) -> ModuleResult:
    """Inventory PDF objects and decode bounded Flate streams.

    Input: PDF bytes/source. Output: objects, decoded artifacts, dangerous-action
    findings. Malformed streams become warnings. Limits: 2,000 objects, 64 streams,
    8 MiB decompressed each. Security: JavaScript, Launch and embedded files are
    reported as passive data and never invoked. Example: ``analyze_objects(pdf, "a.pdf")``.
    """
    result = ModuleResult("pdf_objects")
    objects = list(re.finditer(rb"(?m)(\d+)\s+(\d+)\s+obj\b", data))[:2000]
    for match in objects:
        end = data.find(b"endobj", match.end())
        body = data[match.end() : end if end >= 0 else min(len(data), match.end() + 65536)]
        types = [x.decode("ascii", "replace") for x in re.findall(rb"/Type\s*/([A-Za-z0-9]+)", body[:8192])]
        result.items.append({"object": int(match.group(1)), "generation": int(match.group(2)), "offset": match.start(), "types": types, "size": len(body), "source": source})
    for token, severity in ((b"/JavaScript", "high"), (b"/JS", "high"), (b"/Launch", "critical"), (b"/EmbeddedFile", "medium"), (b"/OpenAction", "high"), (b"/AA", "high")):
        for match in list(re.finditer(re.escape(token), data))[:100]:
            result.findings.append({"type": "active_or_embedded_content", "severity": severity, "title": token.decode()[1:] + " presente", "description": "Elemento staticamente rilevato; non eseguito", "source": source, "offset": match.start(), "confidence": 0.9})
    # ``stream`` also occurs at the end of ``endstream``. The negative
    # look-behind prevents treating terminators as new compressed payloads.
    for index, match in enumerate(re.finditer(rb"(?<!end)stream\r?\n", data)):
        if index >= 64:
            result.warnings.append("Limite di 64 stream PDF raggiunto")
            break
        end = data.find(b"endstream", match.end())
        if end < 0:
            continue
        stream = data[match.end() : end].rstrip(b"\r\n")
        dictionary = data[max(0, match.start() - 2048) : match.start()]
        if b"/FlateDecode" in dictionary:
            try:
                inflater = zlib.decompressobj()
                decoded = inflater.decompress(stream, 8 * 1024**2 + 1)
                if len(decoded) > 8 * 1024**2 or inflater.unconsumed_tail:
                    raise zlib.error("stream exceeds the 8 MiB decoded limit")
                result.artifacts.append({"name": f"pdf-stream-{index:03d}.bin", "content": decoded, "category": "pdf", "source": f"{source}:stream:{index}", "offset": match.end(), "method": "FlateDecode"})
            except zlib.error as exc:
                result.warnings.append(f"Stream {index} non decodificabile: {exc}")
    result.metrics = {"objects": len(objects), "streams_decoded": len(result.artifacts)}
    return result
