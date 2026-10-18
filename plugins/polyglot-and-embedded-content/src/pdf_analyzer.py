"""Static inventory of validated PDF objects, revisions and embedded markers."""

import re
from pathlib import Path


def analyze_pdf(path: Path, boundary: dict, max_bytes: int) -> dict:
    """Inventory indirect objects, streams, attachments and active-action tokens.

    The analyzer never evaluates JavaScript, Launch actions or streams. It reads
    at most ``max_bytes`` inside the validated interval and reports truncation.
    """
    length = min(boundary["length"], max_bytes)
    with path.open("rb") as stream:
        stream.seek(boundary["start_offset"]); data = stream.read(length)
    objects = [{"number": int(m.group(1)), "generation": int(m.group(2)), "offset": boundary["start_offset"] + m.start()} for m in re.finditer(rb"(?m)(\d+)\s+(\d+)\s+obj\b", data)]
    streams = [{"offset": boundary["start_offset"] + m.start(), "length_declared": int(m.group(1)) if m.group(1) else None} for m in re.finditer(rb"(?:/Length\s+(\d+)\s*)?>>\s*stream\r?\n", data)]
    actions = [token.decode() for token in (b"/JavaScript", b"/JS", b"/Launch", b"/OpenAction") if token in data]
    return {
        "format_id": boundary["id"], "objects": objects[:2048], "streams": streams[:1024],
        "eof_count": boundary.get("details", {}).get("eof_count", 0),
        "embedded_file_markers": data.count(b"/EmbeddedFile"), "file_spec_markers": data.count(b"/Filespec"),
        "active_actions_detected_static_only": actions, "analysis_truncated": length < boundary["length"],
    }

