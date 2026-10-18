"""Describe markers and application segments of validated JPEG images."""

from pathlib import Path


def analyze_jpeg(path: Path, boundary: dict, max_preview: int = 4096) -> dict:
    """Return marker inventory and passive APP/COM previews.

    Input must be a validated JPEG. Output bytes are escaped as hex/text and no
    metadata code is executed. Segment lengths came from the structural parser.
    """
    application = []
    with path.open("rb") as stream:
        for segment in boundary.get("details", {}).get("segments", []):
            marker = segment["marker"]
            if marker.startswith("FFE") or marker == "FFFE":
                stream.seek(segment["offset"] + 4)
                raw = stream.read(min(max_preview, max(0, segment["length"] - 2)))
                application.append({**segment, "text_preview": raw.decode("utf-8", "replace"), "hex_preview": raw[:64].hex()})
    return {"format_id": boundary["id"], "segments": boundary.get("details", {}).get("segments", []), "application_segments": application}

