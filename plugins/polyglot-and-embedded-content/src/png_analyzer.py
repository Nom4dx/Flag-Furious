"""Interpret validated PNG chunks and expose passive embedded regions."""

from pathlib import Path


def analyze_png(path: Path, boundary: dict, max_preview: int = 65536) -> dict:
    """Return chunk inventory, textual fields and suspicious custom chunks.

    Requires a previously validated PNG boundary. Reads only declared chunks;
    decompression is left to the payload module and no image decoder is invoked.
    """
    chunks = boundary.get("details", {}).get("chunks", [])
    texts, custom = [], []
    known = {"IHDR", "PLTE", "IDAT", "IEND", "tEXt", "zTXt", "iTXt", "eXIf", "iCCP", "tIME", "cHRM", "pHYs", "sRGB", "gAMA", "bKGD", "tRNS"}
    with path.open("rb") as stream:
        for chunk in chunks:
            kind, offset, length = chunk["type"], chunk["offset"], chunk["length"]
            if kind in {"tEXt", "zTXt", "iTXt"}:
                stream.seek(offset + 8); raw = stream.read(min(length, max_preview))
                texts.append({"chunk": kind, "offset": offset + 8, "raw_preview": raw.decode("utf-8", "replace")})
            if kind not in known:
                custom.append({"chunk": kind, "offset": offset + 8, "length": length, "suspicious": True})
    return {"format_id": boundary["id"], "chunks": chunks, "text_chunks": texts, "custom_chunks": custom}

