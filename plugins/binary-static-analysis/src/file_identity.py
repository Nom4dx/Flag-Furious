"""Streaming identity, hashes and passive libmagic adapter.

Hashes cover the entire immutable input independently of the analysis byte
budget. Optional python-magic and ``file`` improve labels but never determine the
format alone. No data is sent over the network.
"""

from pathlib import Path
import hashlib
import mimetypes


def identify(path: Path, asset: dict, tool_runner=None) -> dict:
    """Return hashes, MIME hints, extension and initial/final magic bytes.

    Input is a regular file already controlled by the Hub. ``OSError`` propagates;
    missing optional tools produce a fallback label. Example: ``identify(path,{})``.
    """
    digests = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256", "sha512")}
    size = 0
    tail = b""
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            size += len(block)
            tail = (tail + block)[-32:]
            for digest in digests.values():
                digest.update(block)
    with path.open("rb") as source:
        head = source.read(32)
    mime = asset.get("mime") or mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    magic_label = ""
    try:
        import magic

        magic_label = magic.from_file(str(path))
        mime = magic.from_file(str(path), mime=True) or mime
    except (ImportError, OSError):
        if tool_runner:
            result = tool_runner.run(["file", "-b", str(path)], timeout=5)
            magic_label = result.get("stdout", "").strip()
    return {
        "name": asset.get("name", path.name),
        "physical_size": size,
        "extension": path.suffix.casefold(),
        "mime": mime,
        "libmagic": magic_label or "non disponibile",
        "header_hex": head.hex(" "),
        "tail_hex": tail.hex(" "),
        "hashes": {name: digest.hexdigest() for name, digest in digests.items()},
        "original_modified": False,
    }
