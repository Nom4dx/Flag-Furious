import json
import mimetypes
from pathlib import Path


def detect(name, kind, data):
    extension = Path(name).suffix.lower()
    mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
    text = data.decode("utf-8", errors="replace")
    types = [kind]
    signatures = []
    if kind == "file":
        if data[:4] in (
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x0a\x0d\x0d\x0a",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
        ):
            types.append("pcap")
            mime = "application/vnd.tcpdump.pcap"
        if (
            data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"7z\xbc\xaf", b"\x1f\x8b"))
            or data[257:262] == b"ustar"
        ):
            types.append("archive")
        if data.startswith(b"QFI\xfb") or data[1080:1082] == b"\x53\xef" or data[510:512] == b"\x55\xaa":
            types.append("disk_image")
            signatures.append("filesystem_image")
        if data.startswith(b"QFI\xfb"):
            signatures.append("qcow")
        if "\ufffd" not in text and b"\x00" not in data:
            types.append("text")
            mime = "text/plain"
            try:
                json.loads(text)
                types.append("json")
                mime = "application/json"
            except ValueError:
                pass
    return {
        "extension": extension,
        "mime": mime,
        "mime_source": "header/content or extension hint",
        "detected_types": types,
        "content_signatures": signatures,
        "header_hex": data[:4096].hex(),
        "sample": text[:65536],
        "metadata": {"encoding": "utf-8" if "\ufffd" not in text else "binary"},
    }
