import base64
import codecs
import json
from pathlib import Path
from urllib.parse import unquote
import regex


def validate_patterns(prefixes, patterns):
    if any(len(x) > 256 for x in prefixes + patterns):
        raise ValueError("Prefisso o regex troppo lungo")
    return [
        regex.compile(p, regex.I)
        for p in (
            [r"(?:" + "|".join(regex.escape(p) for p in prefixes) + r")\{[^{}\r\n]{1,256}\}"]
            if prefixes
            else []
        )
        + patterns
    ]


def search(asset, context):
    prefixes = context.get("prefixes", ["flag", "CTF", "HTB", "picoCTF"])
    patterns = validate_patterns(prefixes, context.get("patterns", []))
    budget = context.get("byte_budget", 64 * 1024**2)
    if asset.get("path") and Path(asset["path"]).is_dir():
        output = []
        warnings = []
        remaining = budget
        for path in Path(asset["path"]).rglob("*"):
            if path.is_file() and not path.is_symlink():
                result = search({**asset, "path": str(path)}, {**context, "byte_budget": remaining})
                for flag in result["flags"]:
                    flag["source_file"] = str(path.relative_to(asset["path"]))
                output.extend(result["flags"])
                warnings.extend(result["warnings"])
                remaining -= result["metrics"]["bytes_read"]
                if remaining <= 0:
                    break
        unique = {f["value"]: f for f in output}
        return {
            "flags": list(unique.values())[: context.get("max_results", 100)],
            "warnings": warnings,
            "metrics": {"bytes_read": budget - remaining},
            "status": "partial" if remaining <= 0 else "completed",
        }
    if asset.get("path"):
        with Path(asset["path"]).open("rb") as handle:
            data = handle.read(budget)
    else:
        value = asset.get("content", "")
        data = (value if isinstance(value, str) else json.dumps(value)).encode()[:budget]
    found = []
    seen = set()
    warnings = []
    maximum = min(context.get("max_results", 100), 1000)

    def scan(text, method, offset=0):
        for pattern in patterns:
            try:
                for match in pattern.finditer(text, timeout=0.1):
                    value = match.group(0)
                    if value in seen:
                        continue
                    seen.add(value)
                    found.append(
                        {
                            "value": value,
                            "method": method,
                            "source": asset.get("id"),
                            "asset_id": asset.get("id"),
                            "offset": offset + match.start() if method == "raw" else None,
                            "source_block_offset": offset,
                            "confidence": 0.95 if method == "raw" else 0.75,
                        }
                    )
                    if len(found) >= maximum:
                        return
            except TimeoutError:
                warnings.append("Timeout regex: ricerca parziale")

    # Overlap handles flags and encoded tokens spanning scan blocks.
    for start in range(0, max(1, len(data)), 65536):
        block = data[max(0, start - 4096) : start + 65536]
        origin = max(0, start - 4096)
        text = block.decode("utf-8", errors="replace")
        scan(block.decode("latin1"), "raw", origin)
        for method, variant in [
            ("url", unquote(text)),
            ("rot13", codecs.decode(text, "rot_13")),
            ("reverse", text[::-1]),
            ("split", regex.sub(r"[\s\x00]+", "", text)),
            ("utf-16le", block.decode("utf-16le", errors="ignore")),
            ("utf-16be", block.decode("utf-16be", errors="ignore")),
        ]:
            scan(variant, method, origin)
        for encoded in regex.finditer(r"[A-Za-z0-9+/=]{12,2048}|(?:[0-9a-fA-F]{2}){6,1024}", text):
            token = encoded.group()
            for method, decoder in [
                ("base64", lambda x: base64.b64decode(x + "=" * (-len(x) % 4), validate=True)),
                ("hex", bytes.fromhex),
            ]:
                try:
                    scan(decoder(token).decode("utf-8", errors="replace"), method, origin + encoded.start())
                except (ValueError, UnicodeError):
                    pass
        if len(found) >= maximum:
            break
    if context.get("rc4_key"):
        key = context["rc4_key"].encode()
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) % 256
            s[i], s[j] = s[j], s[i]
        i = j = 0
        decoded = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            decoded.append(byte ^ s[(s[i] + s[j]) % 256])
        scan(decoded.decode("utf-8", errors="replace"), "rc4")
    return {
        "flags": found[:maximum],
        "warnings": warnings,
        "metrics": {"bytes_read": len(data)},
        "status": "partial" if warnings or len(found) >= maximum else "completed",
    }
