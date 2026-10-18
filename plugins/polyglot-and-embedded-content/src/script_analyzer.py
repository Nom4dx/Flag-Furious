"""Static-only inspection of scripts, heredocs and encoded payload indicators."""

import re
from pathlib import Path


def analyze_script(path: Path, boundary: dict, max_bytes: int = 2 * 1024 * 1024) -> dict:
    """Classify script language and suspicious static constructs without execution.

    Input is a validated script range. Output contains line counts, comments and
    passive indicators. The function never invokes an interpreter or shell.
    """
    with path.open("rb") as stream:
        stream.seek(boundary["start_offset"]); raw = stream.read(min(boundary["length"], max_bytes))
    text = raw.decode("utf-8", "replace")
    first = text.splitlines()[0] if text.splitlines() else ""
    declared = boundary["format"]
    language = "powershell" if "powershell" in first.lower() or declared == "powershell" else "python" if "python" in first.lower() or declared == "python_script" else "javascript" if declared == "javascript" else "batch" if declared == "batch" else "shell" if first.startswith("#!") else "script"
    indicators = [name for name, pattern in {
        "base64": r"(?i)(?:frombase64string|base64\s+-d|b64decode)", "download": r"(?i)(?:curl|wget|invoke-webrequest)",
        "execution": r"(?i)(?:eval\s*\(|exec\s*\(|start-process|powershell\s+-e)",
        "archive_reference": r"(?i)(?:unzip|expand-archive|zipfile|tar\s+-)",
    }.items() if re.search(pattern, text)]
    return {"format_id": boundary["id"], "language": language, "lines": text.count("\n") + 1, "shebang": first if first.startswith("#!") else None, "indicators": indicators, "heredoc_markers": len(re.findall(r"<<[-~]?\s*['\"]?\w+", text)), "executed": False, "truncated": len(raw) < boundary["length"]}
