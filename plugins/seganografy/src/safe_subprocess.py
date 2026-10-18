"""Allow-listed subprocess execution for passive forensic tools.

Commands are argument arrays, never shell strings. The worker already has no
network namespace; this layer also applies time/output limits and a minimal
environment. Extracted programs are never accepted as command names.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path


ALLOWLIST = {
    "binwalk", "steghide", "stegseek", "zsteg", "stegcloak", "stegsnow",
    "openstego", "exiftool", "ffprobe", "ffmpeg", "sox", "identify", "convert",
    "pngcheck", "jpeginfo", "strings", "file", "xxd", "foremost", "tesseract", "zbarimg",
}
_VERSION_CACHE: dict[str, str | None] = {}


def _version(tool: str, binary: str) -> str | None:
    """Return a bounded, cached tool version without going through a shell."""
    if tool in _VERSION_CACHE:
        return _VERSION_CACHE[tool]
    args = ["-ver"] if tool == "exiftool" else ["-version"] if tool in {"ffmpeg", "ffprobe"} else ["--version"]
    try:
        result = subprocess.run([binary, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=3, shell=False, check=False)
        value = result.stdout[:4096].decode("utf-8", "replace").splitlines()[0] if result.stdout else None
    except (OSError, subprocess.TimeoutExpired):
        value = None
    _VERSION_CACHE[tool] = value
    return value


def locate(tool: str) -> str | None:
    """Resolve an allow-listed system binary or return ``None``.

    The commonly misspelled ``steghseek`` is deliberately absent: the correct
    project/binary name is ``stegseek``. Paths supplied by plugins are refused.
    """
    if tool not in ALLOWLIST:
        return None
    return shutil.which(tool)


def run(tool: str, arguments: list[str], timeout: int, output_limit: int, cwd: Path | None = None) -> dict:
    """Run one allow-listed passive command with audit metadata.

    Input arguments are passed without ``shell=True``. Output records command,
    version-independent exit status, bounded stdout/stderr and duration. Timeout
    is recoverable. The caller must use read-only evidence paths and an isolated
    output directory. Example: ``run('file',['-b', path], 5, 65536)``.
    """
    binary = locate(tool)
    if not binary:
        return {"tool": tool, "available": False, "version": None, "status": "not_applicable", "command": [tool, *arguments], "exit_code": None, "stdout": "", "stderr": "binario non disponibile", "duration": 0.0}
    command = [binary, *map(str, arguments)]
    started = time.monotonic()
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/nonexistent"}
    try:
        result = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, shell=False, check=False)
        stdout, stderr = result.stdout[:output_limit], result.stderr[:output_limit]
        return {"tool": tool, "available": True, "version": _version(tool, binary), "status": "completed" if result.returncode == 0 else "decode_failed", "command": command, "exit_code": result.returncode, "stdout": stdout.decode("utf-8", "replace"), "stderr": stderr.decode("utf-8", "replace"), "stdout_truncated": len(result.stdout) > output_limit, "stderr_truncated": len(result.stderr) > output_limit, "duration": round(time.monotonic() - started, 4)}
    except subprocess.TimeoutExpired as exc:
        return {"tool": tool, "available": True, "version": _version(tool, binary), "status": "decode_failed", "command": command, "exit_code": None, "stdout": (exc.stdout or b"")[:output_limit].decode("utf-8", "replace"), "stderr": "timeout", "duration": round(time.monotonic() - started, 4)}
