"""Allow-listed subprocess execution for passive forensic tools.

Commands are argument arrays, never shell strings. The worker already has no
network namespace; this layer also applies time/output limits and a minimal
environment. Extracted programs are never accepted as command names.
"""

from __future__ import annotations

import os
import selectors
import signal
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


def _capture(command: list[str], timeout: int, stdout_limit: int, stderr_limit: int,
             cwd: Path | None = None) -> dict:
    process = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=False, start_new_session=True,
                               env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                    "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/nonexistent"})
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": max(0, stdout_limit), "stderr": max(0, stderr_limit)}
    truncated = {"stdout": False, "stderr": False}
    deadline = time.monotonic() + max(1, timeout)
    timed_out = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(remaining, .25)):
                block = os.read(key.fileobj.fileno(), 64 * 1024)
                if not block:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                name = key.data
                available = limits[name] - len(buffers[name])
                if available > 0:
                    buffers[name].extend(block[:available])
                if len(block) > max(0, available):
                    truncated[name] = True
                    if name == "stdout":
                        os.killpg(process.pid, signal.SIGKILL)
                        break
        if timed_out:
            os.killpg(process.pid, signal.SIGKILL)
        returncode = process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        returncode = process.wait()
        timed_out = True
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
    return {"returncode": returncode, "stdout": bytes(buffers["stdout"]),
            "stderr": bytes(buffers["stderr"]), "timed_out": timed_out,
            "stdout_truncated": truncated["stdout"], "stderr_truncated": truncated["stderr"]}


def _version(tool: str, binary: str) -> str | None:
    """Return a bounded, cached tool version without going through a shell."""
    if tool in _VERSION_CACHE:
        return _VERSION_CACHE[tool]
    args = ["-ver"] if tool == "exiftool" else ["-version"] if tool in {"ffmpeg", "ffprobe"} else ["--version"]
    try:
        result = _capture([binary, *args], 3, 4096, 4096)
        output = result["stdout"] or result["stderr"]
        value = output.decode("utf-8", "replace").splitlines()[0] if output else None
    except OSError:
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
    try:
        result = _capture(command, timeout, output_limit, output_limit, cwd=cwd)
    except OSError as exc:
        return {"tool": tool, "available": True, "version": _version(tool, binary), "status": "decode_failed", "command": command, "exit_code": None, "stdout": "", "stderr": str(exc)[:output_limit], "stdout_truncated": False, "stderr_truncated": False, "duration": round(time.monotonic() - started, 4)}
    incomplete = result["timed_out"] or result["stdout_truncated"] or result["stderr_truncated"]
    return {"tool": tool, "available": True, "version": _version(tool, binary),
            "status": "partial" if incomplete else "completed" if result["returncode"] == 0 else "decode_failed",
            "command": command, "exit_code": None if result["timed_out"] else result["returncode"],
            "stdout": result["stdout"].decode("utf-8", "replace"),
            "stderr": "timeout" if result["timed_out"] else result["stderr"].decode("utf-8", "replace"),
            "stdout_truncated": result["stdout_truncated"], "stderr_truncated": result["stderr_truncated"],
            "timed_out": result["timed_out"], "duration": round(time.monotonic() - started, 4)}
