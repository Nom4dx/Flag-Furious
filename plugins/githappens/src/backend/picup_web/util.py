from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import shutil
import selectors
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable

MAX_COMMAND_OUTPUT = 8 * 1024 * 1024


def _capture(argv: list[str], *, cwd: Path | None, timeout: int, input_data: bytes | None,
             stdout_limit: int, stderr_limit: int) -> tuple[bytes, bytes, int, bool, bool]:
    """Drain child pipes while retaining only bounded output in memory."""
    process = subprocess.Popen(
        argv, cwd=cwd, stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        env={**os.environ, "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0"},
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    input_offset = 0
    if input_data is not None:
        assert process.stdin is not None
        if input_data:
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()
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
            for key, _ in selector.select(min(remaining, 0.25)):
                if key.data == "stdin":
                    try:
                        input_offset += os.write(key.fileobj.fileno(), input_data[input_offset:input_offset + 64 * 1024])
                    except BrokenPipeError:
                        input_offset = len(input_data)
                    if input_offset >= len(input_data):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
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
        for stream in (process.stdout, process.stderr, process.stdin):
            if stream is not None and not stream.closed:
                stream.close()
    return bytes(buffers["stdout"]), bytes(buffers["stderr"]), returncode, timed_out, any(truncated.values())


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(chunk):
            digest.update(block)
    return digest.hexdigest()


def hashes(path: Path) -> dict[str, str | int]:
    sums = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    size = 0
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            size += len(block)
            for digest in sums.values():
                digest.update(block)
    return {**{name: digest.hexdigest() for name, digest in sums.items()}, "size": size}


def safe_name(value: str, fallback: str = "artifact") -> str:
    value = Path(value.replace("\\", "/")).name
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return value[:180] or fallback


def inside(root: Path, candidate: Path) -> Path:
    root = root.resolve()
    candidate = candidate.resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError("path traversal rejected")
    return candidate


def mime_for(path: Path) -> str:
    guessed = mimetypes.guess_type(path.name)[0]
    if shutil.which("file"):
        result = run(["file", "--brief", "--mime-type", str(path)], timeout=10)
        if result["ok"] and result["stdout"].strip():
            return result["stdout"].strip().splitlines()[0]
    return guessed or "application/octet-stream"


def run(argv: list[str], *, cwd: Path | None = None, timeout: int = 120, input_data: bytes | None = None) -> dict[str, Any]:
    """Execute an argv-only command, capture bounded output, never invoke a shell."""
    try:
        stdout, stderr, returncode, timed_out, truncated = _capture(
            argv, cwd=cwd, timeout=timeout, input_data=input_data,
            stdout_limit=MAX_COMMAND_OUTPUT, stderr_limit=MAX_COMMAND_OUTPUT,
        )
        return {
            "command": argv, "returncode": returncode,
            "stdout": stdout.decode("utf-8", "replace"),
            "stderr": stderr.decode("utf-8", "replace"),
            "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
            "ok": returncode == 0 and not timed_out, "timed_out": timed_out, "output_truncated": truncated,
        }
    except OSError as exc:
        return {"command": argv, "returncode": -1, "stdout": "", "stderr": str(exc), "stdout_bytes": 0,
                "stderr_bytes": len(str(exc).encode("utf-8", "replace")), "ok": False}


def run_binary(argv: list[str], *, cwd: Path | None = None, timeout: int = 120, max_bytes: int = 256 * 1024 * 1024) -> tuple[bytes, dict[str, Any]]:
    try:
        data, stderr, returncode, timed_out, truncated = _capture(
            argv, cwd=cwd, timeout=timeout, input_data=None,
            stdout_limit=max_bytes, stderr_limit=MAX_COMMAND_OUTPUT,
        )
        return data, {"command": argv, "returncode": returncode, "stdout": f"<{len(data)} binary bytes>",
                      "stdout_bytes": len(data), "stderr_bytes": len(stderr),
                      "stderr": stderr.decode("utf-8", "replace"), "ok": returncode == 0 and not timed_out and not truncated,
                      "timed_out": timed_out, "output_truncated": truncated}
    except OSError as exc:
        return b"", {"command": argv, "returncode": -1, "stdout": "", "stderr": str(exc), "stdout_bytes": 0,
                      "stderr_bytes": len(str(exc).encode("utf-8", "replace")), "ok": False}


def json_dump(path: Path, value: Any) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    temp.replace(path)


def iter_files(root: Path, *, limit: int = 100_000, max_dirs: int = 10_000,
               diagnostics: list[str] | None = None) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    count = walked = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        walked += 1
        if walked > max_dirs:
            if diagnostics is not None:
                message=f"{root}: directory scan limit {max_dirs} reached"
                if message not in diagnostics:diagnostics.append(message)
            return
        dirs[:] = sorted(name for name in dirs if not (Path(base) / name).is_symlink())
        for name in sorted(files):
            path = Path(base) / name
            if path.is_symlink() or not path.is_file():continue
            if count >= limit:
                if diagnostics is not None:
                    message=f"{root}: file scan limit {limit} reached"
                    if message not in diagnostics:diagnostics.append(message)
                return
            yield path
            count += 1
