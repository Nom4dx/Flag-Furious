"""Subprocess helpers that drain pipes without retaining unlimited output."""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from pathlib import Path
from typing import Any


def run_bounded(argv: list[str], *, timeout: int, max_stdout: int = 8 * 1024 * 1024,
                max_stderr: int = 1024 * 1024, output_path: Path | None = None) -> dict[str, Any]:
    out = output_path.open("xb") if output_path is not None else None
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True,
                                   env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                                        "LANG": "C.UTF-8", "LC_ALL": "C"})
    except OSError as exc:
        if out is not None:
            out.close()
            out.unlink(missing_ok=True)
        return {"returncode": 127, "stdout": b"", "stderr": str(exc).encode(),
                "timed_out": False, "truncated": False, "stderr_truncated": False,
                "output_path": output_path}
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    caps = {"stdout": max(0, max_stdout), "stderr": max(0, max_stderr)}
    stdout_truncated = False
    stderr_truncated = False
    deadline = time.monotonic() + max(1, timeout)
    timed_out = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(remaining, 0.25)):
                block = os.read(key.fileobj.fileno(), 64 * 1024)
                if not block:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                name = key.data
                if name == "stdout" and out is not None:
                    available = caps[name] - out.tell()
                    if available > 0:
                        out.write(block[:available])
                    if len(block) > max(0, available):
                        stdout_truncated = True
                        os.killpg(process.pid, signal.SIGKILL)
                        break
                else:
                    available = caps[name] - len(buffers[name])
                    if available > 0:
                        buffers[name].extend(block[:available])
                    if len(block) > max(0, available):
                        if name == "stdout":
                            stdout_truncated = True
                        else:
                            stderr_truncated = True
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
        if out is not None:
            out.close()
    return {"returncode": returncode, "stdout": bytes(buffers["stdout"]),
            "stderr": bytes(buffers["stderr"]), "timed_out": timed_out,
            "truncated": stdout_truncated, "stderr_truncated": stderr_truncated,
            "output_path": output_path}
