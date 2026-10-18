"""Capture command output with explicit memory and wall-time bounds."""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time


def run_bounded(argv: list[str], *, timeout: int = 120,
                max_stdout: int = 32 * 1024 * 1024,
                max_stderr: int = 1024 * 1024) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True,
                               env={**os.environ, "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0"})
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": max(0, max_stdout), "stderr": max(0, max_stderr)}
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
                block = os.read(key.fileobj.fileno(), 64 * 1024)
                if not block:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                name = key.data
                available = limits[name] - len(outputs[name])
                if available > 0:
                    outputs[name].extend(block[:available])
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
    result = subprocess.CompletedProcess(
        argv, returncode, outputs["stdout"].decode("utf-8", "replace"),
        outputs["stderr"].decode("utf-8", "replace"),
    )
    result.output_truncated = truncated["stdout"]
    result.stderr_truncated = truncated["stderr"]
    result.timed_out = timed_out
    result.stdout_bytes = len(outputs["stdout"])
    result.stderr_bytes = len(outputs["stderr"])
    return result
