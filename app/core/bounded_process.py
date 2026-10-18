"""Run local commands while bounding retained output, input and runtime."""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def run_bounded(argv: list[str], *, timeout: float = 30, stdin: bytes | None = None,
                max_stdout: int = 1024 * 1024, max_stderr: int = 1024 * 1024,
                cwd: str | None = None, env: dict[str, str] | None = None,
                max_file_size: int | None = None) -> dict[str, Any]:
    """Drain subprocess pipes with byte caps and kill the group on cap/timeout.

    ``max_file_size`` optionally inserts a tiny exec helper that applies
    ``RLIMIT_FSIZE`` and a private umask without a threaded ``preexec_fn``.
    """
    started = time.monotonic()
    command = argv
    if max_file_size is not None:
        try:
            __import__("resource")
        except ImportError:
            resource_supported = False
        else:
            resource_supported = os.name == "posix"
        if not resource_supported:
            return {"returncode": 126, "stdout": b"", "stderr": b"file output limit unsupported",
                    "timed_out": False, "truncated": False, "duration": time.monotonic() - started,
                    "file_limit_unsupported": True}
        helper = Path(__file__).with_name("bounded_file_exec.py")
        command = [sys.executable, str(helper), str(max(0, int(max_file_size))), *argv]
    try:
        process = subprocess.Popen(
            command, cwd=cwd, env=env, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, start_new_session=True,
        )
    except OSError as exc:
        return {"returncode": 127, "stdout": b"", "stderr": str(exc).encode(),
                "timed_out": False, "truncated": False, "duration": time.monotonic() - started}

    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    input_offset = 0
    if stdin is not None:
        assert process.stdin is not None
        if stdin:
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    caps = {"stdout": max(0, max_stdout), "stderr": max(0, max_stderr)}
    truncated = {"stdout": False, "stderr": False}
    deadline = started + max(0.1, timeout)
    timed_out = False
    exceeded = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(remaining, 0.25)):
                if key.data == "stdin":
                    try:
                        input_offset += os.write(key.fileobj.fileno(), stdin[input_offset:input_offset + 64 * 1024])
                    except BrokenPipeError:
                        input_offset = len(stdin)
                    if input_offset >= len(stdin):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                block = os.read(key.fileobj.fileno(), 64 * 1024)
                if not block:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                name = key.data
                room = caps[name] - len(buffers[name])
                if room > 0:
                    buffers[name].extend(block[:room])
                if len(block) > max(0, room):
                    truncated[name] = True
                    exceeded = True
                    break
            if exceeded:
                break
        if timed_out or exceeded:
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
    return {"returncode": returncode, "stdout": bytes(buffers["stdout"]),
            "stderr": bytes(buffers["stderr"]), "timed_out": timed_out,
            "truncated": any(truncated.values()), "stdout_truncated": truncated["stdout"],
            "stderr_truncated": truncated["stderr"], "duration": time.monotonic() - started}
