from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable

MAX_COMMAND_OUTPUT = 8 * 1024 * 1024


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
        completed = subprocess.run(
            argv, cwd=cwd, input=input_data, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False,
            env={**os.environ, "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0"},
        )
        return {
            "command": argv, "returncode": completed.returncode,
            "stdout": completed.stdout[:MAX_COMMAND_OUTPUT].decode("utf-8", "replace"),
            "stderr": completed.stderr[:MAX_COMMAND_OUTPUT].decode("utf-8", "replace"),
            "ok": completed.returncode == 0,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"command": argv, "returncode": -1, "stdout": "", "stderr": str(exc), "ok": False}


def run_binary(argv: list[str], *, cwd: Path | None = None, timeout: int = 120, max_bytes: int = 256 * 1024 * 1024) -> tuple[bytes, dict[str, Any]]:
    try:
        completed = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=timeout, check=False,
                                   env={**os.environ, "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0"})
        data = completed.stdout[:max_bytes]
        return data, {"command": argv, "returncode": completed.returncode, "stdout": f"<{len(data)} binary bytes>",
                      "stderr": completed.stderr[:MAX_COMMAND_OUTPUT].decode("utf-8", "replace"), "ok": completed.returncode == 0}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return b"", {"command": argv, "returncode": -1, "stdout": "", "stderr": str(exc), "ok": False}


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
