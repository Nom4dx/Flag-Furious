"""Optional tool inventory and conservative metadata/detection adapters.

Tools enrich evidence but are never required for core decoding. Password attacks
are disabled unless a password or explicitly configured finite wordlist is passed.
No adapter runs an extracted executable or uses network access.
"""

from __future__ import annotations

from pathlib import Path

from .safe_subprocess import ALLOWLIST, locate, run


def inventory(timeout: int = 3, output_limit: int = 65536) -> list[dict]:
    """Report availability and bounded version output for every optional tool."""
    values = []
    for tool in sorted(ALLOWLIST):
        binary = locate(tool)
        if not binary:
            values.append({"tool": tool, "available": False, "status": "not_applicable"})
            continue
        version_arg = "-version" if tool in {"ffmpeg", "ffprobe"} else "--version"
        result = run(tool, [version_arg], timeout, output_limit)
        values.append({"tool": tool, "available": True, "path": binary, "version": (result["stdout"] or result["stderr"]).splitlines()[:1], "exit_code": result["exit_code"]})
    return values


def inspect_file(path: Path, timeout: int, output_limit: int) -> list[dict]:
    """Run only low-risk identification/metadata adapters on the source file."""
    results = []
    for tool, args in (
        ("file", ["-b", "--", str(path)]),
        ("exiftool", ["-json", "-G", "-n", "--", str(path)]),
    ):
        if locate(tool):
            results.append(run(tool, args, timeout, output_limit))
    return results


def steg_detectors(path: Path, detected_format: str, timeout: int, output_limit: int, password: str | None = None) -> list[dict]:
    """Run format-appropriate passive steganography detectors.

    ``steghide info`` and ``stegseek --seed`` do not brute-force. A provided
    password may be used by a future extraction action, but is never guessed here.
    Zsteg is restricted to check mode. Failures remain diagnostic results.
    """
    results = []
    if detected_format in {"png", "bmp"} and locate("zsteg"):
        results.append(run("zsteg", ["--all", str(path)], timeout, output_limit))
    if detected_format in {"jpeg", "bmp", "wav", "au"} and locate("steghide"):
        args = ["info", str(path), "-p", password or ""]
        results.append(run("steghide", args, timeout, output_limit))
    if detected_format in {"jpeg", "bmp", "wav", "au"} and locate("stegseek"):
        results.append(run("stegseek", ["--seed", str(path)], timeout, output_limit))
    return results
