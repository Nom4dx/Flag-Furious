"""Explicit, bounded Hashcat launcher for local BitLocker mode 22100."""
from __future__ import annotations

import shutil
import time
import uuid
from pathlib import Path

from .tool_adapters import ToolRunner, private_tool_env

MAX_WORDLISTS = 32
MAX_RECOVERY_FILE_BYTES = 16 * 1024 * 1024


def run(hash_file: Path, wordlists: list[Path], workdir: Path, options: dict) -> dict:
    """Run Hashcat after confirmation with bounded process and recovery files."""
    if not options.get("confirmed"):
        return {"status": "waiting_for_user", "engine": "hashcat"}
    binary = shutil.which("hashcat")
    if not binary:
        return {"status": "not_supported", "reason": "hashcat unavailable"}
    if not wordlists:
        return {"status": "no_wordlists"}
    selected = wordlists[:MAX_WORDLISTS]
    wordlists_truncated = len(wordlists) > MAX_WORDLISTS
    try:
        timeout = max(1, min(int(options.get("timeout", 900)), 900))
    except (TypeError, ValueError):
        timeout = 900
    workdir.mkdir(parents=True, exist_ok=True)
    workdir = workdir.resolve()
    run_dir = workdir / f"hashcat-{uuid.uuid4().hex}"
    run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    outfile = run_dir / "recovered.out"
    potfile = run_dir / "private.pot"
    command = [binary, "-m", "22100", "--potfile-path", str(potfile), "--outfile", str(outfile),
               "--logfile-disable", "--quiet", str(hash_file.resolve()),
               *(str(path.resolve()) for path in selected)]
    started = time.monotonic()
    result = ToolRunner().run(command, timeout=timeout, max_file_size=MAX_RECOVERY_FILE_BYTES,
                              env=private_tool_env(run_dir), cwd=str(run_dir.resolve()))
    duration = round(time.monotonic() - started, 3)
    if result.get("timed_out"):
        status = "timeout"
    elif result.get("output_truncated") or result.get("file_limit_unsupported"):
        status = "partial"
    elif result.get("exit_code") not in {0, 1}:
        status = "failed"
    else:
        status = "success" if outfile.is_file() and outfile.stat().st_size else "not_found"
    has_recovery = outfile.is_file() and outfile.stat().st_size > 0
    recovery_status = "success" if has_recovery else status
    if wordlists_truncated and status in {"success", "not_found"}:
        status = "partial"
    return {"status": status, "engine": "hashcat", "password_verified": False,
            "secret_pending_vault_import": has_recovery,
            "recovery_status": recovery_status if status == "partial" else None,
            "exit_code": result.get("exit_code"), "duration": duration,
            "recovery_output_bytes": outfile.stat().st_size if outfile.is_file() else 0,
            "recovery_ref": run_dir.name if has_recovery else None,
            "wordlists_used": len(selected), "wordlists_truncated": wordlists_truncated}
