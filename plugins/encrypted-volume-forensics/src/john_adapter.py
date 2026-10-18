"""Explicit, bounded John the Ripper launcher for derived BitLocker hashes."""
from __future__ import annotations

import shutil
import time
import uuid
from pathlib import Path

from .tool_adapters import ToolRunner, private_tool_env

MAX_WORDLISTS = 32
MAX_RECOVERY_FILE_BYTES = 16 * 1024 * 1024


def run(hash_file: Path, wordlists: list[Path], workdir: Path, options: dict) -> dict:
    """Run John only after confirmation with cumulative timeout and file caps."""
    if not options.get("confirmed"):
        return {"status": "waiting_for_user", "engine": "john"}
    binary = shutil.which("john")
    if not binary:
        return {"status": "not_supported", "reason": "john unavailable"}
    if not wordlists:
        return {"status": "no_wordlists"}
    selected = wordlists[:MAX_WORDLISTS]
    wordlists_truncated = len(wordlists) > MAX_WORDLISTS
    try:
        time_limit = max(1, min(int(options.get("timeout", 900)), 900))
    except (TypeError, ValueError):
        time_limit = 900
    workdir.mkdir(parents=True, exist_ok=True)
    workdir = workdir.resolve()
    run_dir = workdir / f"john-{uuid.uuid4().hex}"
    run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    potfile = run_dir / "private.pot"
    runner = ToolRunner()
    started = time.monotonic()
    attempted = []
    status = "not_found"
    for wordlist in selected:
        remaining = time_limit - (time.monotonic() - started)
        if remaining <= 0:
            status = "timeout"
            break
        command = [binary, "--nolog", f"--pot={potfile}", f"--wordlist={wordlist.resolve()}", str(hash_file.resolve())]
        result = runner.run(command, timeout=max(1, int(remaining)),
                             max_file_size=MAX_RECOVERY_FILE_BYTES,
                             env=private_tool_env(run_dir), cwd=str(run_dir.resolve()))
        attempted.append(wordlist.name)
        if result.get("timed_out"):
            status = "timeout"
            break
        if result.get("output_truncated") or result.get("file_limit_unsupported"):
            status = "partial"
            break
        if result.get("exit_code") not in {0, 1}:
            status = "failed"
            break
        if potfile.is_file() and potfile.stat().st_size:
            status = "success"
            break
    has_recovery = potfile.is_file() and potfile.stat().st_size > 0
    if wordlists_truncated and status in {"success", "not_found"}:
        status = "partial"
    return {"status": status, "engine": "john", "password_verified": False,
            "secret_pending_vault_import": has_recovery,
            "recovery_status": "success" if has_recovery else None,
            "wordlists": attempted, "wordlists_truncated": wordlists_truncated,
            "recovery_output_bytes": potfile.stat().st_size if has_recovery else 0,
            "recovery_ref": run_dir.name if has_recovery else None,
            "duration": round(time.monotonic() - started, 3)}
