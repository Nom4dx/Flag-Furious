"""Explicit, bounded Hashcat launcher for local BitLocker mode 22100."""

from __future__ import annotations
import shutil,subprocess,time
from pathlib import Path


def run(hash_file:Path,wordlists:list[Path],workdir:Path,options:dict)->dict:
    """Run Hashcat only after confirmation and keep recovered secrets out of logs."""
    if not options.get("confirmed"):return {"status":"waiting_for_user","engine":"hashcat"}
    binary=shutil.which("hashcat")
    if not binary:return {"status":"not_supported","reason":"hashcat unavailable"}
    if not wordlists:return {"status":"no_wordlists"}
    outfile=workdir/"hashcat.out";pot=workdir/"hashcat.pot";started=time.monotonic()
    command=[binary,"-m","22100","--potfile-path",str(pot),"--outfile",str(outfile),"--quiet",str(hash_file),*[str(path) for path in wordlists]]
    try:completed=subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,shell=False,timeout=min(int(options.get("timeout",900)),900),check=False)
    except subprocess.TimeoutExpired:return {"status":"timeout","engine":"hashcat","duration":round(time.monotonic()-started,3)}
    status="success" if outfile.exists() and outfile.stat().st_size else "not_found" if completed.returncode in {0,1} else "failed"
    return {"status":status,"engine":"hashcat","password_verified":False,"secret_pending_vault_import":status=="success","exit_code":completed.returncode,"duration":round(time.monotonic()-started,3)}
