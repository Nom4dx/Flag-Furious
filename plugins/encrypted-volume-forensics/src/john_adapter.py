"""Explicit John the Ripper launcher for derived BitLocker hashes.

This adapter runs only when the caller records user confirmation. A private pot
file prevents cross-case credential leakage. Plaintext recovery output is not
placed in the tool audit; recovered secrets must be handed to the Hub vault.
"""

from __future__ import annotations
import shutil,subprocess,time
from pathlib import Path


def run(hash_file:Path,wordlists:list[Path],workdir:Path,options:dict)->dict:
    """Run bounded John against one local hash and return status without secret."""
    if not options.get("confirmed"):return {"status":"waiting_for_user","engine":"john"}
    binary=shutil.which("john")
    if not binary:return {"status":"not_supported","reason":"john unavailable"}
    if not wordlists:return {"status":"no_wordlists"}
    pot=workdir/"john.pot";started=time.monotonic();attempted=[]
    for wordlist in wordlists:
        command=[binary,f"--pot={pot}",f"--wordlist={wordlist}",str(hash_file)]
        try:completed=subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,shell=False,timeout=min(int(options.get("timeout",900)),900),check=False)
        except subprocess.TimeoutExpired:return {"status":"timeout","engine":"john","duration":round(time.monotonic()-started,3)}
        attempted.append(str(wordlist.name))
        if pot.exists() and pot.stat().st_size:return {"status":"success","engine":"john","password_verified":False,"secret_pending_vault_import":True,"wordlists":attempted,"duration":round(time.monotonic()-started,3)}
    return {"status":"not_found","engine":"john","wordlists":attempted,"duration":round(time.monotonic()-started,3)}
