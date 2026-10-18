"""Optional read-only Dislocker export adapter.

Secrets are written to the process stdin by requesting the interactive password
mode. They do not appear in argv or persisted audit records. ``dislocker-file``
creates a separate NTFS image and never needs to mount the source.
"""

from __future__ import annotations
import shutil
from pathlib import Path


def unlock(path:Path,volume:dict,secret:str,method:str,target:Path,runner,max_bytes:int)->dict:
    """Run dislocker-file with a password, recovery password or FVEK file.

    Passwords are supplied over stdin so they never appear in process listings.
    An FVEK is an already isolated 66-byte local artifact and is passed through
    ``-k``. Success still requires a complete flat output; callers subsequently
    validate its filesystem before treating the key as correct.
    """
    binary=shutil.which("dislocker-file")
    if not binary:return {"status":"not_supported","reason":"dislocker-file unavailable"}
    if volume["length"]>max_bytes:return {"status":"limit_reached","reason":"decrypted volume exceeds output budget"}
    if method=="fvek":
        key=Path(secret)
        if not key.is_file() or key.is_symlink() or key.stat().st_size!=66:
            return {"status":"corrupted_artifact","reason":"FVEK artifact must be a regular 66-byte file"}
        switch=["-k",str(key)];stdin=None
    else:
        switch=["-p" if method=="recovery_password" else "-u"];stdin=(secret+"\n").encode()
    target.parent.mkdir(parents=True,exist_ok=True)
    result=runner.run([binary,"-r","-q","-V",str(path),"-O",str(volume["offset"]),*switch,"--",str(target)],600,stdin)
    if result["exit_code"]!=0 or not target.is_file():
        target.unlink(missing_ok=True);return {"status":"wrong_password" if "password" in result["stderr"].casefold() else "failed","reason":result["stderr"][-300:]}
    if target.stat().st_size>max_bytes:
        target.unlink(missing_ok=True);return {"status":"limit_reached","reason":"dislocker output exceeded budget"}
    target.chmod(0o400);return {"status":"success","password_verified":method!="fvek","key_verified":method=="fvek","path":str(target),"size":target.stat().st_size,"method":"dislocker_file_read_only_"+method,"writable":False}
