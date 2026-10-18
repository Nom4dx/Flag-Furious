"""Read-only BitLocker unlock and linear export through pybde/libbde.

The adapter receives a secret only in memory, verifies ``volume.unlock()``, and
exports decrypted sectors to a separate file. It never mounts or writes the
encrypted source. Output is bounded before the first decrypted byte is written.
"""

from __future__ import annotations
from pathlib import Path
from .image_reader import SliceReader


def unlock(path:Path,volume:dict,secret:str,method:str,target:Path,max_bytes:int)->dict:
    """Verify a password/recovery password and export a read-only virtual volume."""
    try:import pybde
    except ImportError:return {"status":"not_supported","reason":"pybde unavailable"}
    view=SliceReader(path,volume["offset"],volume["length"]);handle=None
    try:
        handle=pybde.volume();handle.open_file_object(view)
        if method=="recovery_password":handle.set_recovery_password(secret)
        else:handle.set_password(secret)
        if not handle.unlock() or handle.locked:return {"status":"wrong_password","password_verified":False}
        size=int(handle.size)
        if size>max_bytes:return {"status":"limit_reached","password_verified":True,"reason":f"decrypted volume {size} exceeds output budget","size":size}
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open("xb") as destination:
            remaining=size
            while remaining:
                data=handle.read(min(8*1024*1024,remaining))
                if not data:break
                destination.write(data);remaining-=len(data)
        if remaining:
            target.unlink(missing_ok=True);return {"status":"failed","password_verified":True,"reason":"short decrypted read"}
        target.chmod(0o400)
        return {"status":"success","password_verified":True,"path":str(target),"size":size,"method":"libbde_read_only_export","writable":False}
    except Exception as exc:return {"status":"wrong_password" if "unlock" in str(exc).casefold() or "key" in str(exc).casefold() else "failed","password_verified":False,"reason":str(exc)}
    finally:
        try:
            if handle:handle.close()
        except Exception:pass
        view.close()
