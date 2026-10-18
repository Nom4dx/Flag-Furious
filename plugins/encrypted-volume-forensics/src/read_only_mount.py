"""Credential-controlled decrypted-volume export without filesystem mounts."""

from pathlib import Path
from . import dislocker_adapter,libbde_adapter


def unlock(path:Path,volume:dict,secret:str,method:str,target:Path,runner,max_bytes:int,engine:str="libbde")->dict:
    """Select libbde or Dislocker; both create a separate read-only artifact."""
    if method=="fvek":return dislocker_adapter.unlock(path,volume,secret,method,target,runner,max_bytes)
    if engine=="dislocker":return dislocker_adapter.unlock(path,volume,secret,method,target,runner,max_bytes)
    result=libbde_adapter.unlock(path,volume,secret,method,target,max_bytes)
    if result["status"]=="not_supported":return dislocker_adapter.unlock(path,volume,secret,method,target,runner,max_bytes)
    return result
