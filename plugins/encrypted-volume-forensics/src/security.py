"""Filesystem and subprocess safety primitives for passive volume analysis."""

from __future__ import annotations
import os,re
from pathlib import Path


def safe_name(value: str, fallback: str = "artifact.bin") -> str:
    """Return a flat portable name; path components and controls are removed."""
    name=Path(str(value).replace("\\","/")).name
    name=re.sub(r"[^A-Za-z0-9._-]+","_",name).strip("._")[:180]
    return name or fallback


def contained(root: Path, candidate: Path) -> Path:
    """Resolve an output and reject traversal beyond the isolated directory."""
    root=root.resolve();candidate=candidate.resolve()
    if candidate!=root and root not in candidate.parents:raise ValueError("path traversal blocked")
    return candidate


def is_safe_regular(path: Path) -> bool:
    """Accept a local regular non-symlink input only."""
    return path.is_file() and not path.is_symlink()


def mask_command(argv: list[str]) -> list[str]:
    """Mask values attached to password switches before audit persistence."""
    masked=[];hide_next=False
    for value in argv:
        if hide_next:masked.append("********");hide_next=False;continue
        lower=value.casefold()
        if lower in {"-p","--password","-u","--user-password","--recovery-password"}:
            masked.append(value);hide_next=True
        elif lower.startswith(("-p=","-u=","--password=","--user-password=","--recovery-password=")):
            masked.append(value.split("=",1)[0]+"=********")
        elif len(value)>2 and value[:2] in {"-p","-u"}:masked.append(value[:2]+"********")
        else:masked.append(value)
    return masked
