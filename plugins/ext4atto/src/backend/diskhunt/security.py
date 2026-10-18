from __future__ import annotations
import re
from pathlib import Path


def safe_filename(name: str, fallback: str = "artifact.bin") -> str:
    name = Path(name.replace("\\", "/")).name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name[:180] or fallback


def resolve_artifact(root: Path, requested: str) -> Path:
    if "\x00" in requested or Path(requested).is_absolute(): raise ValueError("invalid artifact path")
    target = (root / requested).resolve()
    root = root.resolve()
    if root not in target.parents or not target.is_file(): raise ValueError("artifact not found")
    return target

