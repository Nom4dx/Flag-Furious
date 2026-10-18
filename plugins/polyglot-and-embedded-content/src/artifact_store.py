"""Deduplicated, traversal-safe artifact writer for the isolated workspace."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


class ArtifactStore:
    """Write passive derived bytes under a controlled case output directory.

    Inputs are trusted categories plus untrusted display names. Names are reduced
    to a safe basename; symlinks are never created. The SHA-256 index deduplicates
    content. Output budget exhaustion raises ``ValueError`` for partial reporting.
    """

    def __init__(self, root: Path, byte_budget: int):
        self.root = root
        self.byte_budget = byte_budget
        self.written = 0
        self.by_hash: dict[str, dict] = {}

    def save_bytes(self, category: str, name: str, data: bytes, metadata: dict | None = None) -> dict:
        """Persist bytes once and return hub artifact metadata.

        ``ValueError`` signals the configured budget. Path traversal and Unicode
        controls are removed. Example: ``store.save_bytes('carved','x.zip', data)``.
        """
        digest = hashlib.sha256(data).hexdigest()
        if digest in self.by_hash:
            return {**self.by_hash[digest], "deduplicated": True}
        if self.written + len(data) > self.byte_budget:
            raise ValueError("budget artefatti superato")
        clean_category = re.sub(r"[^a-z0-9_-]", "_", category.lower()) or "raw"
        clean_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name).strip(".") or "artifact.bin"
        folder = self.root / clean_category
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / f"{digest[:12]}-{clean_name}"
        target.write_bytes(data)
        self.written += len(data)
        record = {"name": target.name, "path": str(target), "kind": clean_category, "sha256": digest, "size": len(data), **(metadata or {})}
        self.by_hash[digest] = record
        return record

