"""Deduplicated artifact writer restricted to the hub work directory."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


class ArtifactStore:
    """Write passive derived artifacts with provenance and SHA-256.

    Input: hub output directory. Output: artifact descriptors accepted by the hub.
    Raises ``ValueError`` when the category is unknown or budget is exhausted.
    Limits: caller-supplied byte budget. Security: sanitized flat filenames, no
    overwrite, no path traversal. Example: ``store.save("pdf", "x.bin", data, {})``.
    """

    CATEGORIES = {"raw", "metadata", "pdf", "office", "ole", "rtf", "images", "payloads", "timeline", "flags"}

    def __init__(self, root: Path, budget: int):
        self.root = root.resolve() / "document-metadata-forensics"
        self.root.mkdir(parents=True, exist_ok=True)
        self.remaining = budget
        self.seen: dict[str, dict] = {}

    def save(self, category: str, name: str, content: bytes | str, provenance: dict) -> dict:
        """Persist one deduplicated artifact and return its hub descriptor."""
        if category not in self.CATEGORIES:
            raise ValueError(f"Categoria artefatto non valida: {category}")
        data = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        digest = hashlib.sha256(data).hexdigest()
        if digest in self.seen:
            return self.seen[digest]
        if len(data) > self.remaining:
            raise ValueError("Budget artefatti esaurito")
        self.remaining -= len(data)
        folder = self.root / category
        folder.mkdir(exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name).strip(".")[:120] or "artifact.bin"
        target = folder / f"{digest[:12]}-{safe}"
        target.write_bytes(data)
        record = {"path": str(target), "name": safe, "type": "file", "method": provenance.get("method", "static extraction"), "offset": provenance.get("offset"), "sha256": digest, "source": provenance.get("source"), "internal_path": provenance.get("internal_path"), "category": category}
        self.seen[digest] = record
        return record

    def report(self, value: dict) -> dict:
        """Save a deterministic JSON report; binary document bytes are excluded."""
        return self.save("metadata", "report.json", json.dumps(value, ensure_ascii=False, indent=2), {"method": "plugin report"})
