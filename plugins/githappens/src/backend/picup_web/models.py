from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Artifact:
    id: str
    source: str
    path: str
    offset: int | None
    size: int
    sha256: str
    timestamp: str | None
    extraction_method: str
    module: str
    confidence: float
    status: str = "active"
    mime: str = "application/octet-stream"
    metadata: dict[str, Any] = field(default_factory=dict)

    def dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    module: str
    kind: str
    source: str
    path: str
    value: str
    timestamp: str | None = None
    offset: int | None = None
    size: int = 0
    sha256: str = ""
    method: str = "parser"
    confidence: float = 1.0
    context_before: str = ""
    context_after: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def dict(self) -> dict[str, Any]:
        return asdict(self)

