from __future__ import annotations
from enum import StrEnum
from typing import Any
from pydantic import BaseModel, Field, field_validator


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Budgets(BaseModel):
    total: int = Field(512 * 1024**2, ge=512, le=1024**4)
    metadata: int = Field(64 * 1024**2, ge=0)
    search: int = Field(256 * 1024**2, ge=0)
    journal: int = Field(64 * 1024**2, ge=0)
    carving: int = Field(128 * 1024**2, ge=0)
    max_request: int = Field(1024**2, ge=512, le=64 * 1024**2)
    cache_size: int = Field(8 * 1024**2, ge=0, le=1024**3)


class AnalysisOptions(BaseModel):
    prefix: str | None = Field(None, max_length=256)
    prefixes: list[str] = Field(default_factory=list, max_length=32)
    prefix_is_regex: bool = False
    mode: str = Field("balanced", pattern="^(quick|balanced|deep)$")
    budgets: Budgets = Field(default_factory=Budgets)
    custom_signatures: list[dict[str, str]] = Field(default_factory=list)
    source_hashes: dict[str, str] = Field(default_factory=dict)
    source_size: int | None = Field(None, ge=0)

    @field_validator("prefix")
    @classmethod
    def blank_is_none(cls, value: str | None) -> str | None:
        return value or None

    @field_validator("prefixes")
    @classmethod
    def validate_prefixes(cls, values: list[str]) -> list[str]:
        return [value for value in dict.fromkeys(values) if value][:32]


class JobView(BaseModel):
    id: str
    status: JobStatus
    phase: str
    progress: float
    created_at: str
    updated_at: str
    error: str | None = None
    warnings: list[str] = []
    stats: dict[str, Any] = {}
    options: dict[str, Any] = {}
