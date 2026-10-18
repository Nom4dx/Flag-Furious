from typing import Any, Literal
from pydantic import BaseModel, Field, ConfigDict


class Manifest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    name: str
    version: str
    author: str = ""
    description: str = ""
    entrypoint: str = "plugin.py"
    class_name: str = Field(alias="class")
    domains: list[str] = Field(default_factory=list)
    supported_asset_types: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    unlock_capabilities: dict[str, Any] = Field(default_factory=dict)
    activation: Literal["automatic", "connector_only"] = "automatic"
    dependencies: list[str] = Field(default_factory=list)
    python_dependencies: list[str] = Field(default_factory=list)
    binaries: list[str] = Field(default_factory=list)
    optional_binaries: list[str] = Field(default_factory=list)
    execution_mode: Literal["isolated"] = "isolated"
    requires_network: bool = False
    requires_root: bool = False
    permissions: list[str] = Field(default_factory=list)
    timeout: int = Field(60, ge=1, le=3600)
    cpu_seconds: int = Field(60, ge=1, le=3600)
    memory_mb: int = Field(512, ge=128, le=8192)
    byte_budget: int = Field(64 * 1024**2, ge=1024, le=1024**4)
    output_bytes: int = Field(64 * 1024**2, ge=1024, le=1024**3)
    input_access: Literal["bounded", "random_access"] = "bounded"
    workspace_bytes: int | None = Field(None, ge=1024, le=4 * 1024**3)
    custom_routes: str | None = None
    endpoints: list[dict[str, str]] = Field(default_factory=list)


class Result(BaseModel):
    model_config = ConfigDict(extra="allow")
    plugin_id: str
    asset_id: str
    status: Literal["completed", "partial", "failed", "cancelled", "skipped"] = "completed"
    summary: str = ""
    confidence: float = Field(0, ge=0, le=1)
    phase: str = "analysis"
    findings: list[Any] = Field(default_factory=list)
    sections: list[dict] = Field(default_factory=list)
    artifacts: list[dict] = Field(default_factory=list)
    derived_assets: list[dict] = Field(default_factory=list)
    visualizations: list[dict] = Field(default_factory=list)
    flags: list[dict] = Field(default_factory=list)
    timeline: list[dict] = Field(default_factory=list)
    execution_events: list[dict] = Field(default_factory=list)
    logs: list[Any] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    metrics: dict = Field(default_factory=dict)
    requested_plugins: list[str] = Field(default_factory=list)


class JobRequest(BaseModel):
    case_id: str
    asset_ids: list[str] = Field(min_length=1, max_length=128)
    plugin_ids: list[str] | None = None
    recursive: bool = True
    max_depth: int = Field(3, ge=0, le=8)
    byte_budget: int = Field(512 * 1024**2, ge=1024, le=1024**3)
    prefixes: list[str] = Field(default_factory=lambda: ["flag", "CTF", "HTB", "picoCTF"], max_length=32)
    patterns: list[str] = Field(default_factory=list, max_length=16)
    mode: Literal["quick", "balanced", "deep"] = "balanced"
    max_flags: int = Field(100, ge=1, le=1000)
    plugin_options: dict[str, Any] = Field(default_factory=dict)


class CaseInput(BaseModel):
    name: str = Field("Nuovo caso", max_length=200)


class AssetInput(BaseModel):
    case_id: str
    name: str = Field("input.txt", max_length=240)
    type: str = Field("text", min_length=1, max_length=80)
    content: Any
    metadata: dict = Field(default_factory=dict)


class FlagSearch(BaseModel):
    asset_id: str | None = None
    text: str = Field("", max_length=1024**2)
    prefixes: list[str] = Field(default_factory=lambda: ["flag", "CTF", "HTB", "picoCTF"], max_length=32)
    patterns: list[str] = Field(default_factory=list, max_length=16)
    byte_budget: int = Field(64 * 1024**2, ge=1, le=1024**3)
    max_results: int = Field(100, ge=1, le=1000)
    rc4_key: str | None = Field(None, max_length=256)
