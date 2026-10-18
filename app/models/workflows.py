"""Validated models for editable connector workflows."""

from typing import Any, Literal
from pydantic import BaseModel, Field, model_validator


class WorkflowNode(BaseModel):
    """One asset or connector node with persisted non-secret configuration."""

    id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
    kind: Literal["asset", "connector"]
    asset_id: str | None = None
    connector_id: str | None = None
    x: float = Field(0, ge=0, le=5000)
    y: float = Field(0, ge=0, le=5000)
    config: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def matching_reference(self):
        """Require exactly the reference associated with the node kind."""
        if self.kind == "asset" and (not self.asset_id or self.connector_id):
            raise ValueError("Un nodo asset richiede solo asset_id")
        if self.kind == "connector" and (not self.connector_id or self.asset_id):
            raise ValueError("Un nodo connector richiede solo connector_id")
        if len(str(self.config)) > 65536:
            raise ValueError("Configurazione del nodo troppo grande")
        return self


class WorkflowEdge(BaseModel):
    """Directed connection from an asset/output node to a connector node."""

    id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
    source: str
    target: str


class WorkflowInput(BaseModel):
    """Saved acyclic workflow belonging to one forensic case."""

    case_id: str
    name: str = Field("Workflow estrazione", min_length=1, max_length=160)
    nodes: list[WorkflowNode] = Field(min_length=1, max_length=200)
    edges: list[WorkflowEdge] = Field(default_factory=list, max_length=400)

    @model_validator(mode="after")
    def references(self):
        ids = {n.id for n in self.nodes}
        if len(ids) != len(self.nodes):
            raise ValueError("ID nodo duplicato")
        if any(e.source not in ids or e.target not in ids or e.source == e.target for e in self.edges):
            raise ValueError("Arco workflow non valido")
        if len({e.id for e in self.edges}) != len(self.edges):
            raise ValueError("ID arco duplicato")
        return self


class WorkflowRunInput(BaseModel):
    """Ephemeral secrets supplied only for this execution."""

    secrets: dict[str, dict[str, str]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def bounded_secrets(self):
        """Bound ephemeral connector input before it reaches a worker closure."""
        if len(self.secrets) > 32 or any(len(values) > 8 for values in self.secrets.values()):
            raise ValueError("Troppi campi segreti")
        if any(
            len(key) > 64 or len(value) > 4096
            for values in self.secrets.values()
            for key, value in values.items()
        ):
            raise ValueError("Campo segreto troppo lungo")
        return self
