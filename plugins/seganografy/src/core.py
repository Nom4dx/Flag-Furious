"""Fault-isolated analysis state shared by the plugin orchestration phases."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .reporting import event


@dataclass
class AnalysisState:
    """Accumulate normalized evidence while allowing individual phases to fail.

    The state owns no file handles and is JSON-ready after binary candidate fields
    are removed by the orchestrator. ``run`` records duration and converts parser
    exceptions into warnings rather than hiding them or failing unrelated modules.
    """

    findings: list[dict] = field(default_factory=list)
    artifacts: list[dict] = field(default_factory=list)
    flags: list[dict] = field(default_factory=list)
    visualizations: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    modules: dict[str, dict] = field(default_factory=dict)
    tools: list[dict] = field(default_factory=list)

    def run(self, name: str, reporter, function, *, default=None):
        """Execute one parser phase and retain recoverable failure provenance."""
        reporter.phase(name); reporter.log(f"Avvio fase: {name}"); started=time.monotonic()
        try:
            result=function(); self.modules[name]=result; self.events.append(event(name,started,"completed")); return result
        except Exception as exc:  # Parser boundaries deliberately isolate third-party failures.
            message=f"{name}: {type(exc).__name__}: {exc}"; self.warnings.append(message); reporter.log(message,level="warning"); self.events.append(event(name,started,"partial",error=str(exc))); self.modules[name]=default if default is not None else {}; return self.modules[name]
