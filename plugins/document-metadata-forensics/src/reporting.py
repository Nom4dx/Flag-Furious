"""Shared result model and fault-isolated module runner.

Inputs and outputs are JSON-compatible dictionaries. No document content is
executed. A module exception becomes a recoverable warning and never hides work
completed by other parsers.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class ModuleResult:
    """Collect one parser's output.

    Input: a stable module name. Output: JSON-safe fields via :meth:`as_dict`.
    Exceptions: none. Limits: callers enforce byte/item budgets. Security: this
    model stores passive evidence only. Example: ``ModuleResult("pdf")``.
    """

    name: str
    status: str = "completed"
    items: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    artifacts: list[dict] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        """Return a serializable snapshot; no input mutation or I/O occurs."""
        return {
            "module": self.name,
            "status": self.status,
            "items": self.items,
            "findings": self.findings,
            "artifacts": self.artifacts,
            "timeline": self.timeline,
            "warnings": self.warnings,
            "metrics": self.metrics,
        }


def run_module(name: str, function: Callable[[], ModuleResult], reporter) -> ModuleResult:
    """Run one parser with timing and recoverable failure handling.

    Input: module name, zero-argument parser and hub reporter. Output: a
    ``ModuleResult``. Parser exceptions are converted to ``partial`` results.
    Security: error text is data; no command is evaluated. Example:
    ``run_module("xmp", lambda: parse_xmp(data), reporter)``.
    """
    reporter.phase(name)
    reporter.log(f"Avvio modulo {name}")
    started = time.monotonic()
    try:
        result = function()
    except Exception as exc:  # fault boundary is intentional for plugin modules
        result = ModuleResult(name, status="partial")
        result.warnings.append(f"{name}: {type(exc).__name__}: {exc}")
    result.metrics["duration_seconds"] = round(time.monotonic() - started, 6)
    reporter.log(f"Modulo {name}: {result.status}")
    return result
