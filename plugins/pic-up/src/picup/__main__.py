"""Installed/module entry point for the backwards-compatible pic-up CLI."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    script = Path(__file__).resolve().parent.parent / "pic-up.py"
    spec = importlib.util.spec_from_file_location("picup_legacy_cli", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load CLI module: {script}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
