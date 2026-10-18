import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Settings:
    root: Path = ROOT
    storage: Path = field(default_factory=lambda: Path(os.getenv("HUB_STORAGE", ROOT / "storage")).resolve())
    plugins: Path = field(default_factory=lambda: Path(os.getenv("HUB_PLUGINS", ROOT / "plugins")).resolve())
    connectors: Path = field(default_factory=lambda: Path(os.getenv("HUB_CONNECTORS", ROOT / "connectors")).resolve())
    max_upload: int = int(os.getenv("HUB_MAX_UPLOAD", 1024**3))
    max_case_bytes: int = int(os.getenv("HUB_MAX_CASE_BYTES", 4 * 1024**3))
    byte_budget: int = int(os.getenv("HUB_BYTE_BUDGET", 1024**3))
    timeout: int = int(os.getenv("HUB_TIMEOUT", 120))
    memory_mb: int = int(os.getenv("HUB_MEMORY_MB", 1024))
    max_workspace_bytes: int = int(os.getenv("HUB_MAX_WORKSPACE_BYTES", 1024**3))
    max_depth: int = 3
    # Total evidence and derived assets retained by a case. The traversal limit below
    # bounds a single recursive job independently, so large cases remain reusable.
    max_assets: int = int(os.getenv("HUB_MAX_ASSETS", 1024))
    max_pipeline_assets: int = int(os.getenv("HUB_MAX_PIPELINE_ASSETS", 128))
    max_jobs: int = 2
    signature_files: tuple = field(
        default_factory=lambda: tuple(filter(None, os.getenv("HUB_SIGNATURE_FILES", "").split(os.pathsep)))
    )
    wordlist_roots: tuple = field(
        default_factory=lambda: tuple(
            filter(None, os.getenv("FORENSIC_HUB_WORDLIST_ROOT", "").split(os.pathsep))
        )
    )

    def initialize(self):
        for name in ("cases", "uploads", "artifacts", "reports", "temporary"):
            (self.storage / name).mkdir(parents=True, exist_ok=True)
