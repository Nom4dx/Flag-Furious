"""Check that every preserved source file still matches the imported inventory."""

import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
items = json.loads((root / "docs/source-inventory.json").read_text())
for item in items:
    actual = hashlib.sha256((root / item["copy"]).read_bytes()).hexdigest()
    if actual != item["sha256"]:
        raise SystemExit("Modified preserved source: " + item["copy"])
print(f"PASS: {len(items)} preserved source files, SHA-256 unchanged")
