"""Execute preserved suites separately to respect their module import namespaces."""

import os
import subprocess
import sys
import shutil
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
projects = [
    "app/vendor/magic_wrapper",
    "plugins/hidgrabber/src",
    "plugins/pic-up/src",
    "plugins/ext4atto/src",
    "plugins/githappens/src",
]
failed = []
for project in projects:
    print(f"\nTesting {project}", flush=True)
    with tempfile.TemporaryDirectory(prefix="forensic-hub-legacy-tests-") as directory:
        isolated = Path(directory) / "source"
        shutil.copytree(
            root / project, isolated, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache")
        )
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=isolated,
            env={**os.environ, "PYTHONPATH": str(isolated)},
            check=False,
        )
    if completed.returncode:
        failed.append(project)
if failed:
    raise SystemExit("Failed: " + ", ".join(failed))
