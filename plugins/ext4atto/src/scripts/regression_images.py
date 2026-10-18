#!/usr/bin/env python3
"""Run the real engine against arbitrary challenge images; contains no known answers."""
from __future__ import annotations
import argparse
import json
import shutil
import tempfile
from pathlib import Path
from threading import Event
from diskhunt.analyzer import Analyzer
from diskhunt.db import Database
from diskhunt.models import AnalysisOptions


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("images", nargs="+", type=Path)
    parser.add_argument("--prefix", default="picoCTF{")
    args = parser.parse_args(); failed = False
    for source in args.images:
        with tempfile.TemporaryDirectory(prefix="diskhunt-regression-") as temporary:
            root = Path(temporary); original = root / source.name; shutil.copyfile(source, original)
            database = Database(root / "results.sqlite3"); options = AnalysisOptions(prefix=args.prefix)
            database.create_job("regression", source.name, str(original), options.model_dump(), source.stem)
            Analyzer(database, "regression", Event()).run(); job = database.get_job("regression")
            flags = database.results("regression", "flag"); artifacts = database.results("regression", "artifact")
            result = {"image": str(source), "status": job["status"], "error": job["error"],
                      "partitions": job["stats"].get("partitions", 0), "files": job["stats"].get("files", 0),
                      "artifacts": len(artifacts), "flags": flags}
            print(json.dumps(result, ensure_ascii=False))
            failed |= bool(job["error"])
    return int(failed)


if __name__ == "__main__": raise SystemExit(main())

