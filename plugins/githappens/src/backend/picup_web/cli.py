from __future__ import annotations

import argparse
import json
from pathlib import Path

from .cases import CaseStore
from .pipeline import Pipeline


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze one evidence file using GitHappens")
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--prefixes", default="")
    parser.add_argument("--regex", default="")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    args = parser.parse_args()
    with args.evidence.open("rb") as source:
        if args.reference:
            with args.reference.open("rb") as reference:
                case = CaseStore(args.data_dir).create(args.evidence.stem, args.evidence.name, source, args.reference.name, reference)
        else:
            case = CaseStore(args.data_dir).create(args.evidence.stem, args.evidence.name, source)
    store = CaseStore(args.data_dir)
    case["configuration"] = {"prefixes": args.prefixes, "regex": args.regex, "case_sensitive": False, "timezone": "Europe/Rome"}
    store.save(case["id"], case)
    Pipeline(store).run(case["id"])
    result = store.load(case["id"])
    print(json.dumps({"id": result["id"], "status": result["status"], "result": result.get("result"), "flags": result["findings"], "case_dir": str(store.path(result["id"]))}, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
