"""Optional local-only YARA scanning.

Only regular, non-symlink rule files explicitly visible in the sandbox are
compiled. Match metadata is classification evidence, never a malware verdict.
No rules are downloaded automatically.
"""

from pathlib import Path


def scan(path:Path,rule_paths:list[str],timeout:int=20)->tuple[list[dict],list[str]]:
    """Apply at most 64 local YARA rule files and return normalized matches."""
    if not rule_paths:return [],[]
    try:import yara
    except ImportError:return [],["yara-python non disponibile"]
    safe=[]
    for value in rule_paths[:64]:
        candidate=Path(value)
        if candidate.is_file() and not candidate.is_symlink() and candidate.suffix in {".yar",".yara"} and candidate.stat().st_size<=1024*1024:safe.append(candidate)
    if not safe:return [],["Nessuna regola YARA locale valida o visibile nel sandbox"]
    try:
        rules=yara.compile(filepaths={f"rule_{index}":str(value) for index,value in enumerate(safe)})
        matches=rules.match(str(path),timeout=max(1,min(timeout,60)))
        rows=[]
        for match in matches[:1000]:
            offsets=[]
            for item in match.strings:
                for instance in getattr(item,"instances",[]):offsets.append({"identifier":item.identifier,"offset":instance.offset,"length":instance.matched_length})
            rows.append({"rule":match.rule,"namespace":match.namespace,"tags":list(match.tags),"metadata":dict(match.meta),"strings":offsets[:1000],"confidence":.75,"interpretation":"pattern_match_not_behavior_proof"})
        return rows,[]
    except (yara.Error,OSError) as exc:return [],[f"YARA: {exc}"]
