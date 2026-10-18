"""Safe local Sigma subset evaluator over normalized ECS-like events.

Rules are YAML data only. Selection dictionaries, lists, contains, startswith and
endswith modifiers are supported; no generated query or shell is executed.
"""
from pathlib import Path
import fnmatch
import os

MAX_RULES = 1_000
MAX_RULE_BYTES = 256 * 1024
MAX_RULE_DIRECTORIES = 10_000
MAX_EVENTS = 10_000
MAX_RULE_EVENT_EVALUATIONS = 2_000_000
MAX_RULE_FIELD_COMPARISONS = 5_000_000
MAX_RECORDED_MATCHES = 1_000


class _SigmaBudgetExhausted(Exception):
    pass


def _collect_rules(root: Path, limit: int) -> tuple[list[Path], bool]:
    """Find local YAML rules without materializing an unbounded recursive glob."""
    if root.is_symlink() or not root.is_dir():
        return [], root.is_symlink()
    paths = []
    walked = 0
    limited = False
    for base, dirs, files in os.walk(root, followlinks=False):
        walked += 1
        if walked > MAX_RULE_DIRECTORIES:
            limited = True
            break
        dirs[:] = sorted(name for name in dirs if not (Path(base) / name).is_symlink())
        for name in sorted(files):
            if not name.casefold().endswith((".yaml", ".yml")):
                continue
            path = Path(base) / name
            if path.is_symlink() or not path.is_file():
                continue
            if len(paths) >= limit:
                limited = True
                return paths, limited
            paths.append(path)
    return paths, limited

def load_and_match(events:list[dict],roots:list[Path])->tuple[list[dict],list[str]]:
    """Validate and evaluate local Sigma files, returning provenance and warnings."""
    try:import yaml
    except ImportError:return [],['PyYAML non disponibile: Sigma saltato']
    matches=[];warnings=[]
    rule_paths=[];inventory_limited=False
    for root in roots:
        if not root.exists():continue
        remaining=MAX_RULES-len(rule_paths)
        paths,limited=_collect_rules(root,remaining)
        rule_paths.extend(paths)
        inventory_limited=inventory_limited or limited
    if inventory_limited:
        warnings.append(f"Inventario Sigma limitato a {MAX_RULES} regole")
    event_view=events[:MAX_EVENTS]
    if len(events)>len(event_view):
        warnings.append(f"Valutazione Sigma limitata ai primi {MAX_EVENTS} eventi su {len(events)}")
    remaining_evaluations=MAX_RULE_EVENT_EVALUATIONS
    comparison_budget=[MAX_RULE_FIELD_COMPARISONS]
    for root in roots:
        if not root.exists() or root.is_symlink():continue
        for path in (item for item in rule_paths if root in item.parents):
            try:
                with path.open('rb') as source:raw=source.read(MAX_RULE_BYTES+1)
                if len(raw)>MAX_RULE_BYTES:raise ValueError(f'regola oltre {MAX_RULE_BYTES} byte')
                rule=yaml.safe_load(raw.decode('utf-8'))
                if not isinstance(rule,dict):raise ValueError('la regola deve essere un oggetto YAML')
                detection=rule.get('detection',{});selections={k:v for k,v in detection.items() if k not in {'condition','timeframe'}}
                if not rule.get('title') or not selections:raise ValueError('detection assente')
                if len(selections)>128:raise ValueError('oltre 128 selection per regola')
                matched=[];matched_count=0
                for event in event_view:
                    if remaining_evaluations<=0:
                        break
                    remaining_evaluations-=1
                    if any(_selection(event,value,comparison_budget) for value in selections.values()):
                        matched_count+=1
                        if len(matched)<MAX_RECORDED_MATCHES:matched.append(event['event_id'])
                if matched_count:matches.append({"rule_id":str(rule.get('id') or path.stem),"rule_title":rule['title'],"rule_level":rule.get('level','medium'),"tags":rule.get('tags',[]),"matched_events":matched,"matched_event_count":matched_count,"matched_events_truncated":matched_count>len(matched),"fields":selections,"confidence":.9 if matched_count>1 else .76,"rule_source":str(path.relative_to(root.parent)),"false_positives":rule.get('falsepositives',[]),"references":rule.get('references',[])})
                if remaining_evaluations<=0:
                    warnings.append(f"Budget Sigma di {MAX_RULE_EVENT_EVALUATIONS} valutazioni esaurito")
                    return matches,warnings
            except _SigmaBudgetExhausted:
                warnings.append(f"Budget Sigma di {MAX_RULE_FIELD_COMPARISONS} confronti esaurito")
                return matches,warnings
            except Exception as exc:warnings.append(f'Sigma {path.name}: {exc}')
    return matches,warnings
def _selection(event,value,budget=None):
    if isinstance(value,list):return any(_selection(event,x,budget) for x in value)
    if not isinstance(value,dict):return False
    fields={**event,**event.get('raw_fields',{})}
    for field,expected in value.items():
        if budget is not None:
            budget[0]-=1
            if budget[0]<0:raise _SigmaBudgetExhausted
        base,*mods=field.split('|');actual=None
        for key,value in fields.items():
            if budget is not None:
                budget[0]-=1
                if budget[0]<0:raise _SigmaBudgetExhausted
            if key.casefold()==base.casefold() or key.casefold().endswith('.'+base.casefold()):
                actual=value;break
        values=expected if isinstance(expected,list) else [expected]
        if actual is None:return False
        candidate=str(actual).casefold();ok=False
        for item in values:
            if budget is not None:
                budget[0]-=1
                if budget[0]<0:raise _SigmaBudgetExhausted
            term=str(item).casefold()
            if 'contains' in mods:ok|=term in candidate
            elif 'startswith' in mods:ok|=candidate.startswith(term)
            elif 'endswith' in mods:ok|=candidate.endswith(term)
            else:ok|=fnmatch.fnmatch(candidate,term)
        if not ok:return False
    return True
