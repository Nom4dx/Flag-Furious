"""Safe local Sigma subset evaluator over normalized ECS-like events.

Rules are YAML data only. Selection dictionaries, lists, contains, startswith and
endswith modifiers are supported; no generated query or shell is executed.
"""
from pathlib import Path
import fnmatch

def load_and_match(events:list[dict],roots:list[Path])->tuple[list[dict],list[str]]:
    """Validate and evaluate local Sigma files, returning provenance and warnings."""
    try:import yaml
    except ImportError:return [],['PyYAML non disponibile: Sigma saltato']
    matches=[];warnings=[]
    for root in roots:
        if not root.exists():continue
        for path in sorted(root.rglob('*.y*ml'))[:1000]:
            try:
                rule=yaml.safe_load(path.read_text());detection=rule.get('detection',{});selections={k:v for k,v in detection.items() if k not in {'condition','timeframe'}}
                if not rule.get('title') or not selections:raise ValueError('detection assente')
                matched=[event for event in events if any(_selection(event,value) for value in selections.values())]
                if matched:matches.append({"rule_id":str(rule.get('id') or path.stem),"rule_title":rule['title'],"rule_level":rule.get('level','medium'),"tags":rule.get('tags',[]),"matched_events":[x['event_id'] for x in matched[:1000]],"fields":selections,"confidence":.9 if len(matched)>1 else .76,"rule_source":str(path.relative_to(root.parent)),"false_positives":rule.get('falsepositives',[]),"references":rule.get('references',[])})
            except Exception as exc:warnings.append(f'Sigma {path.name}: {exc}')
    return matches,warnings
def _selection(event,value):
    if isinstance(value,list):return any(_selection(event,x) for x in value)
    if not isinstance(value,dict):return False
    fields={**event,**event.get('raw_fields',{})}
    for field,expected in value.items():
        base,*mods=field.split('|');actual=next((v for k,v in fields.items() if k.casefold()==base.casefold() or k.casefold().endswith('.'+base.casefold())),None)
        values=expected if isinstance(expected,list) else [expected]
        if actual is None:return False
        candidate=str(actual).casefold();ok=False
        for item in values:
            term=str(item).casefold()
            if 'contains' in mods:ok|=term in candidate
            elif 'startswith' in mods:ok|=candidate.startswith(term)
            elif 'endswith' in mods:ok|=candidate.endswith(term)
            else:ok|=fnmatch.fnmatch(candidate,term)
        if not ok:return False
    return True
