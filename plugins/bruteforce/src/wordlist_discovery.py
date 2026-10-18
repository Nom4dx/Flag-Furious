"""Portable wordlist root discovery without mandatory absolute paths."""
import os,json
from pathlib import Path
def roots(project:Path,user_paths=None,persistent=None):
    """Resolve user, environment, config and project-relative roots in priority order."""
    values=[]
    for p,s in [*((x,'ui_selected') for x in user_paths or []),(os.getenv('FORENSIC_HUB_WORDLIST_ROOT'),'environment'),*((x,'persistent_config') for x in persistent or []),(project/'wordlists','project_relative'),(project/'SecLists','project_relative'),(project/'data/wordlists','project_relative')]:
        if not p:continue
        q=Path(p).expanduser().resolve(); key=str(q)
        if key not in {x['path'] for x in values}:values.append({'path':key,'source':s,'exists':q.is_dir()})
    return values
