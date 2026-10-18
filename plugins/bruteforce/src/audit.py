"""Redacted audit event helpers."""
from datetime import datetime,timezone
def event(action,**data):
    """Build one UTC audit record; fields named password are removed."""
    return {'timestamp':datetime.now(timezone.utc).isoformat(),'action':action,**{k:v for k,v in data.items() if 'password' not in k.lower()}}
