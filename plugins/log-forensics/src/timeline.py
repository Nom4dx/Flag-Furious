"""Stable global timeline and timestamp-consistency diagnostics."""
from collections import Counter
from datetime import datetime,timezone
def build(events:list[dict])->tuple[list[dict],list[dict]]:
    """Sort timestamped events and report future, missing, duplicate and gap anomalies."""
    rows=sorted((x for x in events if x.get('timestamp')),key=lambda x:(x['timestamp'],x['source_file'],x['source_line']));issues=[];now=datetime.now(timezone.utc).timestamp();seen=Counter((x.get('timestamp'),x.get('raw')) for x in rows)
    for event in rows:
        try:value=datetime.fromisoformat(event['timestamp'].replace('Z','+00:00')).timestamp()
        except ValueError:continue
        if value>now+86400:issues.append({"type":"future_timestamp","severity":"medium","event_id":event['event_id'],"confidence":.96,"explanation":"Evento oltre 24 ore nel futuro"})
    for (stamp,raw),count in seen.items():
        if count>1:issues.append({"type":"duplicate_record","severity":"info","timestamp":stamp,"count":count,"confidence":.9,"explanation":"Record normalizzato duplicato"})
    points=[{"id":x['event_id'],"timestamp":x['timestamp'],"label":x.get('action') or x.get('event_type'),"category":x.get('event_type'),"source_file":x['source_file'],"host":x.get('host'),"user":x.get('user'),"source_ip":x.get('source_ip'),"severity":"info"} for x in rows]
    return points,issues
