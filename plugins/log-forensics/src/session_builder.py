"""Session reconstruction from explicit IDs and stable entity tuples."""
from collections import defaultdict
from datetime import datetime
def build(events:list[dict],gap_seconds:int=1800,return_meta:bool=False):
    """Group HTTP, SSH, DNS, cloud and flow events with a bounded inactivity gap."""
    groups=defaultdict(list)
    for item in events:
        key=str(item.get('flow_id') or item.get('request_id') or item.get('session_id') or '|'.join(str(item.get(x) or '') for x in ('source_ip','destination_ip','user','host','event_type')))
        if key.strip('|'):groups[key].append(item)
    sessions=[]
    for key,rows in groups.items():
        rows.sort(key=lambda x:(x.get('timestamp') or '',x['source_file'],x['source_line']));chunk=[];previous=None
        for row in rows:
            current=_dt(row.get('timestamp'))
            if chunk and previous and current and (current-previous).total_seconds()>gap_seconds:sessions.append(_session(key,chunk));chunk=[]
            chunk.append(row);previous=current or previous
        if chunk:sessions.append(_session(key,chunk))
    meta={"total_sessions":len(sessions),"returned_sessions":min(len(sessions),10000),"truncated":len(sessions)>10000}
    return (sessions[:10000],meta) if return_meta else sessions[:10000]
def _dt(value):
    try:return datetime.fromisoformat(value.replace('Z','+00:00')) if value else None
    except ValueError:return None
def _session(key,rows):
    timestamps=[x['timestamp'] for x in rows if x.get('timestamp')];total=sum(int(x.get('bytes') or 0) for x in rows if str(x.get('bytes') or '').isdigit())
    return {"session_id":"session-"+__import__('hashlib').sha1(key.encode()).hexdigest()[:14],"correlation_key":key,"start":min(timestamps) if timestamps else None,"end":max(timestamps) if timestamps else None,"events":[x['event_id'] for x in rows],"event_count":len(rows),"source_ip":rows[0].get('source_ip'),"destination_ip":rows[0].get('destination_ip'),"user":rows[0].get('user'),"host":rows[0].get('host'),"bytes":total,"errors":sum(x.get('outcome')=='failure' for x in rows),"confidence":.97 if any(x.get('flow_id') or x.get('request_id') or x.get('session_id') for x in rows) else .7}
