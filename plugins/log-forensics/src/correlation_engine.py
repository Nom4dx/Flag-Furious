"""Cross-source event correlation using explicit IDs and shared entities."""
from collections import defaultdict
def correlate(events:list[dict],sessions:list[dict],findings:list[dict])->list[dict]:
    """Build explainable event links without inferring causality from proximity alone."""
    links=[];seen=set();indexes=defaultdict(list)
    for event in events:
        for field in ('session_id','request_id','flow_id','source_ip','destination_ip','user','host','process_id'):
            if event.get(field):indexes[(field,str(event[field]))].append(event)
    for (field,value),rows in indexes.items():
        if len(rows)<2:continue
        ordered=sorted(rows,key=lambda x:(x.get('timestamp') or '',x['source_file'],x['source_line']))
        for left,right in zip(ordered,ordered[1:]):
            key=(left['event_id'],right['event_id'],field)
            if key in seen:continue
            seen.add(key);links.append({"source":left['event_id'],"target":right['event_id'],"relation":"same_"+field,"value":value,"confidence":.98 if field in {'session_id','request_id','flow_id'} else .72})
            if len(links)>=20000:return links
    return links
