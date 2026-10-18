"""JSON, JSON array and NDJSON parser retaining JSON pointers and corrupt lines."""
import json
from .generic import event,lines
TIME_KEYS=('timestamp','@timestamp','time','datetime','eventTime','event_time','ts')
def _events(value):
    if isinstance(value,list):return value
    if isinstance(value,dict):
        for key in ('Records','records','events','items'):
            if isinstance(value.get(key),list):return value[key]
        return [value]
    return [{"value":value}]
def parse(data,source,context):
    """Parse a document first, then fall back to independently recoverable lines."""
    text=data.decode(context.get('encoding','utf-8-sig'),'replace');out=[]
    try:
        values=_events(json.loads(text));positions=[(1,0,x) for x in values]
    except json.JSONDecodeError:
        positions=[]
        for n,o,line in lines(data,'utf-8-sig'):
            if not line.strip():continue
            try:positions.append((n,o,json.loads(line)))
            except json.JSONDecodeError:out.append(event(source,n,o,line,{"parse_error":"invalid_json_line"},'jsonl_corrupt'))
    for n,o,value in positions:
        fields=value if isinstance(value,dict) else {"value":value};ts=next((fields.get(k) for k in TIME_KEYS if fields.get(k) is not None),None)
        out.append(event(source,n,o,json.dumps(value,ensure_ascii=False),fields,'jsonl',ts)|{"json_pointer":f'/{n-1}'})
    return sorted(out,key=lambda x:(x['source_line'],x['source_offset']))
