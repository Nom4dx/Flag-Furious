"""Direct and cross-event flag reconstruction with explicit ordering provenance."""
from collections import defaultdict
import re
DEFAULT=['flag','CTF','HTB','picoCTF','BVAULT','SVIUSCG']
def hunt(events:list[dict],decoded:list[dict],context:dict)->tuple[list[dict],list[dict]]:
    """Return candidates and decoys from raw fields, decoded data and grouped fragments."""
    prefixes=context.get('prefixes') or DEFAULT;custom=context.get('patterns') or []
    expressions=[re.compile(r'(?i)(?:'+ '|'.join(re.escape(x) for x in prefixes)+r')\{[^{}\r\n]{1,256}\}')]+[re.compile(x,re.I) for x in custom]
    found=[];decoys=[];seen=set()
    def scan(text,source,events_ids,strategy,chain,confidence,valid_source=True):
        for expression in expressions:
            for match in expression.finditer(text):
                value=match.group();key=(value,tuple(events_ids),strategy)
                if key in seen:continue
                seen.add(key);row={"value":value,"status":"validated" if valid_source and value.endswith('}') else "candidate","source_files":sorted(set(source)),"events":events_ids,"ordering_strategy":strategy,"decoder_chain":chain,"evidence":["prefisso configurato","parentesi bilanciate","provenienza eventi conservata"],"confidence":confidence}
                (found if valid_source else decoys).append(row)
    for event in events:scan(event.get('raw',''),[event['source_file']],[event['event_id']],'single_event',[],.96,event.get('parser') not in {'jsonl_corrupt','xml_corrupt'})
    for row in decoded:scan(row['output_preview'],[row['source_file']],[row['source_event']],'decoded_field',row['decoder_chain'],min(.94,row['confidence']),True)
    strategies=[('timestamp',lambda x:(x.get('timestamp') or '',x['source_file'],x['source_line'])),('line_number',lambda x:(x['source_file'],x['source_line'])),('sequence',lambda x:str(x.get('raw_fields',{}).get('sequence') or x.get('raw_fields',{}).get('seq') or x['source_line']))]
    group_keys=['session_id','request_id','flow_id','source_ip']
    for strategy,keyfn in strategies:
        ordered=sorted(events,key=keyfn);_scan_joined(ordered,strategy,scan)
    for group_key in group_keys:
        groups=defaultdict(list)
        for event in events:
            if event.get(group_key):groups[str(event[group_key])].append(event)
        for key,rows in list(groups.items())[:1000]:_scan_joined(sorted(rows,key=lambda x:(x.get('timestamp') or '',x['source_line'])),f'{group_key}:{key}',scan)
    return found[:500],decoys[:500]
def _scan_joined(rows,strategy,scan):
    if not 1<len(rows)<=5000:return
    fragments=[]
    for row in rows:
        fields=row.get('raw_fields',{});value=next((fields.get(k) for k in ('fragment','part','piece','data','payload','message') if fields.get(k)),None)
        if value is not None:fragments.append((str(value),row))
    if not fragments:return
    variants=[('concatenate',''.join(x for x,_ in fragments)),('remove_delimiters',re.sub(r'[\s,;|]+','',''.join(x for x,_ in fragments))),('even',''.join(x for i,(x,_) in enumerate(fragments) if i%2==0)),('odd',''.join(x for i,(x,_) in enumerate(fragments) if i%2))]
    files=[x['source_file'] for _,x in fragments];ids=[x['event_id'] for _,x in fragments]
    for name,value in variants:
        if len(value)<=2_000_000:scan(value,files,ids,strategy,[name],.88,True)
