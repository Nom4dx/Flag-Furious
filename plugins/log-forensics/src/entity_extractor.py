"""Offline entity extraction with event-level provenance and no reputation lookup."""
import ipaddress,re
PATTERNS={
 'url':re.compile(r'https?://[^\s\"\'<>]+',re.I),'email':re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',re.I),
 'domain':re.compile(r'(?<![@\w-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b'),'uuid':re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',re.I),
 'hash':re.compile(r'\b(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b',re.I),'mac':re.compile(r'\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',re.I),
 'file_path':re.compile(r'(?:[A-Za-z]:\\[^\s\"<>]+|/(?:etc|var|tmp|home|usr|opt)/[^\s\"<>]+)')}
IP=re.compile(r'(?<![\w.:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})(?![\w.:])')
def extract(event:dict,max_results:int=5_000,return_truncated:bool=False):
    """Extract typed entities from raw text and normalized fields with offsets."""
    maximum=max(1,int(max_results));text=event.get('raw','');rows=[];seen=set()
    def append(row):
        rows.append(row)
        return len(rows)>=maximum
    for match in IP.finditer(text):
        try:value=str(ipaddress.ip_address(match.group()));key=('ip',value)
        except ValueError:continue
        if key not in seen:
            seen.add(key)
            if append(_row(event,'ip',value,match.start(),.98)):
                return (rows,True) if return_truncated else rows
    for kind,pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            key=(kind,match.group())
            if key in seen:continue
            seen.add(key)
            if append(_row(event,kind,match.group(),match.start(),.9)):
                return (rows,True) if return_truncated else rows
    for kind,key in [('user','user'),('host','host'),('process','process'),('session','session_id'),('request','request_id'),('flow','flow_id')]:
        value=event.get(key)
        if value is not None and (kind,str(value)) not in seen:
            seen.add((kind,str(value)))
            if append(_row(event,kind,str(value),None,.97)):
                return (rows,True) if return_truncated else rows
    return (rows,False) if return_truncated else rows

def _row(event,kind,value,relative,confidence):
    return {"value":value,"type":kind,"event_id":event['event_id'],"source_file":event['source_file'],"source_line":event['source_line'],"offset":event['source_offset']+(relative or 0),"timestamp":event.get('timestamp'),"confidence":confidence}
