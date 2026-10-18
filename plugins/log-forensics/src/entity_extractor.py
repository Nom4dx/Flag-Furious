"""Offline entity extraction with event-level provenance and no reputation lookup."""
import ipaddress,re
PATTERNS={
 'url':re.compile(r'https?://[^\s\"\'<>]+',re.I),'email':re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',re.I),
 'domain':re.compile(r'(?<![@\w-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b'),'uuid':re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',re.I),
 'hash':re.compile(r'\b(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b',re.I),'mac':re.compile(r'\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',re.I),
 'file_path':re.compile(r'(?:[A-Za-z]:\\[^\s\"<>]+|/(?:etc|var|tmp|home|usr|opt)/[^\s\"<>]+)')}
IP=re.compile(r'(?<![\w.:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})(?![\w.:])')
def extract(event:dict)->list[dict]:
    """Extract typed entities from raw text and normalized fields with offsets."""
    text=event.get('raw','');rows=[];seen=set()
    for match in IP.finditer(text):
        try:value=str(ipaddress.ip_address(match.group()));key=('ip',value)
        except ValueError:continue
        if key not in seen:seen.add(key);rows.append(_row(event,'ip',value,match.start(),.98))
    for kind,pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            key=(kind,match.group())
            if key in seen:continue
            seen.add(key);rows.append(_row(event,kind,match.group(),match.start(),.9))
    for kind,key in [('user','user'),('host','host'),('process','process'),('session','session_id'),('request','request_id'),('flow','flow_id')]:
        value=event.get(key)
        if value is not None and (kind,str(value)) not in seen:rows.append(_row(event,kind,str(value),None,.97))
    return rows

def _row(event,kind,value,relative,confidence):
    return {"value":value,"type":kind,"event_id":event['event_id'],"source_file":event['source_file'],"source_line":event['source_line'],"offset":event['source_offset']+(relative or 0),"timestamp":event.get('timestamp'),"confidence":confidence}
