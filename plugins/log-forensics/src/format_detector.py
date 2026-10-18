"""Content-first log format scoring from bounded samples.

Extension is weak evidence. Structural markers, parseability and field schemas
carry the score. Multiple candidates remain visible for mixed/concatenated logs.
"""
from pathlib import Path
import csv,io,json,re

def detect(data:bytes,name:str='',mime:str='') -> list[dict]:
    """Return ranked format candidates with independent reasons and confidence."""
    extension=Path(name).suffix.casefold();text=data[:1024*1024].decode('utf-8','replace');lines=[x for x in text.splitlines() if x.strip()][:100]
    scores={}
    def add(fmt,value,reason):
        row=scores.setdefault(fmt,{"detected_format":fmt,"score":0.0,"reasons":[]});row['score']+=value;row['reasons'].append(reason)
    if data.startswith(b'ElfFile\x00'):add('evtx',.98,'Header binario EVTX ElfFile')
    if data.startswith(b'LPKSHHRH'):add('journald_binary',.98,'Header journal systemd')
    if data.startswith(b'\x1f\x8b\x08'):add('gzip',.99,'Magic gzip')
    if data.startswith(b'PK\x03\x04'):add('zip',.99,'Magic ZIP')
    if data.startswith(b'BZh'):add('bzip2',.99,'Magic bzip2')
    if data.startswith(b'\xfd7zXZ\x00'):add('xz',.99,'Magic xz')
    if any(x.startswith('#Fields:') for x in lines):add('iis_w3c',.95,'Header W3C #Fields')
    if any(x.startswith('#separator') or x.startswith('#fields') for x in lines):add('zeek_tsv',.96,'Header Zeek TSV')
    if any(re.match(r'^<\d{1,3}>\d+ \S+ \S+',x) for x in lines):add('syslog',.94,'Struttura RFC5424')
    elif any(re.match(r'^(?:<\d+>)?[A-Z][a-z]{2}\s+\d+ \d\d:',x) for x in lines):add('syslog',.86,'Struttura RFC3164')
    if any('CEF:' in x for x in lines):add('cef',.97,'Header CEF')
    if any(x.startswith('LEEF:') for x in lines):add('leef',.97,'Header LEEF')
    if any(re.match(r'^\S+ \S+ \S+ \[[^]]+\] "\S+ .* HTTP/',x) for x in lines):add('apache',.94,'Access log Common/Combined')
    if any(re.match(r'^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[\w+\]',x) for x in lines):add('nginx',.94,'Nginx error log')
    if any(x.startswith('type=') and 'msg=audit(' in x for x in lines):add('auditd',.97,'Record auditd')
    if '__REALTIME_TIMESTAMP=' in text and '\n\n' in text:add('journald_export',.95,'Campi journal export')
    json_values=[];valid=0
    for x in lines:
        try:json_values.append(json.loads(x));valid+=1
        except json.JSONDecodeError:pass
    if text.lstrip().startswith(('{','[')):
        try:
            root=json.loads(text);json_values=(root if isinstance(root,list) else root.get('Records',[root]) if isinstance(root,dict) else [root]);add('jsonl',.75,'Documento JSON valido')
        except json.JSONDecodeError:pass
    if valid and valid/max(1,len(lines))>.6:add('jsonl',.75,'Maggioranza righe JSON valida')
    objects=[x for x in json_values if isinstance(x,dict)]
    keys=set().union(*(x.keys() for x in objects[:50])) if objects else set()
    if {'event_type','flow_id'}<=keys:add('suricata_eve_json',.98,'event_type e flow_id Suricata')
    if {'ts','uid'}<=keys:add('zeek_json',.96,'Campi ts e uid Zeek')
    if 'eventSource' in keys or any(isinstance(x,dict) and 'Records' in x for x in objects):add('cloudtrail',.9,'Schema CloudTrail')
    if {'verb','objectRef'}<=keys:add('kubernetes_audit',.96,'Schema Kubernetes audit')
    if 'protoPayload' in keys:add('gcp_audit',.95,'Schema GCP Audit')
    if 'operationName' in keys or 'category' in keys and 'resourceId' in keys:add('azure_activity',.9,'Schema Azure Activity')
    if {'version','host','short_message'}<=keys:add('gelf',.98,'Campi GELF')
    if '<Event' in text and ('EventID' in text or 'TimeCreated' in text):add('windows_xml',.96,'Struttura Windows Event XML')
    elif text.lstrip().startswith('<'):add('xml',.72,'Documento XML candidato')
    if lines and sum('=' in x for x in lines)/len(lines)>.6:add('logfmt',.65,'Righe key=value')
    try:
        dialect=csv.Sniffer().sniff('\n'.join(lines[:20]),delimiters=',\t|;')
        if lines and all(len(next(csv.reader([x],dialect)))>1 for x in lines[:min(5,len(lines))]):add('csv_tsv',.7,f'Delimitatore {repr(dialect.delimiter)} coerente')
    except (csv.Error,StopIteration):pass
    if extension in {'.log','.out','.txt','.1','.2','.old'}:add('plain_text',.18,'Estensione log come indizio')
    elif extension in {'.json','.jsonl','.ndjson'}:add('jsonl',.18,'Estensione JSON come indizio')
    elif extension in {'.csv','.tsv'}:add('csv_tsv',.18,'Estensione tabellare come indizio')
    elif extension=='.evtx':add('evtx',.18,'Estensione EVTX come indizio')
    if not scores:add('plain_text',.4,'Fallback testuale generico')
    return sorted(({**x,"score":round(min(.99,x['score']),3),"confidence":round(min(.99,x['score']),3),"declared_extension":extension,"mime_type":mime} for x in scores.values()),key=lambda x:-x['score'])
