"""ECS-inspired normalization while retaining masked raw and original fields."""
from hashlib import sha1
import json,re
from .timestamp import parse as parse_timestamp
ALIASES={
 'source_ip':['source_ip','src_ip','src','clientip','c-ip','remote_addr','sourceIPAddress','ipAddress'],
 'destination_ip':['destination_ip','dest_ip','dst_ip','dst','d-ip'], 'source_port':['source_port','src_port','sport','id.orig_p'], 'destination_port':['destination_port','dest_port','dst_port','dport','id.resp_p'],
 'user':['user','username','user_name','cs-username','suser','User','userIdentity.userName'],'host':['host','hostname','computer','Computer','_HOSTNAME'],
 'process':['process','app','app-name','process_name','Image','NewProcessName','_COMM'],'process_id':['process_id','pid','proc','ProcessId','_PID'], 'parent_process_id':['parent_process_id','ppid','ParentProcessId'],
 'session_id':['session_id','session','cookie','logon_id','LogonId'],'request_id':['request_id','requestId','trace_id'],'flow_id':['flow_id','uid','flowid'],
 'method':['method','http_method','cs-method','verb'],'uri':['uri','url','request_uri','cs-uri-stem','requestURI'],'status':['status','status_code','sc-status','responseStatus'],
 'bytes':['bytes','bytes_out','sc-bytes','sent_bytes'],'action':['action','eventName','operationName','verb'],'outcome':['outcome','result','status_text']}
SECRET=re.compile(r'(?i)(password|passwd|secret|token|api[_-]?key|cookie|authorization)([=:]\s*)([^\s,;\"]+)')
def flatten(value,prefix='',output=None):
    """Flatten nested dictionaries to dotted paths for alias matching and Sigma."""
    output={} if output is None else output
    if isinstance(value,dict):
        for key,child in value.items():flatten(child,f'{prefix}.{key}' if prefix else str(key),output)
    elif isinstance(value,list):output[prefix]=value
    else:output[prefix]=value
    return output
def mask(value):
    """Mask common secret values in UI-facing strings while preserving structure."""
    return SECRET.sub(lambda m:m.group(1)+m.group(2)+'********',str(value))
def normalize(raw:dict,index:int,context:dict)->dict:
    """Map one parser event to the common model and preserve provenance/confidence."""
    fields=flatten(raw.get('raw_fields',{}));lookup={k.casefold():v for k,v in fields.items()}
    def pick(names):
        for name in names:
            if name in fields:return fields[name]
            if name.casefold() in lookup:return lookup[name.casefold()]
            for key,value in fields.items():
                if key.casefold().endswith('.'+name.casefold()):return value
        return None
    time=parse_timestamp(raw.get('timestamp_raw') or pick(['timestamp','time','@timestamp','eventTime','TimeCreated.@SystemTime']),context.get('timezone','UTC'),context.get('reference_year'))
    normalized={key:pick(names) for key,names in ALIASES.items()};message=pick(['message','msg','short_message','Message']) or raw.get('raw','')
    if not normalized.get('source_ip'):
        match=re.search(r'\bfrom\s+([0-9a-fA-F:.]+)',str(message),re.I)
        if match:normalized['source_ip']=match.group(1)
    if not normalized.get('user'):
        match=re.search(r'\bfor\s+(?:invalid user\s+)?([\w.@-]+)',str(message),re.I)
        if match:normalized['user']=match.group(1)
    event_type=_event_type(raw.get('parser','generic'),normalized,message,fields);action,outcome=_action(normalized,message)
    stable=f"{raw.get('source_file')}:{raw.get('source_line')}:{raw.get('source_offset')}:{index}";event_id='event-'+sha1(stable.encode()).hexdigest()[:16]
    return {"event_id":event_id,"source_file":raw.get('source_file'),"source_line":raw.get('source_line'),"source_offset":raw.get('source_offset'),"raw":mask(raw.get('raw','')),"timestamp":time['timestamp'],"timestamp_raw":time['timestamp_raw'],"timezone":time['timezone'],"timestamp_confidence":time['timestamp_confidence'],"timestamp_error":time.get('error'),**normalized,"event_type":event_type,"action":action,"outcome":outcome,"parser":raw.get('parser','generic'),"message":mask(message),"raw_fields":_masked_fields(fields),"normalized_fields":{"event_type":event_type,"action":action,"outcome":outcome},"confidence":.9 if raw.get('parser') not in {'generic','jsonl_corrupt'} else .62}
def _masked_fields(fields):
    return {key:('********' if re.search(r'(?i)(password|secret|token|api.?key|cookie|authorization)',key) else value) for key,value in fields.items()}
def _event_type(parser,values,message,fields):
    value=' '.join([str(message),str(values.get('action') or '')]).casefold()
    if any(x in value for x in ('login','logon','authentication','sshd','sudo','failed password','accepted password')):return 'authentication'
    if parser in {'apache','nginx_access','iis_w3c'} or values.get('method'):return 'web'
    if parser.startswith(('suricata','zeek','firewall')) or values.get('destination_ip'):return 'network'
    if parser in {'windows_xml','evtx','sysmon'}:return 'windows'
    if parser in {'auditd','journald_export','syslog'}:return 'host'
    if parser in {'aws_cloudtrail','azure_activity','gcp_audit','kubernetes_audit'}:return 'cloud'
    return 'log'
def _action(values,message):
    action=str(values.get('action') or '').casefold();text=str(message).casefold();outcome=values.get('outcome')
    if any(x in text for x in ('failed password','authentication failure','login failed')):return 'login_failed','failure'
    if any(x in text for x in ('accepted password','login successful','logged in')):return 'login_success','success'
    if outcome is None and str(values.get('status','')).isdigit():outcome='success' if int(values['status'])<400 else 'failure'
    return action or None,outcome
