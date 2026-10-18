"""Context-aware built-in detections for authentication, web, host, cloud and network."""
from collections import defaultdict
from datetime import datetime
import math,re
WEB={
 'sql_injection':re.compile(r"(?i)(?:union(?:%20|\s)+select|select(?:%20|\s).+from|sleep\(|or(?:%20|\s)+1=1)"),
 'path_traversal':re.compile(r'(?i)(?:\.\./|\.\.\\|%2e%2e|%252e)'),
 'command_injection':re.compile(r'(?i)(?:;|\||%3b)(?:\s|%20)*(?:cat|id|whoami|curl|wget|bash|sh)\b'),
 'xss':re.compile(r'(?i)(?:<script|%3cscript|javascript:)'),
 'sensitive_path':re.compile(r'(?i)(?:/etc/passwd|/\.env|/\.git|/wp-admin|webshell|\.php\?)')}
HOST={
 'powershell_encoded_command':re.compile(r'(?i)powershell(?:\.exe)?.{0,120}(?:-enc|-encodedcommand)'),
 'lolbin_execution':re.compile(r'(?i)\b(?:rundll32|regsvr32|mshta|certutil|bitsadmin|schtasks)(?:\.exe)?\b'),
 'linux_reverse_shell':re.compile(r'(?i)(?:/dev/tcp/|nc\s+.*-[elp]|bash\s+-i)'),
 'log_clearing':re.compile(r'(?i)(?:wevtutil\s+cl|Clear-EventLog|rm\s+.*(?:auth\.log|syslog)|truncate\s+.*log)'),
 'cron_persistence':re.compile(r'(?i)(?:crontab\s+-e|/etc/cron\.|systemctl\s+enable)'),
 'service_created':re.compile(r'(?i)(?:\bsc(?:\.exe)?\s+create\b|eventid[=: ]+7045|a service was installed)'),
 'security_control_disabled':re.compile(r'(?i)(?:Set-MpPreference.+DisableRealtimeMonitoring|disable.*defender|auditctl\s+-e\s+0)'),
 'suspicious_download':re.compile(r'(?i)\b(?:curl|wget|certutil|bitsadmin)\b.{0,160}(?:https?://|ftp://)'),
 'temporary_path_execution':re.compile(r'(?i)(?:/tmp/|\\Temp\\).{0,120}(?:\.exe|\bsh\b|\bbash\b|powershell)')}
def detect(events:list[dict],options:dict)->list[dict]:
    """Apply individual and correlated rules; a lone keyword stays an indicator."""
    findings=[]
    for event in events:
        text=' '.join(str(event.get(x) or '') for x in ('raw','message','uri','process','action'))
        for kind,pattern in WEB.items():
            if pattern.search(text):findings.append(_finding(kind,'high' if kind in {'sql_injection','command_injection'} else 'medium',.88,[event],['request payload matched contextual web rule']))
        for kind,pattern in HOST.items():
            if pattern.search(text):findings.append(_finding(kind,'high' if kind in {'log_clearing','linux_reverse_shell'} else 'medium',.86,[event],['command/process context matched local rule']))
        action=str(event.get('action') or '').casefold()
        if event.get('parser')=='kubernetes_audit' and ('pods/exec' in text or action=='create' and '/exec' in text):findings.append(_finding('kubernetes_exec','high',.91,[event],['Kubernetes exec API request']))
        if event.get('parser')=='aws_cloudtrail' and any(x in action.casefold() for x in ('attachuserpolicy','putuserpolicy','createaccesskey')):findings.append(_finding('cloud_privilege_change','high',.88,[event],['privilege/access-key operation']))
    findings.extend(_authentication(events,options));findings.extend(_web_aggregate(events,options));findings.extend(_network(events,options))
    return _dedupe(findings)
def _authentication(events,options):
    groups=defaultdict(list)
    for event in events:
        if event.get('action') in {'login_failed','login_success'}:groups[(event.get('source_ip'),event.get('user'))].append(event)
    output=[];threshold=int(options.get('auth_failure_threshold',5))
    by_ip_users=defaultdict(set)
    for (ip,user),rows in groups.items():
        failures=[x for x in rows if x['action']=='login_failed'];success=[x for x in rows if x['action']=='login_success']
        if ip and user and failures:by_ip_users[ip].add(user)
        if len(failures)>=threshold:output.append(_finding('brute_force','high',min(.98,.72+len(failures)*.03),rows,[f'{len(failures)} fallimenti per stessa coppia IP/utente']))
        if len(failures)>=threshold and success:output.append(_finding('success_after_failures','high',.96,rows,[f'{len(failures)} fallimenti seguiti da successo']))
    for ip,users in by_ip_users.items():
        if len(users)>=int(options.get('spray_user_threshold',5)):
            rows=[x for x in events if x.get('source_ip')==ip and x.get('action')=='login_failed'];output.append(_finding('password_spraying','high',.91,rows,[f'{len(users)} utenti distinti dallo stesso IP']))
    return output
def _network(events,options):
    ports=defaultdict(set);dns=defaultdict(list);connections=defaultdict(list)
    for event in events:
        ip=event.get('source_ip');dest=event.get('destination_ip');port=event.get('destination_port')
        if ip and dest and port:ports[(ip,dest)].add(str(port))
        query=event.get('raw_fields',{}).get('dns.rrname') or event.get('raw_fields',{}).get('query')
        if query:dns[ip].append((str(query),event))
        if ip and dest and event.get('timestamp'):connections[(ip,dest)].append(event)
    output=[]
    for key,values in ports.items():
        if len(values)>=int(options.get('scan_port_threshold',10)):output.append(_finding('port_scan','medium',.9,[x for x in events if (x.get('source_ip'),x.get('destination_ip'))==key],[f'{len(values)} porte distinte']))
    for ip,rows in dns.items():
        suspicious=[(q,e) for q,e in rows if max((len(x) for x in q.split('.')),default=0)>40 or _entropy(q.split('.')[0])>4.2]
        if len(suspicious)>=3:output.append(_finding('dns_tunneling','medium',.78,[e for _,e in suspicious],[f'{len(suspicious)} query con label lunghe/ad alta entropia']))
    for key,rows in connections.items():
        intervals=_intervals(rows)
        if len(intervals)>=4 and _cv(intervals)<.2:output.append(_finding('periodic_beaconing','medium',.76,rows,[f'intervalli periodici CV={_cv(intervals):.2f}']))
        transferred=sum(int(x.get('bytes') or 0) for x in rows if str(x.get('bytes') or '').isdigit())
        if transferred>=int(options.get('exfiltration_bytes_threshold',10*1024*1024)):
            output.append(_finding('possible_exfiltration','medium',.74,rows,[f'{transferred} byte verso la stessa destinazione; verificare baseline e direzione']))
    return output
def _web_aggregate(events,options):
    groups=defaultdict(list)
    for event in events:
        if event.get('event_type')=='web' and event.get('source_ip'):groups[event['source_ip']].append(event)
    output=[]
    for ip,rows in groups.items():
        errors=[x for x in rows if str(x.get('status')) in {'401','403','404'}]
        paths={str(x.get('uri')) for x in rows if x.get('uri')}
        if len(errors)>=int(options.get('web_error_threshold',10)) and len(paths)>=5:
            output.append(_finding('web_enumeration','medium',.84,rows,[f'{len(errors)} risposte 401/403/404 su {len(paths)} percorsi']))
    return output
def _intervals(rows):
    values=[]
    for row in sorted(rows,key=lambda x:x['timestamp']):
        try:values.append(datetime.fromisoformat(row['timestamp'].replace('Z','+00:00')).timestamp())
        except ValueError:pass
    return [b-a for a,b in zip(values,values[1:]) if b>a]
def _cv(values):
    if not values:return 99
    mean=sum(values)/len(values);return (sum((x-mean)**2 for x in values)/len(values))**.5/mean if mean else 99
def _entropy(value):
    if not value:return 0
    from collections import Counter
    return -sum((n/len(value))*math.log2(n/len(value)) for n in Counter(value).values())
def _finding(kind,severity,confidence,events,evidence):
    return {"finding_id":"finding-"+__import__('hashlib').sha1((kind+':'+':'.join(x['event_id'] for x in events[:20])).encode()).hexdigest()[:14],"type":kind,"severity":severity,"confidence":round(confidence,3),"matched_events":[x['event_id'] for x in events[:1000]],"source_files":sorted({x['source_file'] for x in events}),"evidence":evidence,"explanation":evidence[0],"classification":"detection"}
def _dedupe(rows):return list({(x['type'],tuple(x['matched_events'])):x for x in rows}.values())
