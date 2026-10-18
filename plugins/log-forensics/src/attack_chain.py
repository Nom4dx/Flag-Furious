"""Attack-chain assembly from correlated detections and ordered event stages."""
STAGES={'brute_force':'initial_access','password_spraying':'initial_access','success_after_failures':'initial_access','sql_injection':'initial_access','path_traversal':'discovery','powershell_encoded_command':'execution','lolbin_execution':'execution','linux_reverse_shell':'command_and_control','periodic_beaconing':'command_and_control','dns_tunneling':'exfiltration','log_clearing':'defense_evasion','cron_persistence':'persistence','cloud_privilege_change':'privilege_escalation','kubernetes_exec':'execution'}
def build(findings:list[dict],events:list[dict])->list[dict]:
    """Group detected stages connected by a shared user, host, IP or session."""
    by_id={x['event_id']:x for x in events};rows=[]
    for finding in findings:
        stage=STAGES.get(finding['type'])
        if stage:rows.append((stage,finding,[by_id[x] for x in finding.get('matched_events',[]) if x in by_id]))
    if not rows:return []
    stages=[]
    for stage,finding,matches in rows:stages.append({"stage":stage,"finding":finding['finding_id'],"events":[x['event_id'] for x in matches],"entities":sorted({str(x.get(k)) for x in matches for k in ('source_ip','user','host') if x.get(k)})})
    return [{"chain_id":"chain-1","attack_stage":stages,"confidence":round(min(.96,sum(x[1]['confidence'] for x in rows)/len(rows)),3),"evidence":"Fasi aggregate da detection locali; la relazione causale richiede revisione"}]
