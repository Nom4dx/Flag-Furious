"""Central parser dispatch; plugins never select parsers in frontend code."""
from importlib import import_module
MAPPING={
 'plain_text':'plain_text','syslog':'syslog','apache':'apache','nginx':'nginx','iis_w3c':'iis','jsonl':'jsonl','csv_tsv':'csv_tsv','cef':'cef','leef':'leef','gelf':'gelf','logfmt':'logfmt','xml':'xml_logs','windows_xml':'windows_xml','sysmon':'sysmon','journald_export':'journald','auditd':'auditd','zeek_tsv':'zeek','zeek_json':'zeek','suricata_eve_json':'suricata','firewall':'firewall','cloudtrail':'cloudtrail','azure_activity':'azure_activity','gcp_audit':'gcp_audit','kubernetes_audit':'kubernetes_audit'}
def parse(format_name,data,source,context,path=None):
    """Run the selected bounded parser and return events plus recoverable warnings."""
    if format_name in {'evtx','evt'}:
        module=import_module('.parsers.'+format_name,__package__);return module.parse_path(path,source,context)
    if format_name in {'gzip','bzip2','xz','zip','journald_binary'}:return [],[f'{format_name} richiede estrazione o adapter dedicato']
    module=import_module('.parsers.'+MAPPING.get(format_name,'generic'),__package__)
    try:return module.parse(data,source,context),[]
    except Exception as exc:
        generic=import_module('.parsers.generic',__package__);return generic.parse(data,source,context),[f'Parser {format_name} parziale: {exc}; fallback generico']
