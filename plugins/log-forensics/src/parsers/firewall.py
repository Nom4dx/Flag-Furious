"""Generic firewall/VPN key-value parser with syslog prefix tolerance."""
import re
from .generic import event,lines
PAIR=re.compile(r'([A-Za-z_][\w.-]*)=("[^"]*"|\S+)')
def parse(data,source,context):
    """Extract vendor-neutral source/destination/action/port fields."""
    out=[]
    for n,o,text in lines(data):
        fields={m.group(1):m.group(2).strip('"') for m in PAIR.finditer(text)};fields.setdefault('message',text if not fields else '')
        out.append(event(source,n,o,text,fields,'firewall',fields.get('time') or fields.get('timestamp')))
    return out
