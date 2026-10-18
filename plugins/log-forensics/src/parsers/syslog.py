"""RFC3164/RFC5424 parser with PRI, host, process and structured-data fields."""
import re
from .generic import event,lines
R5424=re.compile(r'^<(?P<pri>\d{1,3})>\d+ (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<proc>\S+) (?P<msgid>\S+) (?P<sd>-|\[.*?\]) ?(?P<msg>.*)$')
R3164=re.compile(r'^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d) (?P<host>\S+) (?P<app>[\w./-]+)(?:\[(?P<proc>\d+)\])?: ?(?P<msg>.*)$')
def parse(data,source,context):
    """Parse both syslog layouts; malformed lines remain generic syslog records."""
    out=[]
    for n,o,text in lines(data):
        match=R5424.match(text) or R3164.match(text);fields=match.groupdict() if match else {"message":text}
        if match and fields.get('pri') is not None:
            pri=int(fields['pri']);fields.update(facility=pri//8,severity=pri%8)
        out.append(event(source,n,o,text,fields,'syslog',fields.get('ts')))
    return out
