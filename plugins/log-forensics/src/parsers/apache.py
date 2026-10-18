"""Apache Common/Combined and compatible reverse-proxy access log parser."""
import re
from .generic import event,lines
ACCESS=re.compile(r'^(?P<source_ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^]]+)\] "(?P<method>\S+) (?P<uri>.*?) (?P<protocol>HTTP/[^\"]+)" (?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?(?P<tail>.*)$')
def parse(data,source,context):
    """Return request fields and retain unmatched lines for mixed logs."""
    out=[]
    for n,o,text in lines(data):
        match=ACCESS.match(text);fields=match.groupdict() if match else {"message":text}
        for key in ('status','bytes'):
            if fields.get(key,'').isdigit():fields[key]=int(fields[key])
        out.append(event(source,n,o,text,fields,'apache',fields.get('ts')))
    return out
