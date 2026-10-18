"""Linux auditd parser preserving record type, serial and quoted key/value data."""
import re,shlex
from .generic import event,lines
HEAD=re.compile(r'^type=(?P<type>\S+) msg=audit\((?P<ts>[\d.]+):(?P<serial>\d+)\): ?(?P<body>.*)$')
def parse(data,source,context):
    """Parse audit records and keep undecodable tokens in the raw message."""
    out=[]
    for n,o,text in lines(data):
        match=HEAD.match(text);fields=match.groupdict() if match else {"message":text}
        if match:
            try:tokens=shlex.split(fields.pop('body'))
            except ValueError:tokens=[]
            for token in tokens:
                if '=' in token:
                    key,value=token.split('=',1);fields[key]=value
        out.append(event(source,n,o,text,fields,'auditd',fields.get('ts')))
    return out
