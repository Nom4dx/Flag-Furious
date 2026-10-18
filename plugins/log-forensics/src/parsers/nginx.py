"""Nginx access/error parser; access syntax reuses the compatible Apache grammar."""
import re
from .apache import parse as parse_access
from .generic import event,lines
ERROR=re.compile(r'^(?P<ts>\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+): (?:\*(?P<connection>\d+) )?(?P<message>.*)$')
def parse(data,source,context):
    """Choose Nginx error grammar when present, otherwise parse access records."""
    decoded=data[:4096].decode('utf-8','replace')
    if not ERROR.search(decoded):return [{**x,"parser":"nginx_access"} for x in parse_access(data,source,context)]
    out=[]
    for n,o,text in lines(data):
        match=ERROR.match(text);fields=match.groupdict() if match else {"message":text};out.append(event(source,n,o,text,fields,'nginx_error',fields.get('ts')))
    return out
