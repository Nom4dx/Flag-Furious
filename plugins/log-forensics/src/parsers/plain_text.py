"""Plain timestamped and application text log parser."""
import re
from .generic import event,lines
STAMP=re.compile(r'^(\d{4}-\d\d-\d\d[T ][^ ]+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(.*)$')
def parse(data,source,context):
    """Split lines and isolate a leading timestamp when available."""
    out=[]
    for n,o,text in lines(data,context.get('encoding','utf-8')):
        if not text:continue
        match=STAMP.match(text);out.append(event(source,n,o,text,{"message":match.group(2) if match else text},'plain_text',match.group(1) if match else None))
    return out
