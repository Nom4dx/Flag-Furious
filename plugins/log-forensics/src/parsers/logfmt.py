"""Quoted key=value/logfmt parser with conservative tokenization."""
import shlex
from .generic import event,lines
def parse(data,source,context):
    """Parse key=value tokens; unpaired tokens remain in the message field."""
    out=[]
    for n,o,text in lines(data):
        fields={};message=[]
        try:tokens=shlex.split(text,posix=True)
        except ValueError:tokens=text.split();fields['parse_error']='unclosed_quote'
        for token in tokens:
            if '=' in token:
                key,value=token.split('=',1);fields[key]=value
            else:message.append(token)
        if message:fields['message']=' '.join(message)
        ts=next((fields.get(x) for x in ('timestamp','time','ts','@timestamp') if fields.get(x)),None);out.append(event(source,n,o,text,fields,'logfmt',ts))
    return out
