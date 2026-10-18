"""systemd journal export parser for blank-line-separated FIELD=value records."""
from .generic import event,lines
def parse(data,source,context):
    """Parse journal export text including trusted underscore fields."""
    out=[];fields={};raw=[];start_line=1;start_offset=0
    for n,o,text in lines(data):
        if not text:
            if fields:out.append(event(source,start_line,start_offset,'\n'.join(raw),fields,'journald_export',fields.get('__REALTIME_TIMESTAMP')));fields={};raw=[]
            start_line=n+1;start_offset=o;continue
        raw.append(text)
        if '=' in text:
            key,value=text.split('=',1);fields[key]=value
    if fields:out.append(event(source,start_line,start_offset,'\n'.join(raw),fields,'journald_export',fields.get('__REALTIME_TIMESTAMP')))
    return out
