"""IIS W3C parser driven by the #Fields declaration."""
from .generic import event,lines
def parse(data,source,context):
    """Parse W3C columns, preserving comments and inconsistent row widths."""
    fields=[];out=[]
    for n,o,text in lines(data,'utf-8-sig'):
        if text.startswith('#Fields:'):fields=text[8:].strip().split();continue
        if text.startswith('#') or not text:continue
        values=text.split();raw=dict(zip(fields,values)) if fields else {f'column_{i}':v for i,v in enumerate(values)}
        ts=' '.join(filter(None,[raw.get('date'),raw.get('time')])) or None
        out.append(event(source,n,o,text,raw,'iis_w3c',ts))
    return out
