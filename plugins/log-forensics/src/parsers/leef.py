"""LEEF 1/2 parser supporting tab or declared extension delimiters."""
from .generic import event,lines
def parse(data,source,context):
    """Split LEEF header and key/value extension without executing escapes."""
    out=[]
    for n,o,text in lines(data):
        parts=text.split('|',5);fields={}
        if len(parts)>=5 and parts[0].startswith('LEEF:'):
            fields.update(zip(('leef_version','vendor','product','product_version','event_id'),parts[:5]));extension=parts[5] if len(parts)>5 else ''
            delimiter='\t'
            if parts[0].startswith('LEEF:2') and extension[:2].startswith('0x'):
                try:delimiter=chr(int(extension[:4],16));extension=extension[4:]
                except ValueError:pass
            for item in extension.split(delimiter):
                if '=' in item:
                    key,value=item.split('=',1);fields[key.strip()]=value
        else:fields={'message':text,'parse_error':'invalid_leef_header'}
        out.append(event(source,n,o,text,fields,'leef',fields.get('devTime')))
    return out
