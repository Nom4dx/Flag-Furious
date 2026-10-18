"""Common Event Format parser with escaped header/extension handling."""
import re,shlex
from .generic import event,lines
def parse(data,source,context):
    """Parse seven CEF header fields and extension key/value pairs."""
    out=[]
    for n,o,text in lines(data):
        start=text.find('CEF:');body=text[start:] if start>=0 else text;parts=re.split(r'(?<!\\)\|',body,maxsplit=7);fields={}
        if len(parts)>=7:
            fields.update(zip(('cef_version','device_vendor','device_product','device_version','signature_id','name','severity'),[x.replace('\\|','|') for x in parts[:7]]));extension=parts[7] if len(parts)>7 else ''
            for match in re.finditer(r'(?P<key>[\w.]+)=(?P<value>.*?)(?=\s+[\w.]+=|$)',extension):fields[match.group('key')]=match.group('value').replace('\\=','=')
        else:fields={'message':text,'parse_error':'invalid_cef_header'}
        out.append(event(source,n,o,text,fields,'cef',fields.get('rt') or fields.get('start')))
    return out
