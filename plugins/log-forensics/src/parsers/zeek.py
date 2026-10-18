"""Zeek ASCII TSV and Zeek JSON parser with #fields schema support."""
from .generic import event,lines
from .jsonl import parse as parse_json
def parse(data,source,context):
    """Parse Zeek JSON or the self-describing tab-separated ASCII format."""
    stripped=data.lstrip()
    if stripped.startswith((b'{',b'[')):return [{**x,"parser":"zeek_json"} for x in parse_json(data,source,context)]
    fields=[];separator='\t';out=[]
    for n,o,text in lines(data):
        if text.startswith('#separator'):
            token=text.split(None,1)[-1];separator=bytes(token,'utf-8').decode('unicode_escape');continue
        if text.startswith('#fields'):fields=text.split(separator)[1:];continue
        if text.startswith('#') or not text:continue
        values=text.split(separator);raw=dict(zip(fields,values)) if fields else {f'column_{i}':v for i,v in enumerate(values)}
        out.append(event(source,n,o,text,raw,'zeek_tsv',raw.get('ts')))
    return out
