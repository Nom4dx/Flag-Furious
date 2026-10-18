"""Bounded recursive decoder pipeline for payload-like log fields."""
import base64,binascii,codecs,gzip,re,zlib
from urllib.parse import unquote_to_bytes
TOKENS=re.compile(r'(?<![A-Za-z0-9])(?:[A-Za-z0-9+/]{12,}={0,2}|(?:[0-9a-fA-F]{2}){8,}|(?:%[0-9a-fA-F]{2}){4,})(?![A-Za-z0-9])')
def decode_events(events:list[dict],max_attempts:int=2000,max_depth:int=3)->list[dict]:
    """Decode plausible tokens recursively, retaining chain and source event."""
    out=[];seen=set();attempts=0
    for event in events:
        for match in TOKENS.finditer(event.get('raw','')):
            seed=match.group().encode();queue=[(seed,[],0)]
            while queue and attempts<max_attempts:
                value,chain,depth=queue.pop(0);attempts+=1
                for name,decoder in _decoders(value):
                    try:decoded=decoder(value)
                    except Exception:continue
                    digest=__import__('hashlib').sha256(decoded).hexdigest();key=(event['event_id'],digest)
                    if key in seen or decoded==value or len(decoded)>8*1024*1024:continue
                    seen.add(key);printable=sum(32<=b<127 or b in (9,10,13) for b in decoded)/max(1,len(decoded));row={"input_hash":__import__('hashlib').sha256(value).hexdigest(),"output_hash":digest,"decoder_chain":chain+[name],"input_length":len(value),"output_length":len(decoded),"output_preview":decoded[:512].decode('utf-8','replace'),"source_event":event['event_id'],"source_file":event['source_file'],"offset":event['source_offset']+match.start(),"confidence":round(min(.96,.55+printable*.35),3),"bytes":decoded}
                    out.append(row)
                    if depth+1<max_depth:queue.append((decoded,chain+[name],depth+1))
    return out[:max_attempts]
def _decoders(value):
    text=value.decode('ascii','ignore');rows=[]
    if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}',text) and len(text)%4==0:rows.append(('base64',lambda x:base64.b64decode(x,validate=True)))
    if re.fullmatch(r'(?:[0-9a-fA-F]{2})+',text):rows.append(('hex',lambda x:bytes.fromhex(x.decode())))
    if '%' in text:rows.append(('url',lambda x:unquote_to_bytes(x.decode())))
    rows.extend([('reverse',lambda x:x[::-1]),('rot13',lambda x:codecs.decode(x.decode('utf-8'),'rot_13').encode())])
    if value.startswith(b'\x1f\x8b'):rows.append(('gzip',gzip.decompress))
    if value.startswith((b'x\x9c',b'x\xda',b'x\x01')):rows.append(('zlib',zlib.decompress))
    return rows
