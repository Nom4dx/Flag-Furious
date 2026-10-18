"""Bounded recursive decoder pipeline for payload-like log fields."""
import base64,binascii,codecs,gzip,io,re,zlib
from urllib.parse import unquote_to_bytes
MAX_TOKEN_CHARS=1024*1024
MAX_DECODED_BYTES=8*1024*1024
MAX_TOTAL_DECODED=32*1024*1024
MAX_RESULTS=512
TOKENS=re.compile(r'(?<![A-Za-z0-9])(?:[A-Za-z0-9+/]{12,1048576}={0,2}|(?:[0-9a-fA-F]{2}){8,524288}|(?:%[0-9a-fA-F]{2}){4,349525})(?![A-Za-z0-9])')
def decode_events(events:list[dict],max_attempts:int=2000,max_depth:int=3,return_meta:bool=False):
    """Decode plausible tokens recursively, retaining chain and source event."""
    out=[];seen=set();attempts=0;decoded_total=0;truncated=False
    for event in events:
        for match in TOKENS.finditer(event.get('raw','')):
            if len(match.group())>MAX_TOKEN_CHARS:continue
            seed=match.group().encode();queue=[(seed,[],0)]
            while queue and attempts<max_attempts:
                value,chain,depth=queue.pop(0);attempts+=1
                for name,decoder in _decoders(value):
                    try:decoded=decoder(value)
                    except Exception:continue
                    digest=__import__('hashlib').sha256(decoded).hexdigest();key=(event['event_id'],digest)
                    if key in seen or decoded==value:continue
                    if len(decoded)>MAX_DECODED_BYTES or decoded_total+len(decoded)>MAX_TOTAL_DECODED:
                        truncated=True
                        continue
                    seen.add(key);printable=sum(32<=b<127 or b in (9,10,13) for b in decoded)/max(1,len(decoded));row={"input_hash":__import__('hashlib').sha256(value).hexdigest(),"output_hash":digest,"decoder_chain":chain+[name],"input_length":len(value),"output_length":len(decoded),"output_preview":decoded[:512].decode('utf-8','replace'),"source_event":event['event_id'],"source_file":event['source_file'],"offset":event['source_offset']+match.start(),"confidence":round(min(.96,.55+printable*.35),3),"bytes":decoded}
                    out.append(row);decoded_total+=len(decoded)
                    if len(out)>=MAX_RESULTS:
                        truncated=True
                        break
                    if depth+1<max_depth:queue.append((decoded,chain+[name],depth+1))
            if attempts>=max_attempts:
                truncated=True
                break
            if len(out)>=MAX_RESULTS or decoded_total>=MAX_TOTAL_DECODED:
                truncated=True
                break
        if truncated and (attempts>=max_attempts or len(out)>=MAX_RESULTS or decoded_total>=MAX_TOTAL_DECODED):break
    result=out[:MAX_RESULTS]
    metadata={"attempts":attempts,"decoded_bytes":decoded_total,"truncated":truncated}
    return (result,metadata) if return_meta else result
def _decoders(value):
    text=value.decode('ascii','ignore');rows=[]
    if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}',text) and len(text)%4==0:rows.append(('base64',lambda x:base64.b64decode(x,validate=True)))
    if re.fullmatch(r'(?:[0-9a-fA-F]{2})+',text):rows.append(('hex',lambda x:bytes.fromhex(x.decode())))
    if '%' in text:rows.append(('url',lambda x:unquote_to_bytes(x.decode())))
    rows.extend([('reverse',lambda x:x[::-1]),('rot13',lambda x:codecs.decode(x.decode('utf-8'),'rot_13').encode())])
    if value.startswith(b'\x1f\x8b'):rows.append(('gzip',_bounded_gzip))
    if value.startswith((b'x\x9c',b'x\xda',b'x\x01')):rows.append(('zlib',_bounded_zlib))
    return rows

def _bounded_gzip(value):
    with gzip.GzipFile(fileobj=io.BytesIO(value)) as source:
        return source.read(MAX_DECODED_BYTES+1)

def _bounded_zlib(value):
    return zlib.decompressobj().decompress(value,MAX_DECODED_BYTES+1)
