"""Generic line parser and shared provenance constructors.

Unknown fields remain in ``raw_fields`` and raw text is never discarded. Invalid
bytes are represented with replacement characters while byte offsets remain exact.
"""
from ..multiline import group

def lines(data:bytes,encoding='utf-8'):
    """Yield line number, exact byte offset and decoded text."""
    offset=0
    for number,raw in enumerate(data.splitlines(keepends=True),1):
        yield number,offset,raw.rstrip(b'\r\n').decode(encoding,'replace');offset+=len(raw)

def event(source,line,offset,raw,fields=None,parser='generic',timestamp_raw=None):
    """Build one raw event preserving source, line, offset and parser identity."""
    return {"source_file":source,"source_line":line,"source_offset":offset,"raw":raw,"raw_fields":fields or {},"parser":parser,"timestamp_raw":timestamp_raw}

def parse(data:bytes,source:str,context:dict):
    """Parse unknown logs line-by-line with optional bounded multiline grouping."""
    rows=list(lines(data,context.get('encoding','utf-8')))
    grouped=group(rows) if context.get('multiline',True) else [{"source_line":n,"source_offset":o,"raw":t,"line_count":1} for n,o,t in rows]
    return [event(source,x['source_line'],x['source_offset'],x['raw'],{"line_count":x['line_count']},'generic') for x in grouped if x['raw']]
