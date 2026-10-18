"""EVTX parser adapter using python-evtx when installed.

EVTX records are structured binary records, never strings-scanned as a parser.
Absent dependencies return an explicit recoverable parser event.
"""
from pathlib import Path
from .windows_xml import parse as parse_xml
def parse_path(path:Path,source:str,context:dict):
    """Read EVTX records with python-evtx and map each XML record passively."""
    try:
        from Evtx.Evtx import Evtx
    except ImportError:return [],["python-evtx non disponibile: EVTX strutturato non analizzato"]
    out=[];warnings=[]
    try:
        with Evtx(str(path)) as handle:
            for record in handle.records():
                if len(out)>=context.get('max_events',200000):warnings.append('EVTX limitato a max_events');break
                rows=parse_xml(record.xml().encode(),source,context)
                for row in rows:row['source_offset']=record.offset();row['record_id']=record.record_num();row['parser']='evtx'
                out.extend(rows)
    except Exception as exc:warnings.append(f'EVTX parziale: {exc}')
    return out,warnings
