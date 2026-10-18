"""Bounded multiline grouping for stack traces and continuation records."""
import re
START=re.compile(r'^(?:<\d+>|\d{4}-\d\d-\d\d|[A-Z][a-z]{2}\s+\d|\d{1,3}(?:\.\d{1,3}){3}\s)')
def group(lines:list[tuple[int,int,str]],limit:int=1000):
    """Join indented/stack-trace continuations while preserving first provenance."""
    output=[];current=None
    for line_no,offset,text in lines:
        starts=bool(START.match(text)) or current is None
        if starts:
            if current:output.append(current)
            current={"source_line":line_no,"source_offset":offset,"raw":text,"line_count":1}
        elif current["line_count"]<limit:
            current["raw"]+='\n'+text;current["line_count"]+=1
    if current:output.append(current)
    return output
