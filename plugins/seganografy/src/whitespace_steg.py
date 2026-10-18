"""Whitespace channels: trailing spaces, tabs, blank lines and bit mappings."""


def analyze(text: str, source_file: str) -> dict:
    """Extract whitespace bit streams without executing the Whitespace language.

    Space/tab channels are decoded in both polarities and directions. Output
    records mapping and source line. The separate decoder module provides a
    bounded Whitespace-language interpreter for push/output programs.
    """
    lines=text.splitlines(keepends=True); trailing=[]
    for index,line in enumerate(lines,1):
        body=line.rstrip("\r\n"); suffix=body[len(body.rstrip(" \t")):]
        if suffix:trailing.append({"line":index,"sequence":suffix.replace(" ","S").replace("\t","T"),"length":len(suffix)})
    sequence="".join(c for c in text if c in " \t")
    candidates=[]
    if len(sequence)>=8:
        for inverse in (False,True):
            bits="".join("1" if (c=="\t")^inverse else "0" for c in sequence)
            for reverse in (False,True):
                view=bits[::-1] if reverse else bits; raw=bytes(int(view[i:i+8],2) for i in range(0,len(view)-7,8))
                candidates.append({"technique":"space_tab_bits","mapping":"tab=1" if not inverse else "space=1","reverse":reverse,"output":raw,"output_preview":raw[:256].decode("utf-8","replace"),"confidence":.75 if raw and sum(32<=x<127 for x in raw)/len(raw)>.7 else .35})
    return {"source_file":source_file,"trailing_whitespace":trailing,"space_tab_symbols":len(sequence),"double_spaces":text.count("  "),"double_newlines":text.count("\n\n"),"candidates":candidates}
