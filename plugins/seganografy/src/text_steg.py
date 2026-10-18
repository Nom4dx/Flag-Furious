"""General textual steganography heuristics for prose, HTML, Markdown and JSON.

The analyzer enumerates reproducible reading paths. Readable output is evidence,
not proof: acrostics and capitalization patterns occur naturally and therefore
receive moderate confidence unless a decoder or flag validates them.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser


class _HTMLHiddenParser(HTMLParser):
    """Collect comments, metadata attributes and text under hidden styles."""

    def __init__(self):
        super().__init__(convert_charrefs=True); self.items=[]; self.hidden=0

    def handle_comment(self,data): self.items.append({"kind":"html_comment","value":data.strip(),"confidence":.7})
    def handle_starttag(self,tag,attrs):
        values=dict(attrs); style=values.get("style","").replace(" ","").lower()
        hidden=tag in {"script","template","noscript"} or "display:none" in style or "visibility:hidden" in style or "font-size:0" in style or "opacity:0" in style or "color:white;background-color:white" in style or values.get("hidden") is not None or values.get("aria-hidden")=="true"
        self.hidden+=int(hidden)
        for key in ("alt","title","aria-label","data-secret","content"):
            if values.get(key):self.items.append({"kind":f"html_attribute_{key}","value":values[key],"confidence":.72})
    def handle_endtag(self,tag):
        if self.hidden:self.hidden-=1
    def handle_data(self,data):
        if self.hidden and data.strip():self.items.append({"kind":"hidden_html_text","value":data.strip(),"confidence":.78})


def analyze(text: str, source_file: str, max_candidates: int = 128) -> dict:
    """Generate acrostic/telestic/word/parity/case/punctuation candidates.

    Output candidates include their exact technique and confidence. Inputs are
    capped by the caller; parsing is passive and never renders HTML or CSS.
    """
    lines=[line for line in text.splitlines() if line.strip()]; words=re.findall(r"[^\W_]+",text,re.UNICODE)
    candidates=[]
    def add(technique,value,confidence=.45,**extra):
        if value and len(value)>=3:candidates.append({"technique":technique,"value":value[:10000],"output_preview":value[:256],"confidence":confidence,"source_file":source_file,**extra})
    add("line_acrostic","".join(line.lstrip()[:1] for line in lines)); add("line_telestic","".join(line.rstrip()[-1:] for line in lines))
    add("line_first_last","".join(line.strip()[:1]+line.strip()[-1:] for line in lines))
    add("word_initials","".join(word[0] for word in words)); add("word_finals","".join(word[-1] for word in words))
    add("odd_words"," ".join(words[::2])); add("even_words"," ".join(words[1::2])); add("odd_lines","\n".join(lines[::2])); add("even_lines","\n".join(lines[1::2]))
    add("capitalization_bits","".join("1" if c.isupper() else "0" for c in text if c.isalpha()),.38)
    add("punctuation_channel","".join(c for c in text if unicoded_punctuation(c)),.32)
    add("word_lengths"," ".join(str(len(word)) for word in words),.28)
    for position in range(2,min(16,max((len(x) for x in lines),default=0)+1)):
        value="".join(line[position-1] for line in lines if len(line)>=position)
        add("line_position_n",value,.35,position=position)
    html=_HTMLHiddenParser()
    try:html.feed(text)
    except ValueError:pass
    for item in html.items:add(item["kind"],item["value"],item["confidence"])
    # Markdown/JSON/XML comments and values are retained with source offsets.
    structured=[]
    for pattern,kind in ((r"<!--([\s\S]*?)-->","comment"),(r"\[([^]]+)\]\([^)]+\)","markdown_link_text"),(r'"([^"\\]{4,})"\s*:',"json_key")):
        for match in re.finditer(pattern,text):structured.append({"kind":kind,"value":match.group(1),"offset":match.start(1),"confidence":.5})
    return {"source_file":source_file,"lines":len(lines),"words":len(words),"candidates":candidates[:max_candidates],"structured_text":structured[:max_candidates]}


def unicoded_punctuation(char: str) -> bool:
    """Return whether a character belongs to a Unicode punctuation category."""
    import unicodedata
    return unicodedata.category(char).startswith("P")
