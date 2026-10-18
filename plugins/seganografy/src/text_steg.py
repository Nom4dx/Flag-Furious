"""General textual steganography heuristics for prose, HTML, Markdown and JSON.

The analyzer enumerates reproducible reading paths. Readable output is evidence,
not proof: acrostics and capitalization patterns occur naturally and therefore
receive moderate confidence unless a decoder or flag validates them.
"""

from __future__ import annotations

import re
from io import StringIO
from html.parser import HTMLParser

MAX_LINES = 100_000
MAX_WORDS = 250_000
MAX_STRUCTURED_ITEMS = 128


class _HTMLHiddenParser(HTMLParser):
    """Collect comments, metadata attributes and text under hidden styles."""

    def __init__(self, max_items=MAX_STRUCTURED_ITEMS):
        super().__init__(convert_charrefs=True); self.items=[]; self.hidden=0; self.max_items=max_items; self.truncated=False

    def _add(self, item):
        value=item.get("value")
        if isinstance(value,str) and len(value)>4096:
            item["value"]=value[:4096];self.truncated=True
        if len(self.items) < self.max_items:self.items.append(item)
        else:self.truncated=True

    def handle_comment(self,data): self._add({"kind":"html_comment","value":data.strip(),"confidence":.7})
    def handle_starttag(self,tag,attrs):
        values=dict(attrs); style=values.get("style","").replace(" ","").lower()
        hidden=tag in {"script","template","noscript"} or "display:none" in style or "visibility:hidden" in style or "font-size:0" in style or "opacity:0" in style or "color:white;background-color:white" in style or values.get("hidden") is not None or values.get("aria-hidden")=="true"
        self.hidden+=int(hidden)
        for key in ("alt","title","aria-label","data-secret","content"):
            if values.get(key):self._add({"kind":f"html_attribute_{key}","value":values[key],"confidence":.72})
    def handle_endtag(self,tag):
        if self.hidden:self.hidden-=1
    def handle_data(self,data):
        if self.hidden and data.strip():self._add({"kind":"hidden_html_text","value":data.strip(),"confidence":.78})


def analyze(text: str, source_file: str, max_candidates: int = 128,
            max_lines: int = MAX_LINES, max_words: int = MAX_WORDS) -> dict:
    """Generate acrostic/telestic/word/parity/case/punctuation candidates.

    Output candidates include their exact technique and confidence. Inputs are
    capped by the caller; parsing is passive and never renders HTML or CSS.
    """
    lines=[]
    lines_truncated=False
    for line in StringIO(text):
        if not line.strip():continue
        if len(lines)>=max_lines:
            lines_truncated=True;break
        lines.append(line.rstrip("\r\n"))
    word_matches=[];words_truncated=False
    for match in re.finditer(r"[^\W_]+",text,re.UNICODE):
        if len(word_matches)>=max_words:
            words_truncated=True;break
        word_matches.append(match.group())
    words=word_matches
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
    structured=[];structured_truncated=False
    for pattern,kind in ((r"<!--([\s\S]*?)-->","comment"),(r"\[([^]]+)\]\([^)]+\)","markdown_link_text"),(r'"([^"\\]{4,})"\s*:',"json_key")):
        for match in re.finditer(pattern,text):
            if len(structured)>=MAX_STRUCTURED_ITEMS:
                structured_truncated=True;break
            structured.append({"kind":kind,"value":match.group(1)[:4096],"offset":match.start(1),"confidence":.5})
    truncated=lines_truncated or words_truncated or len(candidates)>max_candidates or structured_truncated or html.truncated
    return {"source_file":source_file,"lines":len(lines),"words":len(words),"candidates":candidates[:max_candidates],"structured_text":structured,"truncated":truncated,"coverage":{"line_limit":max_lines,"line_count_observed":len(lines),"lines_truncated":lines_truncated,"word_limit":max_words,"word_count_observed":len(words),"words_truncated":words_truncated,"candidate_limit":max_candidates,"candidate_omitted":max(0,len(candidates)-max_candidates),"structured_limit":MAX_STRUCTURED_ITEMS,"structured_truncated":structured_truncated,"html_item_limit":MAX_STRUCTURED_ITEMS,"html_items_truncated":html.truncated}}


def unicoded_punctuation(char: str) -> bool:
    """Return whether a character belongs to a Unicode punctuation category."""
    import unicodedata
    return unicodedata.category(char).startswith("P")
