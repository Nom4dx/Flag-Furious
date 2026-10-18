"""Unicode steganography, confusable and visual/logical-order analysis.

The implementation follows the defensive ideas of Unicode UTS #39 and Trojan
Source: bidirectional controls can change visual ordering, while mixed-script
homoglyphs can make distinct identifiers look alike. It reports evidence and
creates derived normalized views; it never removes characters from the source.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata


ZERO_WIDTH = {0x200B:"ZERO WIDTH SPACE",0x200C:"ZERO WIDTH NON-JOINER",0x200D:"ZERO WIDTH JOINER",0x2060:"WORD JOINER",0xFEFF:"BOM/ZERO WIDTH NO-BREAK SPACE",0x00AD:"SOFT HYPHEN"}
BIDI = {0x200E:"LRM",0x200F:"RLM",0x202A:"LRE",0x202B:"RLE",0x202C:"PDF",0x202D:"LRO",0x202E:"RLO",0x2066:"LRI",0x2067:"RLI",0x2068:"FSI",0x2069:"PDI"}
SPECIAL_SPACES = {0x00A0,0x1680,0x180E,0x2000,0x2001,0x2002,0x2003,0x2004,0x2005,0x2006,0x2007,0x2008,0x2009,0x200A,0x202F,0x205F,0x2800,0x3000}
CONFUSABLES = {"а":"a","е":"e","о":"o","р":"p","с":"c","у":"y","х":"x","Α":"A","Β":"B","Ε":"E","Ζ":"Z","Η":"H","Ι":"I","Κ":"K","Μ":"M","Ν":"N","Ο":"O","Ρ":"P","Τ":"T","Υ":"Y","Χ":"X"}
MAX_SUSPICIOUS_ITEMS = 10_000
MAX_MIXED_SCRIPT_ITEMS = 10_000
MAX_SYMBOLS = 100_000
MAX_VARIANT_CODEPOINTS = 100_000


def _script(char: str) -> str:
    """Infer a coarse Unicode script from the assigned character name."""
    name=unicodedata.name(char,"")
    for script in ("LATIN","CYRILLIC","GREEK","ARABIC","HEBREW","CJK","HIRAGANA","KATAKANA","HANGUL"):
        if script in name:return script
    return "COMMON" if not char.isalpha() else "OTHER"


def analyze(text: str, source_file: str, source_sha256: str, max_codepoints: int = 100000) -> dict:
    """Inventory codepoints and extract invisible multi-state channels.

    Output includes position, UTF-8 byte index, hex value, Unicode name/category,
    script, bidi class, normalization, confusable and steganographic role. The
    inventory is capped; ``truncated`` is explicit. Derived raw/escaped/normalized/
    cleaned views are returned as bytes for safe artifact storage.
    """
    inventory=[]; byte_index=0; symbols=[]; suspicious=[]
    suspicious_count = symbol_count = 0
    for position,char in enumerate(text):
        code=ord(char); category=unicodedata.category(char); name=unicodedata.name(char,"UNASSIGNED")
        role=None
        if code in ZERO_WIDTH: role="zero_width"
        elif code in BIDI: role="bidirectional_control"
        elif 0xFE00<=code<=0xFE0F or 0xE0100<=code<=0xE01EF: role="variation_selector"
        elif 0xE0000<=code<=0xE007F: role="tag_character"
        elif category.startswith("M"): role="combining_mark"
        elif code in SPECIAL_SPACES: role="nonstandard_whitespace"
        elif category in {"Cc","Cf","Co","Cn"}: role="control_or_unassigned"
        confusable=CONFUSABLES.get(char)
        if role or confusable:
            item={"position":position,"utf8_index":byte_index,"codepoint":f"U+{code:04X}","name":name,"category":category,"script":_script(char),"bidi":unicodedata.bidirectional(char),"visible":repr(char),"normalized":unicodedata.normalize("NFKC",char),"confusable":confusable,"steganographic_role":role}
            suspicious_count += 1
            if len(suspicious) < MAX_SUSPICIOUS_ITEMS:
                suspicious.append(item)
        if position<max_codepoints:
            inventory.append({"position":position,"utf8_index":byte_index,"codepoint":f"U+{code:04X}","name":name,"category":category,"script":_script(char),"bidi":unicodedata.bidirectional(char),"visible":repr(char),"normalized":unicodedata.normalize("NFKC",char),"confusable":confusable,"steganographic_role":role})
        if role in {"zero_width","variation_selector","tag_character"}:
            symbol_count += 1
            if len(symbols) < MAX_SYMBOLS:
                symbols.append((position,byte_index,code,role))
        byte_index+=len(char.encode("utf-8"))
    mixed=[]; mixed_count=0
    for match in re.finditer(r"[^\W\d_]+",text,re.UNICODE):
        scripts={_script(c) for c in match.group() if _script(c) not in {"COMMON","OTHER"}}
        if len(scripts)>1:
            mixed_count += 1
            if len(mixed) < MAX_MIXED_SCRIPT_ITEMS:
                mixed.append({"token":match.group()[:4096],"position":match.start(),"scripts":sorted(scripts),"skeleton":"".join(CONFUSABLES.get(c,c) for c in match.group()[:4096])})
    channels=_decode_symbols(symbols)
    variants={"codepoints.txt":"\n".join(f"{x['position']}\t{x['utf8_index']}\t{x['codepoint']}\t{x['name']}" for x in inventory).encode()}
    variants_truncated = len(text) > MAX_VARIANT_CODEPOINTS
    if not variants_truncated:
        cleaned="".join(c for c in text if ord(c) not in ZERO_WIDTH and ord(c) not in BIDI and not (0xFE00<=ord(c)<=0xFE0F or 0xE0100<=ord(c)<=0xE01EF or 0xE0000<=ord(c)<=0xE007F))
        variants.update({"raw.txt":text.encode("utf-8"),"normalized-nfc.txt":unicodedata.normalize("NFC",text).encode(),"normalized-nfd.txt":unicodedata.normalize("NFD",text).encode(),"normalized-nfkc.txt":unicodedata.normalize("NFKC",text).encode(),"normalized-nfkd.txt":unicodedata.normalize("NFKD",text).encode(),"cleaned-derived.txt":cleaned.encode()})
    inventory_truncated = len(text) > max_codepoints
    suspicious_truncated = suspicious_count > len(suspicious)
    mixed_script_truncated = mixed_count > len(mixed)
    symbol_channel_truncated = symbol_count > len(symbols)
    truncated = inventory_truncated or suspicious_truncated or mixed_script_truncated or symbol_channel_truncated or variants_truncated
    return {"source_file":source_file,"source_sha256":source_sha256,"total_codepoints":len(text),"inventory":inventory,"suspicious":suspicious,"suspicious_count":suspicious_count,"mixed_script":mixed,"mixed_script_count":mixed_count,"symbol_channels":channels,"symbol_count":symbol_count,"variants":variants,"truncated":truncated,"coverage":{"inventory_truncated":inventory_truncated,"suspicious_truncated":suspicious_truncated,"mixed_script_truncated":mixed_script_truncated,"symbol_channel_truncated":symbol_channel_truncated,"variants_truncated":variants_truncated,"suspicious_omitted":max(0,suspicious_count-len(suspicious)),"mixed_script_omitted":max(0,mixed_count-len(mixed)),"symbols_omitted":max(0,symbol_count-len(symbols))},"visual_logical_difference_possible":any(ord(c) in BIDI for c in text)}


def _decode_symbols(symbols: list[tuple[int,int,int,str]]) -> list[dict]:
    """Try binary, inverse and multi-state mappings for invisible symbols."""
    if len(symbols)<8:return []
    codes=[]
    for _,_,code,_ in symbols:
        if code not in codes:codes.append(code)
    outputs=[]
    if len(codes)>=2:
        for inverse in (False,True):
            mapping={codes[0]:1 if inverse else 0,codes[1]:0 if inverse else 1}
            bits="".join(str(mapping[x[2]]) for x in symbols if x[2] in mapping)
            for reverse in (False,True):
                view=bits[::-1] if reverse else bits
                for group in (8,16):
                    raw=bytes(int(view[i:i+8],2) for i in range(0,len(view)-7,8)) if group==8 else b"".join(int(view[i:i+16],2).to_bytes(2,"big") for i in range(0,len(view)-15,16))
                    if raw:outputs.append({"technique":"unicode_invisible_to_bits","mapping":{f"U+{k:04X}":v for k,v in mapping.items()},"inverse":inverse,"reverse":reverse,"group":group,"offset":symbols[0][1],"output":raw,"output_preview":raw[:256].decode("utf-8","replace"),"confidence":.82 if sum(32<=b<127 for b in raw)/len(raw)>.7 else .48})
    if 2<len(codes)<=16:
        base=len(codes); values=[codes.index(x[2]) for x in symbols]; number=0
        for value in values:number=number*base+value
        raw=number.to_bytes(max(1,(number.bit_length()+7)//8),"big")
        outputs.append({"technique":"unicode_multistate","states":base,"offset":symbols[0][1],"output":raw,"output_preview":raw[:256].decode("utf-8","replace"),"confidence":.4})
    return outputs[:16]
