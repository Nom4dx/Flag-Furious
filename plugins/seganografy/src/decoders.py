"""Bounded classic, textual and compression decoders with chain provenance.

Decoders are deterministic and never import/evaluate decoded Python, JavaScript,
HTML or shell text. Failures are ordinary candidate outcomes. Recursive chaining
is implemented in ``recursive_pipeline`` with hash deduplication and attempt caps.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import hashlib
import html
import json
import re
import urllib.parse
import zlib


BASE58=b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MORSE={".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H","..":"I",".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R","...":"S","-":"T","..-":"U","...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z","-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9"}
BAUDOT={0:"",1:"E",2:"\n",3:"A",4:" ",5:"S",6:"I",7:"U",8:"\r",9:"D",10:"R",11:"J",12:"N",13:"F",14:"C",15:"K",16:"T",17:"Z",18:"L",19:"W",20:"H",21:"Y",22:"P",23:"Q",24:"O",25:"B",26:"G",27:"",28:"M",29:"X",30:"V",31:""}


def printable_ratio(data: bytes) -> float:
    """Return the fraction of ASCII whitespace/printable bytes."""
    return sum(byte in b"\t\r\n" or 32<=byte<127 for byte in data)/max(1,len(data))


def decode_candidates(data: bytes, max_output: int, prefixes: list[str]) -> list[dict]:
    """Try format-appropriate decoders and return successful bounded outputs.

    Each output includes input hash, decoder chain, lengths, preview and evidence
    score. Caesar/XOR variants are retained only when readable or containing a
    configured flag prefix, which controls false positives and output volume.
    """
    values=[]; input_hash=hashlib.sha256(data).hexdigest(); text=data.decode("utf-8","ignore").strip()
    needles=[p.encode().lower() for p in prefixes if p]
    def add(name,output,evidence=None,confidence=None,**extra):
        if isinstance(output,str):output=output.encode()
        if not output or len(output)>max_output or output==data:return
        ratio=printable_ratio(output); has_flag=any(re.search(re.escape(x)+rb"\{[^{}\r\n]{1,512}\}",output,re.I) for x in needles);known=output.startswith((b"PK\x03\x04",b"\x89PNG",b"%PDF-",b"\xff\xd8\xff",b"GIF8",b"RIFF",b"\x1f\x8b",b"7z\xbc\xaf'\x1c"))
        if name in {"rot13","rot47","atbash","reverse"} and not has_flag:return
        if not has_flag and not known and ratio<.55:return
        if confidence is None:confidence=min(.95,.42+ratio*.35+(.18 if has_flag else 0))
        values.append({"input_hash":input_hash,"decoder_chain":[name],"input_length":len(data),"output_length":len(output),"output_preview":output[:512].decode("utf-8","replace"),"output":output,"confidence":round(confidence,3),"evidence":evidence or (["printable output"] if ratio>.7 else [])+(["matching flag structure"] if has_flag else []),**extra})
    candidates=(
        ("base16",lambda:base64.b16decode(re.sub(r"\s+","",text).upper())),
        ("base32",lambda:base64.b32decode(re.sub(r"\s+","",text).upper()+"="*((-len(re.sub(r'\s+','',text)))%8))),
        ("base64",lambda:_base64(text,False)),
        ("base64url",lambda:_base64(text,True)),
        ("base85",lambda:base64.b85decode(re.sub(r"\s+","",text))),
        ("ascii85",lambda:base64.a85decode(text,adobe=text.startswith("<~"))),
        ("hex",lambda:bytes.fromhex(text)),
        ("url",lambda:urllib.parse.unquote_to_bytes(text)),
        ("html_entities",lambda:html.unescape(text).encode()),
        ("json_escape",lambda:json.loads(f'"{text}"').encode()),
        ("unicode_escape",lambda:codecs.decode(text,"unicode_escape").encode()),
        ("rot13",lambda:codecs.decode(text,"rot_13").encode()),
        ("rot47",lambda:"".join(chr(33+(ord(c)-33+47)%94) if 33<=ord(c)<=126 else c for c in text).encode()),
        ("atbash",lambda:"".join(chr(ord('A')+ord('Z')-ord(c)) if c.isupper() and c.isascii() else chr(ord('a')+ord('z')-ord(c)) if c.islower() and c.isascii() else c for c in text).encode()),
        ("reverse",lambda:data[::-1]),
        ("morse",lambda:_decode_morse(text).encode()),
        ("a1z26",lambda:"".join(chr(64+int(n)) if 1<=int(n)<=26 else "?" for n in re.findall(r"\d+",text)).encode()),
        ("bacon",lambda:_decode_bacon(text).encode()),
        ("baudot",lambda:_decode_baudot(text).encode()),
        ("brainfuck",lambda:_brainfuck_candidate(text)),
        ("ook",lambda:_ook_candidate(text)),
        ("whitespace_language",lambda:decode_whitespace_language(text)),
        ("gzip",lambda:_bounded_decompress(data, max_output, True)),
        ("zlib",lambda:_bounded_decompress(data, max_output, False)),
    )
    for name,function in candidates:
        try:add(name,function())
        except (ValueError,TypeError,binascii.Error,UnicodeError,json.JSONDecodeError,gzip.BadGzipFile,zlib.error,EOFError):pass
    if re.fullmatch(r"[0-9A-Za-z]+",text or "") and len(text)>=6:
        for base in (2,8,36):
            try:add(f"base{base}",int(text,base).to_bytes(max(1,(int(text,base).bit_length()+7)//8),"big"))
            except ValueError:pass
    if text and all(c in BASE58.decode() for c in text):
        number=0
        for char in text.encode():number=number*58+BASE58.index(char)
        add("base58",b"\0"*(len(text)-len(text.lstrip("1")))+number.to_bytes(max(1,(number.bit_length()+7)//8),"big"))
    for shift in range(1,26):
        output="".join(chr((ord(c.lower())-97-shift)%26+97).upper() if c.isupper() else chr((ord(c)-97-shift)%26+97) if c.islower() and c.isascii() else c for c in text).encode()
        if any(re.search(re.escape(x)+rb"\{",output,re.I) for x in needles):add(f"caesar:{shift}",output)
    for key in range(1,256):
        output=bytes(value^key for value in data)
        if any(re.search(re.escape(x)+rb"\{",output,re.I) for x in needles):add(f"xor:{key}",output,evidence=["matching flag structure","single-byte XOR"])
    return _dedupe(values)


def _bounded_decompress(data: bytes, limit: int, gzip_stream: bool) -> bytes:
    """Decompress at most ``limit`` bytes, rejecting expansion beyond the budget."""
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS if gzip_stream else zlib.MAX_WBITS)
    output = decoder.decompress(data, limit + 1)
    if len(output) > limit or decoder.unconsumed_tail:
        raise ValueError("decompression output budget exceeded")
    output += decoder.flush(max(0, limit + 1 - len(output)))
    if len(output) > limit:
        raise ValueError("decompression output budget exceeded")
    return output


def _dedupe(values: list[dict]) -> list[dict]:
    """Keep the strongest record for each decoded SHA-256."""
    seen={}
    for value in values:
        digest=hashlib.sha256(value["output"]).hexdigest(); value["output_hash"]=digest
        if digest not in seen or value["confidence"]>seen[digest]["confidence"]:seen[digest]=value
    return sorted(seen.values(),key=lambda x:-x["confidence"])


def _decode_bacon(text: str) -> str:
    """Decode A/B Bacon groups; non-symbol characters are ignored."""
    symbols="".join(c.upper() for c in text if c.upper() in "AB")
    if len(symbols)<5 or len(symbols)/max(1,len(text.replace(" ","")))<.8:raise ValueError("non Bacon")
    return "".join(chr(65+int(symbols[i:i+5].replace("A","0").replace("B","1"),2)) if int(symbols[i:i+5].replace("A","0").replace("B","1"),2)<26 else "?" for i in range(0,len(symbols)-4,5))


def _decode_morse(text: str) -> str:
    """Decode Morse only when the complete input uses Morse symbols/separators."""
    if not text or not re.fullmatch(r"[.\-/ \r\n]+",text):raise ValueError("non Morse")
    return " ".join("".join(MORSE.get(token,"?") for token in word.split()) for word in text.strip().split(" / "))


def _decode_baudot(text: str) -> str:
    """Decode 5-bit ITA2 letters without shift-state guessing."""
    if not re.fullmatch(r"[01\s]+",text) or len(text)<5:raise ValueError("non Baudot")
    bits="".join(c for c in text if c in "01")
    return "".join(BAUDOT.get(int(bits[i:i+5],2),"?") for i in range(0,len(bits)-4,5))


def decode_brainfuck(program: str, max_steps: int = 200000, max_output: int = 1048576) -> bytes:
    """Interpret Brainfuck with bounded tape, steps and output.

    Input commands are filtered to the eight-language alphabet. Unmatched loops
    or exhausted limits raise ``ValueError``. The language cannot access files,
    network or subprocesses.
    """
    code="".join(c for c in program if c in "><+-.,[]"); pairs={}; stack=[]
    for index,char in enumerate(code):
        if char=="[":stack.append(index)
        elif char=="]":
            if not stack:raise ValueError("Brainfuck bracket")
            left=stack.pop();pairs[left]=index;pairs[index]=left
    if stack:raise ValueError("Brainfuck bracket")
    tape=bytearray(65536);pointer=pc=steps=0;output=bytearray()
    while pc<len(code) and steps<max_steps and len(output)<max_output:
        command=code[pc]
        if command==">":pointer=(pointer+1)%len(tape)
        elif command=="<":pointer=(pointer-1)%len(tape)
        elif command=="+":tape[pointer]=(tape[pointer]+1)&255
        elif command=="-":tape[pointer]=(tape[pointer]-1)&255
        elif command==".":output.append(tape[pointer])
        elif command=="[" and not tape[pointer]:pc=pairs[pc]
        elif command=="]" and tape[pointer]:pc=pairs[pc]
        pc+=1;steps+=1
    if steps>=max_steps:raise ValueError("Brainfuck step limit")
    return bytes(output)


def _base64(text: str, urlsafe: bool) -> bytes:
    """Decode a syntactically plausible Base64 token of at least eight chars."""
    compact=re.sub(r"\s+","",text)
    alphabet=r"[A-Za-z0-9_-]+={0,2}" if urlsafe else r"[A-Za-z0-9+/]+={0,2}"
    if len(compact)<8 or not re.fullmatch(alphabet,compact):raise ValueError("non Base64")
    padded=compact+"="*((-len(compact))%4)
    return base64.urlsafe_b64decode(padded) if urlsafe else base64.b64decode(padded,validate=True)


def _brainfuck_candidate(text: str) -> bytes:
    """Require a command-dense source before invoking bounded Brainfuck."""
    code="".join(c for c in text if c in "><+-.,[]")
    if len(code)<12 or len(code)/max(1,len(text))<.45:raise ValueError("non Brainfuck")
    return decode_brainfuck(code)


def _ook_candidate(text: str) -> bytes:
    """Require canonical Ook! pairs before translating to Brainfuck."""
    if len(re.findall(r"Ook[.!?]",text,re.I))<4:raise ValueError("non Ook")
    return decode_brainfuck(_ook_to_brainfuck(text))


def _ook_to_brainfuck(text: str) -> str:
    """Translate canonical Ook! token pairs to Brainfuck commands."""
    tokens=re.findall(r"Ook[.!?]",text,re.I); mapping={
        (".","?"): ">", ("?","."): "<", (".","."): "+", ("!","!"): "-",
        ("!","."): ".", (".","!"): ",", ("!","?"): "[", ("?","!"): "]",
    }
    return "".join(mapping.get((tokens[i][-1],tokens[i+1][-1]),"") for i in range(0,len(tokens)-1,2))


def decode_whitespace_language(text: str, max_steps: int = 10000) -> bytes:
    """Interpret the safe push/output-character subset of Whitespace.

    Unsupported control-flow/heap instructions stop decoding. This conservative
    subset is sufficient for common CTF encoders and cannot perform I/O beyond
    producing bounded bytes.
    """
    code="".join(c for c in text if c in " \t\n");pc=steps=0;stack=[];out=bytearray()
    while pc<len(code) and steps<max_steps:
        if code.startswith("  ",pc):
            pc+=2
            if pc>=len(code):break
            sign=-1 if code[pc]=="\t" else 1;pc+=1;bits=""
            while pc<len(code) and code[pc]!="\n":bits+="1" if code[pc]=="\t" else "0";pc+=1
            pc+=1;stack.append(sign*int(bits or "0",2))
        elif code.startswith("\t\n  ",pc):
            pc+=4
            if not stack:raise ValueError("Whitespace stack")
            out.append(stack.pop()&255)
        else:break
        steps+=1
    if not out:raise ValueError("Whitespace subset non decodificabile")
    return bytes(out)
