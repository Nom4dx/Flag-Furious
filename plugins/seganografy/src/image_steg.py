"""Image steganalysis, bounded bit extraction and statistical diagnostics.

The bit extractor supports zsteg-compatible dimensions (channels, 1–8 bits,
xy/yx/reverse order, LSB/MSB, invert, offset and step). Statistical anomalies are
reported as possibilities; only readable or structurally recognizable extracted
bytes are promoted to artifacts.
"""

from __future__ import annotations

import io
import math
import re
from pathlib import Path

from .decoders import printable_ratio
from .safe_subprocess import locate, run


FILE_MARKERS=(b"\x89PNG\r\n\x1a\n",b"\xff\xd8\xff",b"PK\x03\x04",b"%PDF-",b"GIF89a",b"GIF87a",b"\x1f\x8b\x08",b"RIFF")


def available() -> bool:
    """Return whether Pillow is importable; absence triggers a core warning."""
    try:import PIL  # noqa: F401
    except ImportError:return False
    return True


def extract_bits(image, *, bits: int, channels: str, order: str, bit_order: str, invert: bool, step: int, offset: int, max_bytes: int) -> bytes:
    """Extract a bounded pixel bit stream for one explicit configuration.

    ``image`` is a Pillow object converted to RGBA. Channels accept r/g/b/a/rgb/
    rgba/bgr. Uppercase order reverses traversal; yx swaps axes. Invalid options
    raise ``ValueError``. The function never alters pixels or the source file.
    """
    if bits not in range(1,9) or channels not in {"r","g","b","a","rgb","rgba","bgr"} or order not in {"xy","yx","XY","YX"} or bit_order not in {"lsb","msb"} or step<1 or offset<0:raise ValueError("configurazione LSB non valida")
    rgba=image.convert("RGBA");width,height=rgba.size;pixels=rgba.load();indexes={"r":0,"g":1,"b":2,"a":3};selected=[indexes[x] for x in channels]
    reverse=order.isupper();yx=order.lower()=="yx"
    primary=range(height) if not yx else range(width);secondary=range(width) if not yx else range(height)
    if reverse:primary=reversed(list(primary));secondary_values=list(secondary)[::-1]
    else:secondary_values=list(secondary)
    packed=bytearray();current=count=seen=0
    for first in primary:
        for second in secondary_values:
            x,y=(second,first) if not yx else (first,second)
            for channel in selected:
                if seen<offset:seen+=1;continue
                if (seen-offset)%step:seen+=1;continue
                value=pixels[x,y][channel];positions=range(bits) if bit_order=="lsb" else range(7,7-bits,-1)
                for position in positions:
                    bit=(value>>position)&1
                    if invert:bit^=1
                    current=(current<<1)|bit;count+=1
                    if count==8:
                        packed.append(current);current=count=0
                        if len(packed)>=max_bytes:return bytes(packed)
                seen+=1
    return bytes(packed)


def analyze(path: Path, mode: str, max_attempts: int, max_artifact: int, timeout: int, tool_output: int) -> dict:
    """Analyze image metadata, planes, channels, LSB modes, QR/OCR and statistics.

    Output contains explicit configurations, promoted byte candidates,
    visualization-ready statistics and optional-tool audits. JPEG coefficient
    claims remain heuristic because Pillow exposes decoded pixels, not original
    quantized DCT coefficients.
    """
    if not available():return {"applicable":False,"warnings":["Pillow non disponibile"],"candidates":[],"artifacts":[],"visualizations":[],"tools":[]}
    from PIL import Image
    try:
        image=Image.open(path);image.load()
    except (OSError,ValueError) as exc:return {"applicable":False,"warnings":[f"Parser immagine: {exc}"],"candidates":[],"artifacts":[],"visualizations":[],"tools":[]}
    rgba=image.convert("RGBA");width,height=rgba.size;attempts=[];candidates=[]
    bit_values=range(1,9) if mode=="deep" else (1,2,4,8) if mode=="balanced" else (1,)
    channel_values=("r","g","b","a","rgb","rgba","bgr") if mode=="deep" else ("r","g","b","a","rgb","rgba") if mode=="balanced" else ("rgb","rgba")
    orders=("xy","yx","XY","YX") if mode=="deep" else ("xy","yx") if mode=="balanced" else ("xy",)
    for bits in bit_values:
        for channels in channel_values:
            if "a" in channels and image.mode not in {"RGBA","LA","P"}:continue
            for order in orders:
                for bit_order in ("lsb","msb"):
                    if len(attempts)>=max_attempts:break
                    config={"technique":"lsb" if bit_order=="lsb" else "msb","bits":bits,"channels":channels,"order":order,"bit_order":bit_order,"invert":False,"step":1,"offset":0}
                    raw=extract_bits(rgba,**{k:config[k] for k in ("bits","channels","order","bit_order","invert","step","offset")},max_bytes=min(max_artifact,2*1024*1024));ratio=printable_ratio(raw);marker=next((m for m in FILE_MARKERS if raw.startswith(m)),None);flag_like=bool(re.search(rb"[A-Za-z][A-Za-z0-9_]{1,31}\{[^{}\x00\r\n]{1,512}\}",raw))
                    record={**config,"output_length":len(raw),"printable_ratio":round(ratio,3),"known_signature":marker.hex() if marker else None,"flag_like":flag_like,"confidence":.96 if flag_like else .92 if marker else .76 if ratio>.82 and len(raw)>=8 else .28}
                    attempts.append(record)
                    if marker or flag_like or ratio>.82:
                        candidates.append({**record,"data":raw,"status":"decoded" if flag_like else "extracted" if marker else "extracted_uninterpreted","output_preview":raw[:256].decode("utf-8","replace")})
                if len(attempts)>=max_attempts:break
            if len(attempts)>=max_attempts:break
        if len(attempts)>=max_attempts:break
    pixels=list(rgba.getdata());parity=[]
    for index,name in enumerate("rgba"):
        even=sum(1 for pixel in pixels if not pixel[index]&1);odd=len(pixels)-even
        expected=max(1,len(pixels)/2);chi=((even-expected)**2+(odd-expected)**2)/expected
        parity.append({"channel":name,"even":even,"odd":odd,"chi_square":round(chi,4),"possible_lsb_embedding":chi<.15 and len(pixels)>256,"confidence":.55 if chi<.15 else .2})
    unique=len(set(pixels));near_identical=sum(1 for a,b in zip(pixels,pixels[1:]) if max(abs(a[i]-b[i]) for i in range(4))<=1)
    statistics={"width":width,"height":height,"mode":image.mode,"frames":getattr(image,"n_frames",1),"unique_colors":unique,"near_identical_adjacent":near_identical,"palette":image.mode=="P","metadata":{str(k):str(v)[:4096] for k,v in image.info.items() if not isinstance(v,bytes)},"parity":parity,"piet_possible":unique<=32 and width*height<=1000000}
    plane_artifacts=[]
    for index,name in enumerate("rgba"):
        plane=Image.new("L",rgba.size);plane.putdata([255 if pixel[index]&1 else 0 for pixel in pixels]);output=io.BytesIO();plane.save(output,format="PNG")
        plane_artifacts.append({"name":f"bit-plane-{name}-lsb.png","data":output.getvalue(),"technique":"bit_plane_visualization","channel":name,"status":"extracted","confidence":.5})
    tools=[]
    for tool,args in (("zbarimg",["--quiet",str(path)]),("tesseract",[str(path),"stdout"]),("identify",["-verbose",str(path)])):
        if locate(tool):tools.append(run(tool,args,timeout,tool_output))
    visual=[{"type":"bar","title":"Parità LSB per canale","data":[{"x":x["channel"]+" even","y":x["even"]} for x in parity]+[{"x":x["channel"]+" odd","y":x["odd"]} for x in parity],"palette":"signal","options":{"interactive":True,"tooltip":True}}]
    return {"applicable":True,"format":(image.format or "image").lower(),"statistics":statistics,"attempts":attempts,"candidates":candidates,"artifacts":plane_artifacts,"visualizations":visual,"tools":tools,"warnings":["Analisi DCT/DWT basata su pixel decodificati: anomalia statistica, non estrazione"] if (image.format or "").upper()=="JPEG" else []}
