"""PCM audio steganalysis, signal statistics and safe derived audio views.

WAV is parsed internally. Other containers are inventoried by signatures and
optional ffprobe/ffmpeg. Phase, echo, spread-spectrum, QIM and spectral findings
are heuristic and never labeled as extracted payloads without decodable bytes.
"""

from __future__ import annotations

import io
import math
import re
import struct
import wave
from pathlib import Path

from .decoders import printable_ratio


def _samples(raw: bytes, width: int) -> list[int]:
    """Decode little-endian PCM samples for widths 1, 2, 3 or 4 bytes."""
    if width==1:return [x-128 for x in raw]
    if width==2:return list(struct.unpack("<"+"h"*(len(raw)//2),raw[:len(raw)//2*2]))
    if width==4:return list(struct.unpack("<"+"i"*(len(raw)//4),raw[:len(raw)//4*4]))
    if width==3:
        return [int.from_bytes(raw[i:i+3]+(b"\xff" if raw[i+2]&0x80 else b"\0"),"little",signed=True) for i in range(0,len(raw)-2,3)]
    raise ValueError("sample width non supportato")


def _bits_to_bytes(bits) -> bytes:
    """Pack a bit iterator most-significant output bit first."""
    output=bytearray();current=count=0
    for bit in bits:
        current=(current<<1)|(bit&1);count+=1
        if count==8:output.append(current);current=count=0
    return bytes(output)


def _wave_bytes(params, frames: bytes, rate: int | None = None) -> bytes:
    """Serialize PCM frames to a derived WAV without touching the source."""
    output=io.BytesIO()
    with wave.open(output,"wb") as target:
        target.setnchannels(params.nchannels);target.setsampwidth(params.sampwidth);target.setframerate(rate or params.framerate);target.writeframes(frames)
    return output.getvalue()


def analyze(path: Path, max_artifact: int, max_attempts: int) -> dict:
    """Extract PCM LSB channels and generate waveform/spectrum diagnostics.

    Input must be a WAV accepted by ``wave``. Outputs include exact bit-plane
    configurations, reverse/slow/fast passive copies, channel candidates and
    engine-ready waveform/spectrogram data. Unsupported codecs return not
    applicable rather than failing the plugin.
    """
    try:
        with wave.open(str(path),"rb") as source:
            params=source.getparams();frames=source.readframes(min(source.getnframes(),max_artifact//max(1,source.getnchannels()*source.getsampwidth())))
    except (wave.Error,OSError,EOFError) as exc:return {"applicable":False,"warnings":[f"Parser WAV: {exc}"],"candidates":[],"artifacts":[],"visualizations":[]}
    try:samples=_samples(frames,params.sampwidth)
    except ValueError as exc:return {"applicable":False,"warnings":[str(exc)],"candidates":[],"artifacts":[],"visualizations":[]}
    channels=[samples[index::params.nchannels] for index in range(params.nchannels)];attempts=[];candidates=[]
    for channel_index,channel in enumerate(channels):
        for bit in range(min(8,params.sampwidth*8)):
            if len(attempts)>=max_attempts:break
            raw=_bits_to_bytes((value>>bit)&1 for value in channel)[:max_artifact];ratio=printable_ratio(raw);known=raw.startswith((b"PK\x03\x04",b"\x89PNG",b"%PDF-",b"\x1f\x8b"));flag_like=bool(re.search(rb"[A-Za-z][A-Za-z0-9_]{1,31}\{[^{}\x00\r\n]{1,512}\}",raw))
            record={"technique":"pcm_bit_plane","channel":channel_index,"bit":bit,"samples":len(channel),"output_length":len(raw),"printable_ratio":round(ratio,3),"flag_like":flag_like,"confidence":.96 if flag_like else .92 if known else .75 if ratio>.82 else .25}
            attempts.append(record)
            if known or flag_like or ratio>.82:candidates.append({**record,"data":raw,"status":"decoded" if flag_like else "extracted" if known else "extracted_uninterpreted","output_preview":raw[:256].decode("utf-8","replace")})
    frame_size=params.nchannels*params.sampwidth;chunks=[frames[i:i+frame_size] for i in range(0,len(frames)-frame_size+1,frame_size)];reverse=b"".join(reversed(chunks))
    artifacts=[{"name":"audio-reversed.wav","data":_wave_bytes(params,reverse),"technique":"audio_reverse","status":"extracted","confidence":1.0},{"name":"audio-slow.wav","data":_wave_bytes(params,frames,max(1,params.framerate//2)),"technique":"sample_rate_half","status":"extracted","confidence":1.0},{"name":"audio-fast.wav","data":_wave_bytes(params,frames,params.framerate*2),"technique":"sample_rate_double","status":"extracted","confidence":1.0}]
    stride=max(1,len(samples)//1000);waveform=[{"x":index/params.framerate/params.nchannels,"y":samples[index]} for index in range(0,len(samples),stride)][:1000]
    spectrum=[];signal_findings=[]
    try:
        import numpy as np
        mono=np.asarray(channels[0][:min(len(channels[0]),262144)],dtype=float)
        if len(mono)>=256:
            window=1024;hop=512;rows=[]
            for start in range(0,min(len(mono)-window,window*64),hop):
                values=np.abs(np.fft.rfft(mono[start:start+window]*np.hanning(window)));bins=np.array_split(values,64);rows.append([float(np.mean(x)) for x in bins])
            maximum=max((max(row) for row in rows),default=1) or 1;spectrum=[[round(value/maximum,5) for value in row] for row in rows]
            frequencies=np.fft.rfftfreq(len(mono),1/params.framerate);power=np.abs(np.fft.rfft(mono))
            peaks=frequencies[np.argsort(power)[-12:]].tolist()
            dtmf=[float(x) for x in peaks if any(abs(x-f)<20 for f in (697,770,852,941,1209,1336,1477,1633))]
            if len(dtmf)>=2:signal_findings.append({"technique":"dtmf_frequency_pairs","frequencies":dtmf,"confidence":.58,"status":"detected"})
            autocorr=np.correlate(mono[:min(len(mono),20000)],mono[:min(len(mono),20000)],mode="full");autocorr=autocorr[len(autocorr)//2:]
            if len(autocorr)>100 and np.max(autocorr[40:])>autocorr[0]*.35:signal_findings.append({"technique":"possible_echo_hiding_or_repetition","confidence":.42,"status":"detected"})
    except (ImportError,ValueError,MemoryError):pass
    visualizations=[{"type":"line","title":"Waveform campionata","data":waveform,"encoding":{"x":{"field":"x","type":"number"},"y":{"field":"y","type":"number"}},"palette":"signal","options":{"interactive":True,"zoom":True,"pan":True,"tooltip":True}}]
    if spectrum:visualizations.append({"type":"heatmap","title":"Spettrogramma FFT multi-finestra","data":spectrum,"palette":"signal","options":{"interactive":True,"tooltip":True}})
    stats={"channels":params.nchannels,"sample_rate":params.framerate,"sample_width_bits":params.sampwidth*8,"frames_analyzed":len(chunks),"duration_analyzed":len(chunks)/params.framerate,"clipped_samples":sum(abs(x)>=(1<<(params.sampwidth*8-1))-1 for x in samples),"silent_samples":sum(x==0 for x in samples)}
    return {"applicable":True,"format":"wav","statistics":stats,"attempts":attempts,"candidates":candidates,"artifacts":artifacts,"signal_findings":signal_findings,"visualizations":visualizations,"warnings":[]}
