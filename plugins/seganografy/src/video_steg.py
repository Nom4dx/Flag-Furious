"""Bounded video container probing and frame/audio sampling.

FFprobe/FFmpeg are optional and run in the networkless worker through the safe
subprocess adapter. Sampling modes never extract unbounded frame sets. Produced
frames and audio remain passive artifacts for recursive hub analysis.
"""

from __future__ import annotations

import json
from pathlib import Path

from .safe_subprocess import locate, run


MODES={"extract_frames:first","extract_frames:last","extract_frames:keyframes","extract_frames:every_n","extract_frames:all_with_limit"}


def analyze(path: Path, output_dir: Path, max_frames: int, timeout: int, tool_output: int, modes: list[str] | None = None) -> dict:
    """Probe streams and extract a bounded set of representative frames/audio.

    Input is immutable media. Output records every command, exit code, duration,
    frame index/timestamp approximation and artifact bytes. Missing tools produce
    ``not_applicable`` warnings. No codec output is executed.
    """
    selected=[mode for mode in (modes or ["extract_frames:first","extract_frames:last","extract_frames:keyframes"]) if mode in MODES]
    if not locate("ffprobe"):return {"applicable":False,"warnings":["ffprobe non disponibile"],"tools":[],"frames":[],"artifacts":[]}
    probe=run("ffprobe",["-v","error","-show_format","-show_streams","-of","json",str(path)],timeout,tool_output)
    try:metadata=json.loads(probe["stdout"] or "{}")
    except json.JSONDecodeError:metadata={}
    video_streams=[x for x in metadata.get("streams",[]) if x.get("codec_type")=="video"]
    if not video_streams:return {"applicable":False,"metadata":metadata,"warnings":["Nessuno stream video"],"tools":[probe],"frames":[],"artifacts":[]}
    tools=[probe];frames=[];artifacts=[];temp=output_dir/"video-sampling";temp.mkdir(parents=True,exist_ok=True)
    if locate("ffmpeg"):
        filters=[]
        if "extract_frames:first" in selected:filters.append(("first","select=eq(n\\,0)",1))
        # The last frame uses ffmpeg's input-relative seek; the ``duration``
        # symbol is not portable inside select expressions.
        if "extract_frames:last" in selected:
            pattern=temp/"last-%03d.png"
            result=run("ffmpeg",["-v","error","-sseof","-1","-i",str(path),"-frames:v","1",str(pattern)],timeout,tool_output,cwd=temp);tools.append(result)
            for item in sorted(temp.glob("last-*.png"))[:1]:
                data=item.read_bytes();record={"frame_index":len(frames),"timestamp":"last_second","keyframe":False,"sampling_mode":"extract_frames:last","techniques":[],"flags":[],"name":item.name,"data":data,"status":"extracted","confidence":.98}
                frames.append({k:v for k,v in record.items() if k!="data"});artifacts.append(record);item.unlink()
        if "extract_frames:keyframes" in selected:filters.append(("keyframe","select=eq(pict_type\\,I)",max_frames))
        if "extract_frames:every_n" in selected:filters.append(("sample","select=not(mod(n\\,30))",max_frames))
        if "extract_frames:all_with_limit" in selected:filters.append(("limited","select=lt(n\\,%d)"%max_frames,max_frames))
        remaining=max_frames
        for label,expression,limit in filters:
            if remaining<=0:break
            count=min(limit,remaining);pattern=temp/f"{label}-%03d.png"
            result=run("ffmpeg",["-v","error","-i",str(path),"-vf",expression,"-vsync","vfr","-frames:v",str(count),str(pattern)],timeout,tool_output,cwd=temp);tools.append(result)
            produced=sorted(temp.glob(f"{label}-*.png"))[:count]
            for item in produced:
                data=item.read_bytes();index=len(frames);record={"frame_index":index,"timestamp":None,"keyframe":label=="keyframe","sampling_mode":f"extract_frames:{label}","techniques":[],"flags":[],"name":item.name,"data":data,"status":"extracted","confidence":.98}
                frames.append({k:v for k,v in record.items() if k!="data"});artifacts.append(record);item.unlink()
            remaining-=len(produced)
        audio=temp/"audio.wav";result=run("ffmpeg",["-v","error","-i",str(path),"-map","0:a:0?","-vn","-acodec","pcm_s16le","-t","120",str(audio)],timeout,tool_output,cwd=temp);tools.append(result)
        if audio.is_file() and audio.stat().st_size:
            artifacts.append({"name":"video-audio.wav","data":audio.read_bytes(),"status":"extracted","technique":"video_audio_stream","confidence":.98});audio.unlink()
    return {"applicable":True,"metadata":metadata,"streams":metadata.get("streams",[]),"chapters":metadata.get("chapters",[]),"frames":frames,"artifacts":artifacts,"tools":tools,"warnings":[] if locate("ffmpeg") else ["ffmpeg non disponibile: frame non estratti"]}
