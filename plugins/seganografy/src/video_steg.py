"""Bounded video container probing and frame/audio sampling.

FFprobe/FFmpeg are optional and run in the networkless worker through the safe
subprocess adapter. Frame count, per-artifact size, total output bytes, and time
are capped. Produced media remains passive evidence for recursive hub analysis.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .safe_subprocess import locate, run


MODES = {"extract_frames:first", "extract_frames:last", "extract_frames:keyframes", "extract_frames:every_n", "extract_frames:all_with_limit"}
DEFAULT_ARTIFACT_CAP = 32 * 1024 * 1024
AUDIO_RESERVE = 8 * 1024 * 1024


def _read_artifact(path: Path, cap: int) -> tuple[bytes | None, str | None]:
    size = path.stat().st_size
    if size <= 0:
        return None, f"Output media vuoto: {path.name}"
    if size >= cap:
        return None, f"Output media ha raggiunto il limite di {cap} byte: {path.name}"
    with path.open("rb") as source:
        data = source.read(cap + 1)
    if len(data) != size or len(data) > cap:
        return None, f"Vista media incoerente o oltre limite: {path.name}"
    return data, None


def _command_complete(result: dict) -> bool:
    return result.get("exit_code") == 0 and not result.get("timed_out") and not result.get("stdout_truncated")


def analyze(path: Path, output_dir: Path, max_frames: int, timeout: int,
            tool_output: int, modes: list[str] | None = None,
            max_output_bytes: int = 128 * 1024 * 1024,
            max_artifact_bytes: int = DEFAULT_ARTIFACT_CAP) -> dict:
    """Probe and extract representative media within shared output limits."""
    selected = [mode for mode in (modes or ["extract_frames:first", "extract_frames:last", "extract_frames:keyframes"]) if mode in MODES]
    warnings = []
    stage_deadline = time.monotonic() + min(240, max(1, int(timeout) * 4))

    def run_video(arguments: list[str], cwd: Path | None = None) -> dict:
        remaining = stage_deadline - time.monotonic()
        if remaining <= 0:
            warnings.append("Video analysis stopped at its cumulative time limit")
            return {"status": "partial", "exit_code": None, "timed_out": True,
                    "stdout_truncated": False, "stderr_truncated": False,
                    "stdout": "", "stderr": "cumulative timeout", "tool": arguments[0]}
        return run(arguments[0], arguments[1:], max(1, min(int(timeout), int(remaining))), tool_output, cwd=cwd)

    if not locate("ffprobe"):
        return {"applicable": False, "warnings": ["ffprobe non disponibile"], "tools": [], "frames": [], "artifacts": []}
    probe = run_video(["ffprobe", "-v", "error", "-show_format", "-show_streams", "-of", "json", str(path)])
    tools = [probe]
    if probe.get("status") == "partial" or probe.get("timed_out"):
        warnings.append("ffprobe output incompleto; inventario stream parziale")
    try:
        metadata = json.loads(probe["stdout"] or "{}")
    except json.JSONDecodeError:
        metadata = {}
        warnings.append("ffprobe JSON incompleto o non valido")
    video_streams = [item for item in metadata.get("streams", []) if item.get("codec_type") == "video"]
    if not video_streams:
        if metadata.get("streams") and not warnings:
            warnings.append("Nessuno stream video valido nell'output ffprobe")
        return {"applicable": False, "metadata": metadata, "warnings": warnings or ["Nessuno stream video"], "tools": tools, "frames": [], "artifacts": []}

    frames, artifacts = [], []
    total_output = 0
    output_limit = max(0, int(max_output_bytes))
    artifact_limit = min(max(0, int(max_artifact_bytes)), output_limit)
    temp = output_dir / "video-sampling"
    temp.mkdir(parents=True, exist_ok=True)
    audio_streams = [item for item in metadata.get("streams", []) if item.get("codec_type") == "audio"]
    audio_reserve = min(AUDIO_RESERVE, artifact_limit) if audio_streams else 0
    frame_slots = min(max(0, int(max_frames)), max(0, (output_limit - audio_reserve) // max(1, artifact_limit))) if artifact_limit else 0
    frame_cap = min(artifact_limit, (output_limit - audio_reserve) // max(1, frame_slots)) if frame_slots else 0

    if locate("ffmpeg"):
        if selected and frame_slots <= 0:
            warnings.append("Budget output insufficiente per estrarre frame video")
        if "extract_frames:last" in selected and frame_slots > 0:
            pattern = temp / "last-%03d.png"
            for stale in temp.glob("last-*.png"): stale.unlink(missing_ok=True)
            result = run_video(["ffmpeg", "-v", "error", "-sseof", "-1", "-i", str(path), "-frames:v", "1", "-fs", str(frame_cap), str(pattern)], cwd=temp)
            tools.append(result)
            produced = sorted(temp.glob("last-*.png"))[:1]
            complete = _command_complete(result)
            if not complete:
                warnings.append("Estrazione ultimo frame incompleta")
                for item in temp.glob("last-*.png"): item.unlink(missing_ok=True)
                produced = []
            for item in produced:
                data, warning = _read_artifact(item, frame_cap)
                item.unlink(missing_ok=True)
                if warning:
                    warnings.append(warning)
                    continue
                index = len(frames)
                record = {"frame_index": index, "timestamp": "last_second", "keyframe": False,
                          "sampling_mode": "extract_frames:last", "techniques": [], "flags": [],
                          "name": item.name, "data": data, "status": "extracted", "confidence": .98}
                frames.append({key: value for key, value in record.items() if key != "data"})
                artifacts.append(record); total_output += len(data)

        filters = []
        if "extract_frames:first" in selected: filters.append(("first", "select=eq(n\\,0)", 1))
        if "extract_frames:keyframes" in selected: filters.append(("keyframe", "select=eq(pict_type\\,I)", max_frames))
        if "extract_frames:every_n" in selected: filters.append(("sample", "select=not(mod(n\\,30))", max_frames))
        if "extract_frames:all_with_limit" in selected: filters.append(("limited", "select=lt(n\\,%d)" % max_frames, max_frames))
        remaining_frames = max(0, frame_slots - len(frames))
        for label, expression, requested in filters:
            if remaining_frames <= 0 or frame_cap <= 0: break
            count = min(requested, remaining_frames)
            pattern = temp / f"{label}-%03d.png"
            for stale in temp.glob(f"{label}-*.png"): stale.unlink(missing_ok=True)
            result = run_video(["ffmpeg", "-v", "error", "-i", str(path), "-vf", expression,
                                     "-vsync", "vfr", "-frames:v", str(count), "-fs", str(frame_cap),
                                     str(pattern)], cwd=temp)
            tools.append(result)
            produced = sorted(temp.glob(f"{label}-*.png"))[:count]
            if not _command_complete(result):
                warnings.append(f"Estrazione frame {label} incompleta")
                for item in temp.glob(f"{label}-*.png"): item.unlink(missing_ok=True)
                produced = []
            for item in produced:
                data, warning = _read_artifact(item, frame_cap)
                item.unlink(missing_ok=True)
                if warning:
                    warnings.append(warning)
                    continue
                index = len(frames)
                record = {"frame_index": index, "timestamp": None, "keyframe": label == "keyframe",
                          "sampling_mode": f"extract_frames:{label}", "techniques": [], "flags": [],
                          "name": item.name, "data": data, "status": "extracted", "confidence": .98}
                frames.append({key: value for key, value in record.items() if key != "data"})
                artifacts.append(record); total_output += len(data)
            remaining_frames -= len(produced)

        if audio_streams and total_output < output_limit:
            audio_cap = min(artifact_limit, output_limit - total_output)
            audio = temp / "audio.wav"
            audio.unlink(missing_ok=True)
            result = run_video(["ffmpeg", "-v", "error", "-i", str(path), "-map", "0:a:0?", "-vn",
                                     "-ac", "2", "-ar", "16000", "-acodec", "pcm_s16le", "-t", "30",
                                     "-fs", str(audio_cap), str(audio)], cwd=temp)
            tools.append(result)
            complete = _command_complete(result)
            if not complete:
                warnings.append("Estrazione audio incompleta")
                audio.unlink(missing_ok=True)
            if complete and audio.is_file():
                data, warning = _read_artifact(audio, audio_cap)
                audio.unlink(missing_ok=True)
                if warning: warnings.append(warning)
                elif data is not None:
                    artifacts.append({"name": "video-audio.wav", "data": data, "status": "extracted",
                                      "technique": "video_audio_stream", "confidence": .98})
                    total_output += len(data)
    else:
        warnings.append("ffmpeg non disponibile: frame e audio non estratti")
    return {"applicable": True, "metadata": metadata, "streams": metadata.get("streams", []),
            "chapters": metadata.get("chapters", []), "frames": frames, "artifacts": artifacts,
            "tools": tools, "warnings": warnings,
            "metrics": {"frames": len(frames), "bytes_exported": total_output,
                        "output_budget": output_limit, "frame_limit": frame_slots,
                        "per_artifact_limit": artifact_limit}}
