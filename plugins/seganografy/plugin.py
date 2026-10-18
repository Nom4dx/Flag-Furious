"""Steganography Forensics plugin orchestration for Forensic Hub.

All analyzers operate on a read-only sandbox path. The orchestration distinguishes
statistical detection, byte extraction and successful interpretation, preserving
unknown payloads as derived artifacts with provenance instead of discarding them.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path

from app.core.plugin import BasePlugin

from .src import audio_steg, binary_steg, document_steg, image_steg, metadata_steg, text_steg, unicode_steg, video_steg, whitespace_steg
from .src.carving import carve
from .src.container_extract import ArtifactStore, extract_zip
from .src.core import AnalysisState
from .src.external_tools import inspect_file, steg_detectors
from .src.file_identity import identify
from .src.flag_hunter import hunt
from .src.graph_builder import build as build_graph
from .src.limits import Limits
from .src.recursive_pipeline import decode_recursive, detect_type
from .src.reporting import finding, section
from .src.safe_subprocess import ALLOWLIST, locate
from .src.signatures import SIGNATURES, scan, validate_candidates


IMAGE_FORMATS={"png","jpeg","gif","bmp","tiff","webp","avif","heic","svg","psd","raw_image"}
AUDIO_FORMATS={"wav","au","aiff","flac","mp3","ogg","opus","m4a"}
VIDEO_FORMATS={"mp4","mkv","avi","mov","webm","mpeg"}
TYPE_DETECTION_BYTES=1024*1024


class Plugin(BasePlugin):
    """Analyze text, Unicode, images, audio, video, documents and containers.

    Inputs are hub assets mounted read-only. Output is normalized JSON plus files
    under the isolated output directory. Recoverable parser/tool errors produce a
    partial result. Limits: manifest/context budgets. Security: no macro, script,
    active document, embedded executable or external link is run. Example: select
    “Steganography Forensics” for a PNG, WAV, document or text asset.
    """

    def can_handle(self, asset, context):
        """Score a file from at most 64 KiB without claiming steganography.

        Known signatures and textual invisible/control characters increase routing
        confidence. Generic regular files remain compatible at a lower score so an
        operator can explicitly request analysis.
        """
        path=asset.get("path")
        if not path or asset.get("type") not in {None,"file","archive","text","json","structured","disk_image"}:
            return {"compatible":False,"score":0,"reasons":["Asset non file/testo"]}
        try:
            with Path(path).open("rb") as stream:data=stream.read(65536)
        except OSError as exc:return {"compatible":False,"score":0,"reasons":[f"Input non leggibile: {exc}"]}
        hits=[signature.format for signature in SIGNATURES if signature.marker in data]
        text=data.decode("utf-8","ignore");invisible=any(char in text for char in "\u200b\u200c\u200d\u2060\u202e\ufeff")
        reasons=[]
        if hits:reasons.append("Firme candidate: "+", ".join(sorted(set(hits))[:6]))
        if invisible:reasons.append("Caratteri Unicode invisibili o bidi nella vista limitata")
        if asset.get("type") in {"text","json","structured"}:reasons.append("Asset testuale o strutturato")
        score=.96 if invisible else .9 if hits else .72 if reasons else .52
        return {"compatible":True,"score":score,"reasons":reasons or ["Analisi steganografica generale disponibile"]}

    def validate(self, asset, context):
        """Require a regular non-symlink file while preserving it immutably."""
        path=Path(asset.get("path", ""));valid=bool(asset.get("path") and path.is_file() and not path.is_symlink())
        return {"valid":valid,"reason":"È richiesto un file regolare non simbolico" if not valid else ""}

    def analyze(self, asset, context, reporter):
        """Run the complete modular, bounded steganography pipeline.

        Each phase is isolated through :class:`AnalysisState`; byte candidates keep
        their technique/configuration through extraction, recursive decoding, flag
        hunting and graph generation. The returned object is JSON serializable.
        """
        started=time.monotonic();path=Path(asset["path"]);name=asset.get("name",path.name);limits=Limits.from_context(context);state=AnalysisState();store=ArtifactStore(Path(context["output_dir"]),limits)
        physical_size=path.stat().st_size;declared_size=int(asset.get("size",physical_size));input_partial=bool(asset.get("partial_input")) or declared_size>physical_size
        byte_budget=min(physical_size,limits.byte_budget);analysis_cap=min(byte_budget,64*1024*1024)
        with path.open("rb") as stream:data=stream.read(analysis_cap)

        identity=state.run("Hash e identificazione reale",reporter,lambda:identify(path,name,byte_budget,limits.max_entropy_scan_size,limits.timeout_per_stage,limits.max_tool_output),default={})
        source_sha=identity.get("hashes",{}).get("sha256",hashlib.sha256(data).hexdigest())
        hits,scan_partial=state.run("Inventario strutturale",reporter,lambda:scan(path,byte_budget),default=([],True))
        formats,rejected=state.run("Validazione firme e confini",reporter,lambda:validate_candidates(path,hits,path.stat().st_size,byte_budget),default=([],hits))
        detected={item["format"] for item in formats};binary=state.run("Analisi binaria e container",reporter,lambda:binary_steg.analyze(path,data,identity,hits,formats,rejected),default={})
        for raw in binary.get("findings",[]):state.findings.append(self._normalize_finding(raw,name,source_sha,len(state.findings)+1))

        text_result={"applicable":False};unicode_result={"applicable":False};whitespace_result={"applicable":False}
        text_value=data.decode("utf-8","replace")
        text_applicable=asset.get("type") in {"text","json","structured"} or identity.get("declared_mime","").startswith("text/") or (data and data.count(0)/len(data)<.01 and sum(byte in b"\t\r\n" or 32<=byte<127 or byte>=128 for byte in data)/len(data)>.72)
        if text_applicable:
            text_result=state.run("Steganografia testuale",reporter,lambda:text_steg.analyze(text_value,name),default={"applicable":False})
            text_result["applicable"]=True
            unicode_result=state.run("Unicode e ordine visuale",reporter,lambda:unicode_steg.analyze(text_value,name,source_sha),default={"applicable":False});unicode_result["applicable"]=True
            whitespace_result=state.run("Whitespace steganography",reporter,lambda:whitespace_steg.analyze(text_value,name),default={"applicable":False});whitespace_result["applicable"]=True
            if unicode_result.get("suspicious"):
                state.findings.append(finding("unicode-summary","unicode_anomalies",f"{len(unicode_result['suspicious'])} codepoint invisibili, controlli o confusabili",severity="medium",confidence=.78,source_file=name,source_sha256=source_sha,technique="unicode_inventory",evidence=["inventario Unicode con offset UTF-8"]))
            if unicode_result.get("visual_logical_difference_possible"):
                state.findings.append(finding("unicode-bidi","bidirectional_visual_order", "Controlli bidi possono alterare l’ordine visuale rispetto a quello logico",severity="high",confidence=.95,source_file=name,source_sha256=source_sha,technique="trojan_source",evidence=["codepoint bidi esplicito"]))
            if unicode_result.get("mixed_script"):
                state.findings.append(finding("unicode-mixed","mixed_script_homoglyph",f"{len(unicode_result['mixed_script'])} token mixed-script",severity="medium",confidence=.72,source_file=name,source_sha256=source_sha,technique="uts39_mixed_script"))

        image_result={"applicable":False,"candidates":[],"artifacts":[],"visualizations":[],"tools":[],"warnings":[]}
        if detected&IMAGE_FORMATS or identity.get("declared_mime","").startswith("image/"):
            image_result=state.run("Steganografia immagini",reporter,lambda:image_steg.analyze(path,context.get("mode","balanced"),limits.max_decoder_attempts,limits.max_single_artifact_size,limits.timeout_per_stage,limits.max_tool_output),default=image_result)
        audio_result={"applicable":False,"candidates":[],"artifacts":[],"visualizations":[],"warnings":[]}
        if detected&AUDIO_FORMATS or identity.get("declared_mime","").startswith("audio/"):
            audio_result=state.run("Steganografia audio",reporter,lambda:audio_steg.analyze(path,limits.max_single_artifact_size,limits.max_decoder_attempts),default=audio_result)
        video_result={"applicable":False,"frames":[],"artifacts":[],"tools":[],"warnings":[]}
        if detected&VIDEO_FORMATS or identity.get("declared_mime","").startswith("video/"):
            options=context.get("plugin_options",{}).get("seganografy",{})
            video_result=state.run("Steganografia video",reporter,lambda:video_steg.analyze(path,Path(context["output_dir"])/"video-work",limits.max_video_frames,limits.timeout_per_stage,limits.max_tool_output,options.get("video_modes")),default=video_result)

        document_result=state.run("Documenti e contenuti nascosti",reporter,lambda:document_steg.analyze(data,detected,name),default={"items":[],"findings":[],"embedded":[],"warnings":[]})
        for raw in document_result.get("findings",[]):state.findings.append(self._normalize_finding(raw,name,source_sha,len(state.findings)+1))
        metadata_result=state.run("Metadata steganography",reporter,lambda:metadata_steg.analyze(path,data,formats,limits.timeout_per_stage,limits.max_tool_output),default={"items":[],"warnings":[],"tools":[]})

        reporter.phase("Estrazione candidati e container");reporter.log("Scrittura soltanto nella directory derivata del caso")
        artifacts,carve_warnings=carve(path,formats,store,path.stat().st_size);state.artifacts.extend(artifacts);state.warnings.extend(carve_warnings)
        for item in [*image_result.get("artifacts",[]),*audio_result.get("artifacts",[]),*video_result.get("artifacts",[])]:
            self._save_generated(store,state,item,"media",name)
        if unicode_result.get("suspicious"):
            for variant_name,variant_data in unicode_result.get("variants",{}).items():self._save_generated(store,state,{"name":variant_name,"data":variant_data,"technique":"unicode_derived_view","status":"extracted"},"unicode",name)
        for fmt in formats:
            if fmt["format"]!="zip" or fmt["length"]>limits.max_single_artifact_size:continue
            with path.open("rb") as stream:stream.seek(fmt["start_offset"]);archive_data=stream.read(fmt["length"])
            archive=state.run(f"Estrazione ZIP @{fmt['start_offset']}",reporter,lambda raw=archive_data,format_id=fmt["id"]:extract_zip(raw,store,limits,name,format_id),default={"entries":[],"artifacts":[],"warnings":["Estrazione ZIP fallita"]})
            state.artifacts.extend(archive.get("artifacts",[]));state.warnings.extend(archive.get("warnings",[]))

        seeds=[{"data":data,"source":name,"technique":"raw_input","confidence":.5}]
        for candidate in text_result.get("candidates",[]):seeds.append({"data":candidate["value"].encode(),"source":name,"technique":candidate["technique"],"confidence":candidate["confidence"]})
        for candidate in unicode_result.get("symbol_channels",[]):seeds.append({"data":candidate["output"],"source":name,"technique":candidate["technique"],"decoder_chain":[candidate["technique"]],"confidence":candidate["confidence"]})
        for candidate in whitespace_result.get("candidates",[]):seeds.append({"data":candidate["output"],"source":name,"technique":candidate["technique"],"decoder_chain":[candidate["technique"]],"confidence":candidate["confidence"]})
        for candidate in [*image_result.get("candidates",[]),*audio_result.get("candidates",[])]:seeds.append({"data":candidate["data"],"source":name,"technique":candidate["technique"],"confidence":candidate["confidence"]})
        unique_artifacts={}
        for artifact in state.artifacts:unique_artifacts.setdefault(artifact.get("sha256",artifact.get("path")),artifact)
        state.artifacts=list(unique_artifacts.values())
        for artifact in state.artifacts:
            try:
                artifact_path=Path(artifact["path"]);artifact_size=artifact_path.stat().st_size
                with artifact_path.open("rb") as source:raw=source.read(TYPE_DETECTION_BYTES)
                kind=detect_type(raw);artifact["detected_type"]=kind;artifact["type_detection_bytes"]=len(raw)
                if artifact_size>len(raw):
                    artifact["type_detection_partial"]=True
                    state.warnings.append(f"Tipo dell'artefatto {artifact.get('name')} valutato sui primi {len(raw)} byte")
                if kind=="application/octet-stream":
                    artifact["status"]="extracted_uninterpreted";state.findings.append(finding(f"uninterpreted-{len(state.findings)+1}","extracted_payload_uninterpreted","Payload estratto correttamente ma non decodificato",severity="medium",confidence=float(artifact.get("confidence",.75)),status="extracted_uninterpreted",source_file=name,source_sha256=source_sha,artifact_sha256=artifact["sha256"],technique=artifact.get("technique","extraction")))
                seeds.append({"data":raw,"source":artifact["name"],"technique":artifact.get("technique","artifact"),"confidence":artifact.get("confidence",.8),"artifact_sha256":artifact["sha256"]})
            except OSError as exc:state.warnings.append(f"Lettura artefatto {artifact.get('name')}: {exc}")

        decoded=state.run("Decodifica ricorsiva",reporter,lambda:decode_recursive(seeds,limits,context.get("prefixes",[])),default=[])
        for item in decoded:
            meaningful=item["detected_type"]!="application/octet-stream" or item["printable_ratio"]>.7
            if meaningful:self._save_generated(store,state,{"name":f"decoded-{len(state.artifacts)+1}.bin","data":item["data"],"technique":" → ".join(item["decoder_chain"]),"decoder_chain":item["decoder_chain"],"status":"decoded","confidence":item["confidence"],"detected_type":item["detected_type"]},"decoded",item["source"])

        flag_sources=[{"data":data,"source":name,"offset":0,"technique":"raw","confidence":.6}]
        for seed in seeds:flag_sources.append({"data":seed["data"],"source":seed["source"],"technique":seed["technique"],"confidence":seed.get("confidence",.5),"artifact_sha256":seed.get("artifact_sha256"),"decoder_chain":seed.get("decoder_chain",[])})
        for item in decoded:flag_sources.append({"data":item["data"],"source":item["source"],"technique":item["technique"],"confidence":item["confidence"],"decoder_chain":item["decoder_chain"],"artifact_sha256":item.get("artifact_sha256")})
        state.flags=hunt(flag_sources,context.get("prefixes",[]),context.get("patterns",[]),context.get("max_flags",256))

        state.tools.extend(inspect_file(path,limits.timeout_per_stage,limits.max_tool_output));state.tools.extend(metadata_result.get("tools",[]));state.tools.extend(image_result.get("tools",[]));state.tools.extend(video_result.get("tools",[]))
        if detected:
            state.tools.extend(steg_detectors(path,next(iter(detected)),limits.timeout_per_stage,limits.max_tool_output,context.get("plugin_options",{}).get("seganografy",{}).get("password")))
        tool_inventory=[{"tool":tool,"available":bool(locate(tool)),"status":"detected" if locate(tool) else "not_applicable"} for tool in sorted(ALLOWLIST)]
        graph=build_graph(name,source_sha,formats,state.artifacts,decoded,state.flags);graph_spec={"type":"graph","title":"Grafo artefatti e decoder","data":graph,"palette":"signal","options":{"interactive":True,"zoom":True,"pan":True,"tooltip":True}}
        offset_spec={"type":"offset_map","title":"Mappa strutture e payload","data":[{"x":x["start_offset"],"y":x["length"],"label":x["format"],"confidence":x["confidence"]} for x in formats],"encoding":{"x":{"field":"x","type":"number"},"y":{"field":"y","type":"number"}},"palette":"signal","options":{"interactive":True,"zoom":True,"tooltip":True}}
        state.visualizations=[offset_spec,graph_spec,*image_result.get("visualizations",[]),*audio_result.get("visualizations",[])]
        state.warnings.extend([*document_result.get("warnings",[]),*metadata_result.get("warnings",[]),*image_result.get("warnings",[]),*audio_result.get("warnings",[]),*video_result.get("warnings",[])])
        if scan_partial:state.warnings.append("Inventario firme limitato dal byte budget o dal numero massimo di risultati")
        if byte_budget<physical_size:state.warnings.append(f"Vista limitata a {byte_budget} di {physical_size} byte")
        if input_partial:state.warnings.append(f"Input già parziale: vista montata {physical_size} byte su asset dichiarato {declared_size}")
        for candidate in image_result.get("candidates",[]):state.findings.append(finding(f"image-{len(state.findings)+1}","image_steg_candidate",f"Candidato {candidate['technique']} {candidate.get('channels','')}",confidence=candidate["confidence"],status=candidate["status"],source_file=name,source_sha256=source_sha,technique=candidate["technique"],evidence=[f"printable ratio {candidate['printable_ratio']}",f"config: bits={candidate.get('bits')} channels={candidate.get('channels')} order={candidate.get('order')} bit_order={candidate.get('bit_order')}"]))
        for candidate in audio_result.get("candidates",[]):state.findings.append(finding(f"audio-{len(state.findings)+1}","audio_steg_candidate",f"PCM bit plane canale {candidate['channel']} bit {candidate['bit']}",confidence=candidate["confidence"],status=candidate["status"],source_file=name,source_sha256=source_sha,technique=candidate["technique"]))

        uninterpreted=[{k:v for k,v in item.items() if k!="path"} for item in state.artifacts if item.get("status")=="extracted_uninterpreted"]
        public_decoded=[self._public(item) for item in decoded]
        sections=[
            section("file_identity","File Identity",10,[identity]),
            section("detection_summary","Detection Summary",20,[{"validated_formats":formats,"signature_count":len(hits),"rejected_count":len(rejected),"text_applicable":text_applicable,"image_applicable":image_result.get("applicable",False),"audio_applicable":audio_result.get("applicable",False),"video_applicable":video_result.get("applicable",False)}]),
            section("text_steganography","Text Steganography",30,self._public(text_result)),
            section("unicode_inventory","Unicode Inventory",40,self._public(unicode_result)),
            section("whitespace_analysis","Whitespace Analysis",50,self._public(whitespace_result)),
            section("image_steganography","Image Steganography",60,self._public(image_result)),
            section("audio_steganography","Audio Steganography",70,self._public(audio_result)),
            section("video_steganography","Video Steganography",80,self._public(video_result)),
            section("document_steganography","Document Steganography",90,document_result),
            section("binary_container_analysis","Binary and Container Analysis",100,binary),
            section("external_tools","External Tools",110,{"inventory":tool_inventory,"executions":state.tools}),
            section("decoder_chains","Decoder Chains",120,public_decoded),
            section("extracted_artifacts","Extracted Artifacts",130,[{k:v for k,v in item.items() if k!="path"} for item in state.artifacts]),
            section("uninterpreted_artifacts","Uninterpreted Artifacts",140,uninterpreted,"partial" if uninterpreted else "completed"),
            section("flags","Flags",150,state.flags),section("findings","Findings",160,state.findings),
            section("execution_graph","Execution Graph",170,[graph_spec],visualization=graph_spec),
            section("warnings","Warnings",180,state.warnings,"partial" if state.warnings else "completed"),section("errors","Errors",190,state.errors),
        ]
        status="partial" if state.warnings or state.errors or input_partial else "completed";metrics={"duration":round(time.monotonic()-started,4),"bytes_read":analysis_cap,"declared_input_bytes":declared_size,"partial_input":input_partial,"bytes_hashed":identity.get("bytes_hashed",0),"signature_hits":len(hits),"validated_formats":len(formats),"findings":len(state.findings),"artifacts":len(state.artifacts),"decoder_results":len(decoded),"flags":len(state.flags),"external_tools_run":len(state.tools),"original_modified":False}
        sections.append(section("metrics","Metrics",200,metrics))
        result={"summary":f"{len(state.findings)} finding, {len(state.artifacts)} artefatti, {len(state.flags)} flag candidate","status":status,"confidence":max([x.get("confidence",0) for x in state.findings+state.flags] or [.25]),"phase":"steganography forensics","findings":state.findings,"sections":sections,"artifacts":state.artifacts,"derived_assets":[],"visualizations":state.visualizations,"flags":state.flags,"timeline":[],"execution_events":state.events,"logs":[],"warnings":state.warnings,"errors":state.errors,"metrics":metrics}
        encrypted=[member for fmt in formats for member in fmt.get("details",{}).get("encrypted",[])]
        if encrypted:
            from app.core.unlock_requests import request as unlock_request
            result["unlock_requests"]=[unlock_request(asset.get("id",""),"zipcrypto","seganografy",["zip_adapter"],members=encrypted)]
        reporter.phase("Report");reporter.log("Serializzazione del report senza contenuti binari inline")
        try:
            report=json.dumps({k:v for k,v in result.items() if k not in {"artifacts"}},ensure_ascii=False,indent=2).encode();result["artifacts"].append(store.save("report","report.json",report,{"technique":"report","detected_type":"json","status":"decoded","confidence":1.0}))
        except (ValueError,TypeError) as exc:result["warnings"].append(f"Report: {exc}");result["status"]="partial"
        reporter.partial(result);return result

    def extract_artifacts(self, asset, context, reporter):
        """Return no second-pass artifacts; ``analyze`` already emits all files."""
        return []

    def create_assets(self, asset, context, reporter):
        """Return no duplicate assets; hub registers emitted artifacts recursively."""
        return []

    def create_visualizations(self, result, context):
        """Return no duplicate charts; analysis already uses the central engine."""
        return []

    def search_flags(self, result, context):
        """Return no duplicate flags; analysis already records provenance chains."""
        return []

    def cleanup(self, context):
        """Remove unregistered media scratch directories inside the workspace.

        Registered artifact files are preserved until the worker packs them. The
        sandbox namespace guarantees cleanup after termination as a second layer.
        """
        scratch=Path(context.get("output_dir","/work"))/"video-work"
        if scratch.exists():shutil.rmtree(scratch,ignore_errors=True)

    @staticmethod
    def _save_generated(store: ArtifactStore, state: AnalysisState, item: dict, category: str, source: str):
        """Persist a generated byte candidate and retain its technique/config."""
        raw=item.get("data")
        if not isinstance(raw,bytes):return
        metadata={k:v for k,v in item.items() if k!="data"};metadata.setdefault("source_file",source)
        try:
            saved=store.save(category,item.get("name",f"payload-{len(state.artifacts)+1}.bin"),raw,metadata)
            if not any(existing.get("sha256")==saved.get("sha256") for existing in state.artifacts):state.artifacts.append(saved)
        except ValueError as exc:state.warnings.append(str(exc))

    @staticmethod
    def _public(value):
        """Recursively remove raw byte fields while preserving every other field."""
        if isinstance(value,dict):return {key:Plugin._public(item) for key,item in value.items() if key not in {"data","output","variants"}}
        if isinstance(value,list):return [Plugin._public(item) for item in value]
        if isinstance(value,bytes):return {"length":len(value),"sha256":hashlib.sha256(value).hexdigest()}
        return value

    @staticmethod
    def _normalize_finding(raw: dict, source: str, digest: str, index: int) -> dict:
        """Normalize analyzer-specific findings into the common provenance shape."""
        return finding(str(raw.get("id",f"finding-{index}")),raw.get("type","steganography_indicator"),raw.get("message",raw.get("description",raw.get("type","Indicatore rilevato"))),severity=raw.get("severity","medium"),confidence=float(raw.get("confidence",.5)),status=raw.get("status","detected"),source_file=source,source_sha256=digest,offset=raw.get("offset"),length=raw.get("length"),technique=raw.get("technique",raw.get("type")),evidence=raw.get("evidence",[]),**{k:v for k,v in raw.items() if k not in {"id","type","message","description","severity","confidence","status","offset","length","technique","evidence"}})
