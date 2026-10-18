"""Encrypted-volume forensic analysis for the Forensic Hub.

The plugin prioritizes BitLocker/FVE and treats images as immutable evidence.
Automatic analysis stops at metadata, hash extraction and a password-free broker
request. Decryption happens only when explicit plugin options contain ``unlock``
and an ephemeral credential. Decrypted bytes are written to a separate bounded
artifact and analyzed read-only.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from app.core.plugin import BasePlugin

from .src.artifact_extractor import ArtifactStore,extract_interesting
from .src.bitlocker_detector import probe
from .src.bitlocker_metadata import analyze as analyze_metadata
from .src.bruteforce_bridge import build as build_unlock_request
from .src.confidence import volume_confidence
from .src.filesystem_detector import detect as detect_filesystem
from .src.flag_hunter import hunt as hunt_flags
from .src.graph_builder import build as build_graph,timeline as build_timeline
from .src.hash_extractor import extract as extract_hashes
from .src.image_reader import container_type,hashes,prepare
from .src.key_protectors import normalize as normalize_protectors
from .src.memory_fvek import is_memory_candidate,scan as scan_memory_fvek
from .src.partition_detector import inspect as inspect_partitions
from .src.password_handler import select as select_credential
from .src.read_only_mount import unlock
from .src.reporting import event,finding,section
from .src.security import is_safe_regular
from .src.tool_adapters import ToolRunner
from .src.volume_detector import detect as detect_volumes


class Plugin(BasePlugin):
    """Analyze local encrypted volumes, especially BitLocker, without mutation.

    Input is a regular Hub file. Output follows the normalized result contract.
    The parser works without optional binaries for RAW/MBR/GPT/FVE detection;
    pybde enriches metadata and can perform an explicitly requested export.
    """

    def can_handle(self,asset,context):
        """Score a bounded content view; extension contributes weak evidence."""
        path=Path(asset.get("path",""))
        if asset.get("type") not in {None,"file","disk_image","memory_dump","archive"} or not is_safe_regular(path):
            return {"compatible":False,"score":0,"reasons":["È richiesta un'immagine locale regolare"]}
        try:
            if is_memory_candidate(path):
                return {"compatible":True,"score":.91,"reasons":["Dump di memoria compatibile con la ricerca passiva di pool FVEK"]}
            return probe(path)
        except OSError as exc:return {"compatible":False,"score":0,"reasons":[f"Input non leggibile: {exc}"]}

    def validate(self,asset,context):
        """Reject empty files and symlinks before any parser or tool is invoked."""
        path=Path(asset.get("path",""));valid=is_safe_regular(path) and path.stat().st_size>=512
        return {"valid":valid,"reason":"Immagine vuota, simbolica o troppo corta" if not valid else ""}

    def analyze(self,asset,context,reporter):
        """Run identification, FVE parsing, hash extraction and optional unlock.

        Parser failures become warnings and preserve successful modules. Secrets
        exist only in local variables and are never added to the returned JSON.
        """
        started=time.monotonic();source=Path(asset["path"]);size=source.stat().st_size;declared_size=int(asset.get("size",size));input_partial=bool(asset.get("partial_input")) or declared_size>size
        options=context.get("plugin_options",{}).get("encrypted-volume-forensics",{})
        byte_budget=min(size,int(context.get("byte_budget",size)));output_budget=int(context.get("output_bytes",512*1024*1024))
        workspace=min(int(options.get("workspace_bytes",2*1024*1024*1024)),4*1024*1024*1024)
        runner=ToolRunner();warnings=[];errors=[];events=[];findings=[];artifacts=[];unlock_rows=[];filesystem_rows=[];deleted=[];ads=[]
        output=Path(context["output_dir"]);store=ArtifactStore(output,output_budget)

        reporter.phase("Input e hash");phase=time.monotonic();digest=hashes(source);kind=container_type(source)
        identity={"name":asset.get("name",source.name),"path_type":"local_regular_file","size":size,"declared_size":declared_size,"partial_input":input_partial,"container":kind,**digest,"original_modified":False}
        events.append(event("Input e hash",phase,"partial" if input_partial else "completed"));reporter.log("Hash completi calcolati in streaming; originale aperto in sola lettura")
        if input_partial:warnings.append(f"Input già parziale: vista montata {size} byte su asset dichiarato {declared_size}")

        memory_mode=asset.get("type")=="memory_dump" or source.suffix.casefold() in {".mem",".dmp",".vmem",".lime"}
        memory_keys=[]
        if memory_mode:
            reporter.phase("Ricerca FVEK in memoria");phase=time.monotonic();analysis_path=source
            image_info={"source_container":"memory_dump","analysis_path_is_original":True,"size":size,"source_size":size,"read_only":True}
            prepare_warnings=[];partitions=[];partition_result={"scheme":"memory","anomalies":[]};volumes=[];truncated=byte_budget<size
            candidates,memory_warnings=scan_memory_fvek(source,byte_budget,int(options.get("max_fvek_candidates",32)));warnings.extend(memory_warnings)
            for index,row in enumerate(candidates,1):
                payload=row.pop("payload")
                stored=store.save("memory-keys",f"memory-fvek-{index:02d}.fvek",payload,{"kind":"bitlocker_fvek","detected_type":"Dislocker FVEK key","source_offset":row["source_offset"],"extraction_method":row["layout"],"validated":False,"status":"candidate_requires_volume_validation"})
                artifacts.append(stored);memory_keys.append({**row,"artifact_id":stored["artifact_id"],"name":stored["name"]})
                findings.append(finding("memory_fvek_candidate","medium",row["confidence"],"Possibile FVEK BitLocker estratta da un pool kernel; richiede validazione sul volume",asset.get("name",source.name),row["source_offset"],[row["layout"],f"pool size {row['pool_size']}"]))
            events.append(event("Ricerca FVEK in memoria",phase,"partial" if truncated else "completed"));reporter.log(f"{len(memory_keys)} candidati FVEK deduplicati")
        else:
            reporter.phase("Preparazione immagine");phase=time.monotonic();analysis_path,image_info,prepare_warnings=prepare(source,output/"encrypted-volume-forensics"/"temporary",workspace,runner);warnings.extend(prepare_warnings)
            image_info.update({"size":analysis_path.stat().st_size,"source_size":size,"source_container":kind,"read_only":True})
            events.append(event("Preparazione immagine",phase,"partial" if prepare_warnings else "completed"))
            reporter.phase("Partition table");phase=time.monotonic();partition_result=inspect_partitions(analysis_path);partitions=partition_result["partitions"];warnings.extend(partition_result["anomalies"])
            events.append(event("Partition table",phase,"partial" if partition_result["anomalies"] else "completed"));reporter.log(f"Schema {partition_result['scheme']}; {len(partitions)} partizioni")
            reporter.phase("Rilevamento BitLocker");phase=time.monotonic();volumes,truncated=detect_volumes(analysis_path,partitions,min(byte_budget,analysis_path.stat().st_size));events.append(event("Rilevamento BitLocker",phase,"partial" if truncated else "completed"))
            if truncated:warnings.append(f"Scansione FVE limitata a {byte_budget} di {analysis_path.stat().st_size} byte")
            reporter.log(f"{len(volumes)} volumi BitLocker individuati")

        reporter.phase("Metadata FVE e key protector");phase=time.monotonic();metadata=[];copies=[];protectors=[]
        for volume in volumes:
            result=analyze_metadata(analysis_path,volume);result["metadata"]["confidence"]=volume_confidence(volume["validated"],result["metadata"].get("parser")=="pybde",len(result["copies"]));metadata.append(result["metadata"])
            copies.extend({**row,"volume_id":volume["id"]} for row in result["copies"]);protectors.extend({**row,"volume_id":volume["id"]} for row in normalize_protectors(result["protectors"]));warnings.extend(result["warnings"])
            findings.append(finding("bitlocker_volume","high",result["metadata"]["confidence"],f"Volume BitLocker a offset {volume['offset']}",asset.get("name",source.name),volume["offset"],volume["evidence"]))
            if volume.get("trailing_bytes"):
                findings.append(finding("data_after_logical_volume","medium",.9,f"{volume['trailing_bytes']} byte dopo la fine logica del volume",volume["id"],volume["offset"]+volume["length"]))
            if result["metadata"].get("metadata_copies_diverge"):findings.append(finding("metadata_mismatch","medium",.88,"Metadata FVE primari e backup divergenti",volume["id"],volume["offset"]))
        events.append(event("Metadata FVE e key protector",phase,"partial" if any("Parser libbde" in x for x in warnings) else "completed"))

        reporter.phase("Hash extraction e richieste");phase=time.monotonic();hash_artifacts=[];unlock_requests=[]
        if options.get("extract_hash",True):
            for volume in volumes:
                rows,hash_warnings=extract_hashes(analysis_path,volume,output/"encrypted-volume-forensics"/"temporary",store,runner,min(workspace,output_budget));hash_artifacts.extend(rows);warnings.extend(hash_warnings)
        artifacts.extend(hash_artifacts)
        for volume in volumes:
            related=[row for row in protectors if row["volume_id"]==volume["id"]]
            related_hashes=[row for row in hash_artifacts if row.get("parent_artifact_id")==volume["id"]]
            unlock_requests.append(build_unlock_request(volume,related_hashes,{**asset,"path":str(source)},related))
        hash_phase_status="skipped" if not options.get("extract_hash",True) else "partial" if volumes and not hash_artifacts else "completed"
        events.append(event("Hash extraction e richieste",phase,hash_phase_status))

        reporter.phase("Sblocco read-only");phase=time.monotonic();secret,method,credential_record=select_credential(options)
        key_candidates=[]
        if options.get("use_companion_keys",True):
            for companion in context.get("companion_assets",[]):
                path=Path(companion.get("path",""))
                if path.is_file() and path.stat().st_size==66 and path.read_bytes()[1:2]==b"\x80":key_candidates.append(path)
        attempts=[(secret,method)] if secret else []
        attempts.extend((str(path),"fvek") for path in key_candidates)
        if attempts and volumes:
          for candidate,candidate_method in attempts:
            volume=volumes[0];target=output/"encrypted-volume-forensics"/"temporary"/f"unlocked-volume-{len(unlock_rows)}.raw"
            attempt=unlock(analysis_path,volume,candidate,candidate_method,target,runner,min(output_budget-store.used,int(options.get("max_unlocked_bytes",output_budget))),str(options.get("unlock_engine","libbde")))
            secret=None;attempt={**attempt,"volume_id":volume["id"],"credential_type":candidate_method,"password_display":"********"};unlock_rows.append(attempt)
            if attempt["status"]=="success":
                unlocked=store.register_file("unlocked","unlocked-volume.raw",Path(attempt["path"]),{"kind":"decrypted_volume","detected_type":"filesystem image","parent_artifact_id":volume["id"],"extraction_method":attempt["method"],"password_verified":True,"writable":False})
                artifacts.append(unlocked);fs=detect_filesystem(Path(unlocked["path"]));fs["volume_id"]=volume["id"];fs["artifact_id"]=unlocked["artifact_id"];filesystem_rows.append(fs)
                extracted=extract_interesting(Path(unlocked["path"]),store,options.get("filesystem",{}))
                for child in extracted["artifacts"]:child["parent_artifact_id"]=unlocked["artifact_id"]
                artifacts.extend(extracted["artifacts"]);deleted.extend(extracted["deleted"]);ads.extend(extracted["ads"]);warnings.extend(extracted["warnings"])
                break
            elif attempt["status"] not in {"wrong_password","limit_reached"}:warnings.append(f"Sblocco: {attempt.get('reason',attempt['status'])}")
        elif options.get("unlock"):unlock_rows.append({"status":"wrong_password" if credential_record["status"]=="invalid_format" else "waiting_for_user","volume_id":volumes[0]["id"] if volumes else None,"password_display":credential_record.get("password_display")})
        events.append(event("Sblocco read-only",phase,"completed" if any(x["status"]=="success" for x in unlock_rows) else "skipped"))

        reporter.phase("Flag hunting");phase=time.monotonic();flags,flag_warnings=hunt_flags({**asset,"path":str(source)},context,asset.get("name",source.name));warnings.extend(flag_warnings)
        for row in artifacts:
            if row.get("kind") in {"password_hash"}:continue
            child={"id":row["artifact_id"],"name":row["name"],"type":"file","path":row["path"]};child_flags,child_warnings=hunt_flags(child,context,row["artifact_id"],row.get("parent_artifact_id"));flags.extend(child_flags);warnings.extend(child_warnings)
        unique={(row.get("value"),row.get("source_artifact"),row.get("offset")):row for row in flags};flags=list(unique.values())
        events.append(event("Flag hunting",phase));reporter.log(f"{len(flags)} candidate con provenance")

        graph=build_graph(asset,image_info,partitions,volumes,copies,protectors,hash_artifacts,unlock_rows,filesystem_rows,artifacts,flags)
        graph_visual={"type":"graph","title":"Encrypted Volume Structure","data":graph,"palette":"volume","options":{"interactive":True,"zoom":True,"pan":True,"tooltip":True}}
        partition_visual={"type":"offset_map","title":"Partition and Volume Map","data":[{"start":row["offset"],"end":row["offset"]+row["length"],"x":row["offset"],"y":row["length"],"label":row.get("name") or row.get("type"),"status":row["status"]} for row in partitions],"palette":"volume","options":{"interactive":True,"zoom":True,"tooltip":True}}
        timeline=build_timeline(events)
        timeline_visual={"type":"timeline","title":"Recovery Timeline","data":timeline,"palette":"volume","options":{"interactive":True,"zoom":True,"tooltip":True}}
        tools=runner.inventory(["dislocker","dislocker-file","bdeinfo","bdemount","bitlocker2john","john","hashcat","qemu-img","mmls","fls","icat","fsstat"])
        try:import pybde;tools.append({"tool":"pybde","available":True,"version":pybde.get_version()})
        except ImportError:tools.append({"tool":"pybde","available":False,"version":None})
        try:import pytsk3;tools.append({"tool":"pytsk3","available":True,"version":pytsk3.get_version()})
        except ImportError:tools.append({"tool":"pytsk3","available":False,"version":None})

        safe_artifacts=[{k:v for k,v in row.items() if k!="path"} for row in artifacts]
        metrics={"duration":round(time.monotonic()-started,4),"source_bytes":size,"declared_source_bytes":declared_size,"partial_input":input_partial,"bytes_scanned":min(byte_budget,analysis_path.stat().st_size),"partitions":len(partitions),"bitlocker_volumes":len(volumes),"memory_fvek_candidates":len(memory_keys),"metadata_copies":len(copies),"key_protectors":len(protectors),"hash_artifacts":len(hash_artifacts),"unlock_attempts":len(unlock_rows),"unlocked_volumes":sum(x["status"]=="success" for x in unlock_rows),"extracted_files":sum(x.get("kind") not in {"password_hash","bitlocker_fvek"} for x in artifacts),"flags":len(flags),"original_modified":False}
        sections=[section("file_identity","File Identity",10,[identity],kind="summary"),section("disk_image","Disk Image",20,[image_info]),section("memory_fvek","Memory FVEK Candidates",25,memory_keys,kind="artifact_list"),section("partition_table","Partition Table",30,partitions),section("volume_detection","Volume Detection",40,volumes),section("bitlocker_metadata","BitLocker Metadata",50,metadata,kind="details"),section("backup_metadata","Backup Metadata",60,copies),section("key_protectors","Key Protectors",70,protectors),section("encryption_method","Encryption Method",80,[{"volume_id":row["id"],"method":row.get("encryption_method"),"method_id":row.get("encryption_method_id"),"locked":row.get("locked",True)} for row in metadata]),section("hash_extraction","Hash Extraction",90,[{k:v for k,v in row.items() if k!="path"} for row in hash_artifacts],kind="artifact_list"),section("recovery_credentials","Recovery Credentials",100,[credential_record] if options.get("unlock") else []),section("bruteforce_requests","Bruteforce Requests",110,unlock_requests),section("unlock_attempts","Unlock Attempts",120,unlock_rows),section("read_only_access","Read-only Access",130,[row for row in safe_artifacts if row.get("kind")=="decrypted_volume"]),section("filesystem","Filesystem",140,filesystem_rows),section("extracted_files","Extracted Files",150,[row for row in safe_artifacts if row.get("kind") not in {"password_hash","decrypted_volume","bitlocker_fvek"}],kind="artifact_list"),section("deleted_files","Deleted Files",160,deleted),section("alternate_data_streams","Alternate Data Streams",170,ads),section("timeline","Timeline",180,timeline,kind="timeline",visualization=timeline_visual),section("graph","Graph",190,[graph_visual],kind="visualization_list",visualization=graph_visual),section("flag_candidates","Flag Candidates",200,flags),section("findings","Findings",210,findings),section("tools","Tools",890,tools+runner.audit),section("warnings","Warnings",900,warnings,kind="list"),section("errors","Errors",910,errors,kind="list"),section("metrics","Metrics",920,[metrics],kind="metrics")]
        # Warnings may come from hashing, filesystem extraction, flags or unlock
        # adapters as well as image preparation; expose every reduced phase.
        status="partial" if warnings or truncated or input_partial or (volumes and not metadata) else "completed"
        summary=(f"{len(memory_keys)} candidati FVEK da memoria" if memory_mode else f"{len(volumes)} volumi BitLocker, {len(protectors)} protector, {len(hash_artifacts)} hash, {metrics['unlocked_volumes']} sbloccati")
        result={"plugin_id":"encrypted-volume-forensics","status":status,"summary":summary,"confidence":max((row.get("confidence",0) for row in metadata),default=.2),"phase":"encrypted volume forensics","findings":findings,"sections":sections,"artifacts":artifacts,"derived_assets":[],"visualizations":[partition_visual,graph_visual,timeline_visual],"flags":flags,"timeline":timeline,"execution_events":events,"logs":runner.audit,"warnings":warnings,"errors":errors,"metrics":metrics,"unlock_requests":unlock_requests,"requested_plugins":[]}
        report=json.dumps({**result,"artifacts":safe_artifacts,"logs":[{**row,"stdout":"","stderr":""} for row in runner.audit]},ensure_ascii=False,indent=2).encode()
        try:result["artifacts"].append(store.save("report","encrypted-volume-forensics-report.json",report,{"kind":"json_report","detected_type":"JSON","parent_artifact_id":asset.get("id")}))
        except ValueError as exc:result["warnings"].append(str(exc));result["status"]="partial"
        reporter.partial(result);return result

    def extract_artifacts(self,asset,context,reporter=None):
        """Artifacts are created during analysis so exact provenance is retained."""
        return []
    def create_assets(self,asset,context,reporter=None):
        """The Hub promotes normalized artifacts to derived assets centrally."""
        return []
    def create_visualizations(self,result,context):
        """Return already declarative and engine-compatible visuals."""
        return result.get("visualizations",[])
    def search_flags(self,result,context):
        """Return candidates already enriched with volume provenance."""
        return result.get("flags",[])
    def cleanup(self,context):
        """No mount is created; the Hub owns cleanup of the isolated workspace."""
        return None
