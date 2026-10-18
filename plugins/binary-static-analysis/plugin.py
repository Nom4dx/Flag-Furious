"""Binary Static Analysis orchestration for Forensic Hub.

The plugin treats executables, firmware and raw binaries as passive evidence. It
coordinates bounded independent parsers, retains rejected signature hits, carves
only validated ranges, and distinguishes format recognition, validation,
extraction, code identification and suspicious indicators in its output.
"""

from __future__ import annotations

from pathlib import Path
import json
import time

from app.core.flag_detector import search as global_flag_search
from app.core.plugin import BasePlugin

from .src.archive_analyzer import analyze_zip
from .src.artifact_manager import ArtifactManager
from .src.bruteforce_bridge import requests_from
from .src.carving import carve
from .src.coff_analyzer import analyze as analyze_coff
from .src.compression_detector import detect as detect_compression
from .src.crypto_detector import detect as detect_crypto
from .src.disassembler import disassemble
from .src.elf_analyzer import analyze as analyze_elf
from .src.entropy_analyzer import scan as scan_entropy, shannon
from .src.file_identity import identify
from .src.function_analyzer import analyze as analyze_functions
from .src.graph_builder import code as code_graph, structure as structure_graph
from .src.import_export_analyzer import enrich as enrich_imports
from .src.macho_analyzer import analyze as analyze_macho
from .src.magic_detection import scan as scan_magic, validate as validate_magic
from .src.overlay_analyzer import analyze as analyze_overlay
from .src.pe_analyzer import analyze as analyze_pe
from .src.raw_binary import analyze as analyze_raw
from .src.reporting import finding, section
from .src.strings_analyzer import extract as extract_strings, hex_rows
from .src.tool_adapters import ToolRunner
from .src.yara_analyzer import scan as scan_yara


class Plugin(BasePlugin):
    """Analyze local binary evidence statically without executing any bytes.

    The Hub mounts the input read-only and an isolated output directory writable.
    Parser failures remain local to their phase. Optional tools and Python modules
    enrich results but are never required for identity, formats, strings, entropy,
    carving or graphs. Example: run on ``firmware.bin`` or an ELF renamed ``.dat``.
    """

    def can_handle(self, asset, context):
        """Score a file from at most 64 KiB, magic and binary characteristics.

        Extensions contribute only weak evidence. Textual files without a binary
        marker are refused. The method does not hash or scan the full input.
        """
        path=Path(asset.get("path", ""))
        if asset.get("type") not in {"file","archive","disk_image","memory_dump","firmware"} or not path.is_file() or path.is_symlink():
            return {"compatible":False,"score":0,"reasons":["È richiesto un asset file binario regolare"]}
        try:
            with path.open("rb") as source:data=source.read(65536)
        except OSError as exc:return {"compatible":False,"score":0,"reasons":[f"Input non leggibile: {exc}"]}
        markers=[]
        from .src.format_registry import SIGNATURES
        for signature in SIGNATURES:
            position=data.find(signature.value)
            if position>=0 and position-signature.relative_offset>=0:markers.append((signature.name,position-signature.relative_offset))
        binary_ratio=sum(value==0 or value<9 or 13<value<32 for value in data)/max(1,len(data))
        extension=path.suffix.casefold();reasons=[]
        if markers:reasons.extend(f"Firma {name} a offset {offset}" for name,offset in markers[:5])
        if binary_ratio>.08:reasons.append(f"Contenuto binario {binary_ratio:.0%}")
        if extension in {".bin",".elf",".so",".o",".ko",".exe",".dll",".sys",".efi",".rom",".img",".fw",".firmware",".class",".wasm",".core",".dump"}:reasons.append("Estensione binaria come indizio secondario")
        compatible=bool(markers or binary_ratio>.08 or extension==".bin")
        score=.97 if any(offset==0 for _,offset in markers) else .84 if markers else .68 if binary_ratio>.08 else .52
        return {"compatible":compatible,"score":score if compatible else 0,"reasons":reasons or ["Nessuna evidenza binaria sufficiente"]}

    def validate(self, asset, context):
        """Require a non-symlink regular file with at least one byte."""
        path=Path(asset.get("path", ""));valid=bool(asset.get("path") and path.is_file() and not path.is_symlink() and path.stat().st_size>0)
        return {"valid":valid,"reason":"File vuoto, simbolico o non regolare" if not valid else ""}

    def analyze(self, asset, context, reporter):
        """Run all bounded phases and return the normalized Hub result.

        Input and context come from the isolated worker. Recoverable parser/tool
        errors become warnings and ``partial`` only when they reduce requested
        coverage. Extracted bytes are never opened as code in this process.
        """
        started=time.monotonic();path=Path(asset["path"]);physical=path.stat().st_size
        budget=min(physical,int(context.get("byte_budget",physical)));output_budget=int(context.get("output_bytes",256*1024*1024))
        options=context.get("plugin_options",{}).get("binary-static-analysis",{});warnings=[];errors=[];events=[];runner=ToolRunner()
        input_partial=bool(asset.get("partial_input")) or int(asset.get("size",physical))>physical
        if input_partial:warnings.append(f"Input già parziale: vista montata {physical} byte su asset dichiarato {asset.get('size',physical)}")

        reporter.phase("Input e hash");phase=time.monotonic();identity=identify(path,asset,runner);events.append(self._event("Input e hash",phase,"completed"));reporter.log("Hash completi calcolati in streaming; originale aperto in sola lettura")
        if budget<physical:warnings.append(f"Analisi strutturale limitata a {budget} di {physical} byte")

        reporter.phase("Identificazione formato");phase=time.monotonic();candidates,truncated=scan_magic(path,budget);validated,rejected=validate_magic(path,candidates,budget);events.append(self._event("Identificazione formato",phase,"partial" if truncated else "completed"));reporter.log(f"{len(candidates)} firme, {len(validated)} strutture validate, {len(rejected)} firme respinte")
        if truncated:warnings.append("Inventario firme limitato dal byte budget o dal numero massimo di risultati")

        reporter.phase("Analisi strutturale");phase=time.monotonic();parsed=None;parser_error=None
        primary_candidates=[item for item in validated if item["start_offset"]==0]
        primary_format=primary_candidates[0]["format"] if primary_candidates else "raw"
        try:
            if any(item["validator"]=="elf" for item in primary_candidates):parsed=analyze_elf(path,budget)
            elif any(item["validator"]=="pe" for item in primary_candidates):parsed=analyze_pe(path,budget)
            elif any(item["validator"]=="macho" for item in primary_candidates):parsed=analyze_macho(path,budget)
            elif any(item["validator"]=="coff" for item in primary_candidates):parsed=analyze_coff(path,budget)
        except (OSError,ValueError) as exc:
            parser_error=str(exc);warnings.append(f"Parser strutturale primario: {exc}")
        with path.open("rb") as source:prefix=source.read(min(budget,16*1024*1024))
        raw_analysis=analyze_raw(prefix) if not parsed else {"regions":[],"integer_candidates":[],"classification":"not_applicable"}
        events.append(self._event("Analisi strutturale",phase,"partial" if parser_error else "completed"))

        reporter.phase("Stringhe ed entropia");phase=time.monotonic();strings=self._strings(path,budget);entropy=scan_entropy(path,budget);events.append(self._event("Stringhe ed entropia",phase,"partial" if entropy.get("truncated") or len(strings)>=5000 else "completed"));reporter.log(f"{len(strings)} stringhe, entropia globale {entropy['global']}")
        if entropy.get("truncated"):warnings.append("Entropia limitata dal byte budget o dal massimo di finestre")
        if len(strings)>=5000:warnings.append("Estrazione stringhe fermata a 5.000 risultati")
        findings=list(parsed.get("findings",[]) if parsed else [])
        for row in strings:
            if row.get("category") in {"command_string","possible_credential","url","ip_address"}:
                severity="medium" if row["category"] in {"command_string","possible_credential"} else "info"
                findings.append(finding("possible_network_indicator" if row["category"] in {"url","ip_address"} else row["category"],severity,.72,f"Stringa classificata come {row['category']}",row["offset"],row.get("section"),[row["value"][:240]]))
        if entropy["global"]>7.4:findings.append(finding("high_entropy_region","low",.48,"Entropia globale elevata; può derivare da compressione, cifratura o dati casuali"))
        compression=detect_compression(validated,entropy)

        reporter.phase("Overlay, embedded e carving");phase=time.monotonic();store=ArtifactManager(Path(context["output_dir"]),output_budget);artifacts,carve_warnings=carve(path,validated,store,physical);warnings.extend(carve_warnings)
        archive_rows=[]
        for item in [value for value in validated if value["format"]=="zip"]:
            try:
                archive=analyze_zip(path,item,store);archive_rows.extend(archive["entries"]);artifacts.extend(archive["artifacts"]);warnings.extend(archive["warnings"])
            except (OSError,ValueError) as exc:warnings.append(f"Archivio ZIP @{item['start_offset']}: {exc}")
        primary_view=parsed or ({"logical_end":primary_candidates[0]["end_offset"]} if primary_candidates else None)
        overlays=analyze_overlay(physical,primary_view,(parsed or {}).get("sections",[]))
        for item in overlays:findings.append(finding(item["type"],"medium",item["confidence"],item["evidence"][0],item["start_offset"],evidence=item["evidence"]))
        events.append(self._event("Overlay, embedded e carving",phase,"completed"));reporter.log(f"{len(artifacts)} artefatti salvati da intervalli validati")

        reporter.phase("Disassemblaggio statico");phase=time.monotonic();instructions=[];functions={"functions":[],"blocks":[],"calls":[]};disassembly_warnings=[]
        if parsed and parsed.get("executable_regions"):
            instructions,disassembly_warnings=disassemble(path,parsed["executable_regions"],parsed.get("architecture",""),parsed.get("bits",0),parsed.get("endian","little"),min(20000,max(1,int(options.get("max_instructions",20000)))))
            functions=analyze_functions(instructions,parsed.get("entry_points",[]),parsed.get("symbols",[]))
        events.append(self._event("Disassemblaggio statico",phase,"completed" if instructions or not parsed else "skipped"))

        reporter.phase("Indicatori, YARA e flag");phase=time.monotonic();imports,import_findings=enrich_imports((parsed or {}).get("imports",[]));findings.extend(import_findings)
        yara_matches,yara_warnings=scan_yara(path,options.get("yara_rules",[]),int(options.get("yara_timeout",20)),budget);warnings.extend(yara_warnings)
        for match in yara_matches:findings.append(finding("yara_match","medium",match["confidence"],f"Regola locale {match['rule']} corrispondente",evidence=["YARA è pattern matching, non prova di comportamento"]))
        encryption,unlock_raw=detect_crypto(path,validated,entropy,asset.get("id",""));unlock_requests=requests_from(encryption,unlock_raw)
        flag_scan_budget=min(budget,64*1024*1024)
        flags_result=global_flag_search(asset,{"prefixes":context.get("prefixes",["flag","CTF","HTB","picoCTF"]),"patterns":context.get("patterns",[]),"byte_budget":flag_scan_budget,"max_results":min(context.get("max_flags",100),500)})
        flags=[{**item,"source_file":asset.get("name",path.name),"technique":"binary_static_scan","status":"candidate","evidence":["pattern configurato trovato in dati statici"]} for item in flags_result["flags"]]
        warnings.extend(flags_result.get("warnings",[]))
        if flags_result.get("status")=="partial":warnings.append("Ricerca flag parziale entro il budget consentito")
        if flag_scan_budget<physical:warnings.append(f"Ricerca flag limitata a {flag_scan_budget} di {physical} byte")
        events.append(self._event("Indicatori, YARA e flag",phase,"partial" if flags_result.get("status")=="partial" or yara_warnings else "completed"))

        structure=structure_graph(asset.get("name",path.name),physical,parsed,validated,artifacts,findings);code=code_graph((parsed or {}).get("entry_points",[]),functions,imports,instructions)
        entropy_visual={"type":"line","title":"Entropia per offset","data":[{"x":item["offset"],"y":item["entropy"],"category":item["category"]} for item in entropy["windows"]],"encoding":{"x":{"field":"x","type":"number"},"y":{"field":"y","type":"number"}},"palette":"code","options":{"interactive":True,"zoom":True,"pan":True,"tooltip":True}}
        structure_visual={"type":"graph","title":"File Structure Graph","data":structure,"palette":"code","options":{"interactive":True,"zoom":True,"pan":True}}
        code_visual={"type":"graph","title":"Code Analysis Graph","data":code,"palette":"code","options":{"interactive":True,"zoom":True,"pan":True}}
        offset_visual={"type":"offset_map","title":"Mappa degli offset validati","data":[{"x":item["start_offset"],"y":item["length"],"start":item["start_offset"],"end":item["end_offset"],"label":item["format"],"status":"validated"} for item in validated],"palette":"code","options":{"interactive":True,"zoom":True,"tooltip":True}}
        byte_visual={"type":"byte_grid","title":"Byte grid iniziale","data":[{"offset":index,"value":value} for index,value in enumerate(prefix[:4096])],"palette":"code","options":{"interactive":True,"tooltip":True}}
        tool_inventory=runner.inventory();tool_rows=tool_inventory+[{"tool":"capstone","available":bool(instructions),"note":"nessuna regione eseguibile o modulo assente" if not instructions else f"{len(instructions)} istruzioni"},{"tool":"yara-python","available":not any("non disponibile" in value for value in yara_warnings),"matches":len(yara_matches)}]
        warnings.extend(disassembly_warnings if options.get("require_disassembly") else [])

        detection=[{**item,"status":"validated"} for item in validated]+[{**item,"status":"rejected"} for item in rejected[:1000]]
        sections=[
            section("file_identity","File Identity",10,[identity]),section("format_detection","Format Detection",20,detection,"partial" if rejected else "completed"),section("binary_header","Binary Header",30,[parsed["header"]] if parsed else [{"format":primary_format,"status":"raw_or_container","parser_error":parser_error}]),section("sections","Sections",40,(parsed or {}).get("sections",[])),section("segments","Segments",50,(parsed or {}).get("segments",[])),section("entry_points","Entry Points",60,(parsed or {}).get("entry_points",[])),section("symbols","Symbols",70,(parsed or {}).get("symbols",[])),section("imports","Imports",80,imports),section("exports","Exports",90,(parsed or {}).get("exports",[])),section("relocations","Relocations",100,(parsed or {}).get("relocations",[])),section("strings","Strings",110,strings),section("hex_view","Hex View",115,hex_rows(prefix)),section("entropy","Entropy",120,[entropy],kind="visualization",visualization=entropy_visual),section("compression","Compression",130,compression),section("encryption","Encryption Indicators",140,encryption),section("embedded_files","Embedded Files",150,[{k:v for k,v in item.items() if k not in {"context_hex"}} for item in validated if item["start_offset"]>0]+archive_rows),section("overlay","Overlay",160,overlays),section("firmware","Firmware",170,[item for item in validated if item.get("firmware") or item["validator"] in {"uefi","uboot","fdt","android_boot","android_vendor"}]),section("file_system","File System",180,[item for item in validated if item.get("filesystem")]),section("disassembly","Static Disassembly",190,instructions),section("functions","Functions",200,functions["functions"]+functions["blocks"]),section("code_graph","Code Analysis Graph",210,[code_visual],kind="visualization",visualization=code_visual),section("structure_graph","File Structure Graph",220,[structure_visual],kind="visualization",visualization=structure_visual),section("yara","YARA Matches",230,yara_matches),section("indicators","Suspicious Indicators",240,findings),section("flags","Flag Candidates",250,flags),section("artifacts","Extracted Artifacts",260,[{k:v for k,v in item.items() if k!="path"} for item in artifacts],kind="artifact_list"),section("tools","Tools and Diagnostics",900,tool_rows+runner.audit),
        ]
        metrics={"duration":round(time.monotonic()-started,4),"physical_size":physical,"bytes_analyzed":budget,"signature_hits":len(candidates),"validated_formats":len(validated),"rejected_signatures":len(rejected),"strings":len(strings),"artifacts":len(artifacts),"instructions":len(instructions),"functions":len(functions["functions"]),"yara_matches":len(yara_matches),"original_modified":False}
        sections.append(section("metrics","Metrics",910,[metrics],kind="metrics"))
        # Each warning records a coverage reduction or unavailable enrichment.
        # Keep the job state aligned with these diagnostics for downstream UI.
        status="partial" if warnings or truncated or budget<physical or parser_error or input_partial else "completed"
        result={"plugin_id":"binary-static-analysis","status":status,"summary":f"{len(validated)} formati validati, {len(findings)} indicatori, {len(artifacts)} artefatti","confidence":max((item["confidence"] for item in validated),default=.45),"phase":"binary static analysis","findings":findings,"sections":sections,"artifacts":artifacts,"derived_assets":[],"visualizations":[entropy_visual,offset_visual,byte_visual,structure_visual,code_visual],"flags":flags,"timeline":[],"execution_events":events,"logs":runner.audit,"warnings":warnings,"errors":errors,"metrics":metrics,"unlock_requests":unlock_requests}
        report=json.dumps({**result,"artifacts":[{k:v for k,v in item.items() if k!="path"} for item in artifacts]},ensure_ascii=False,indent=2).encode()
        try:result["artifacts"].append(store.save("report","binary-static-analysis-report.json",report,{"detected_type":"json","validated":True,"confidence":1.0,"extraction_method":"plugin_report"}))
        except ValueError as exc:result["warnings"].append(str(exc));result["status"]="partial"
        reporter.partial(result);return result

    def extract_artifacts(self,asset,context,reporter=None):
        """Artifacts are produced during ``analyze`` to retain exact provenance."""
        return []

    def create_assets(self,asset,context,reporter=None):
        """The Hub converts normalized artifacts into derived assets centrally."""
        return []

    def create_visualizations(self,result,context):
        """Return already validated declarative visualizations."""
        return result.get("visualizations",[])

    def search_flags(self,result,context):
        """Return plugin candidates already produced by the global detector."""
        return result.get("flags",[])

    def cleanup(self,context):
        """No mounts are created; the Hub removes the isolated output workspace."""
        return None

    @staticmethod
    def _strings(path,budget):
        rows=[];overlap=b"";offset=0
        with path.open("rb") as source:
            while offset<budget and len(rows)<5000:
                block=source.read(min(4*1024*1024,budget-offset))
                if not block:break
                base=max(0,offset-len(overlap));rows.extend(extract_strings(overlap+block,base,5000-len(rows)));overlap=block[-256:];offset+=len(block)
        unique={(item["offset"],item["encoding"],item["value"]):item for item in rows};return sorted(unique.values(),key=lambda item:item["offset"])[:5000]

    @staticmethod
    def _event(name,started,status):return {"phase":name,"status":status,"duration":round(time.monotonic()-started,4)}
