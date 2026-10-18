"""Log Forensics orchestration for heterogeneous local evidence.

The plugin keeps source bytes immutable, detects format from bounded content,
normalizes events into an ECS-inspired model, correlates sessions/entities and
separates rule detections, statistical anomalies and reconstructed flag evidence.
"""
from __future__ import annotations
from collections import Counter
from pathlib import Path
import hashlib
import json,time
from app.core.plugin import BasePlugin
from .src.anomaly_engine import detect as detect_anomalies
from .src.archive_reader import collect
from .src.artifact_manager import ArtifactManager
from .src.attack_chain import build as build_chains
from .src.chart_builder import build as build_charts
from .src.correlation_engine import correlate
from .src.decoder_pipeline import decode_events
from .src.detection_engine import detect as detect_attacks
from .src.entity_extractor import extract as extract_entities
from .src.file_identity import identify
from .src.flag_hunter import hunt
from .src.format_detector import detect as detect_format
from .src.graph_builder import events_graph,attack_graph,flag_graph
from .src.normalizer import normalize
from .src.parser_registry import parse
from .src.reporting import section,phase
from .src.session_builder import build as build_sessions
from .src.sigma_engine import load_and_match
from .src.timeline import build as build_timeline
from .src.tool_adapters import ToolRunner

class Plugin(BasePlugin):
    """Parse, normalize and correlate local log assets without external lookups.

    Inputs may be files, directories, textual assets or JSON. Parser failures are
    isolated per source. Unknown fields and exact line/offset provenance remain
    available, while common secrets are masked in UI-facing event representations.
    """
    def can_handle(self,asset,context):
        """Score at most 128 KiB; extensions remain weak secondary evidence."""
        kind=asset.get('type');path=Path(asset.get('path','')) if asset.get('path') else None
        if kind=='directory' and path and path.is_dir():return {"compatible":True,"score":.86,"reasons":["Directory locale analizzabile come raccolta di log"]}
        if kind not in {'file','text','json','log','archive'}:return {"compatible":False,"score":0,"reasons":["Tipo asset non compatibile"]}
        try:
            if path and path.is_file():
                with path.open('rb') as source:data=source.read(128*1024)
                name=asset.get('name',path.name)
            else:
                content=asset.get('content','');data=(content if isinstance(content,str) else json.dumps(content)).encode()[:128*1024];name=asset.get('name','input.log')
        except OSError as exc:return {"compatible":False,"score":0,"reasons":[f'Input non leggibile: {exc}']}
        candidates=detect_format(data,name,asset.get('mime',''));primary=candidates[0];printable=sum(byte in b'\t\r\n' or 32<=byte<127 for byte in data)/max(1,len(data));extension=Path(name).suffix.casefold()
        structured=primary['score']>=.6;compatible=structured or (printable>.8 and extension in {'.log','.txt','.out','.json','.jsonl','.csv','.tsv','.xml','.1','.2','.old'})
        score=max(primary['score'],.64 if compatible else 0);reasons=primary['reasons']+[f'Vista prevalentemente testuale ({printable:.0%})'] if printable>.8 else primary['reasons']
        return {"compatible":compatible,"score":min(.99,score),"reasons":reasons}
    def validate(self,asset,context):
        """Require an existing non-symlink file/directory or non-empty inline value."""
        if asset.get('path'):
            path=Path(asset['path']);valid=path.exists() and not path.is_symlink() and (path.is_file() or path.is_dir())
        else:valid=asset.get('content') not in (None,'',{},[])
        return {"valid":valid,"reason":"Asset log vuoto, simbolico o non leggibile" if not valid else ''}
    def analyze(self,asset,context,reporter):
        """Run bounded phases and return the complete normalized Hub contract."""
        started=time.monotonic();events_log=[];warnings=[];errors=[];artifacts=[];runner=ToolRunner();options=context.get('plugin_options',{}).get('log-forensics',{})
        max_events=min(max(1,int(options.get('max_events',20000))),50000);budget=min(max(0,int(context.get('byte_budget',256*1024**2))),256*1024**2);output_budget=int(context.get('output_bytes',256*1024**2));store=ArtifactManager(Path(context['output_dir']),output_budget)
        execution=[];identities=[];sources=[];inline_truncated=False;input_partial=bool(asset.get('partial_input'))
        reporter.phase('Input e hash');mark=time.monotonic()
        if asset.get('path'):
            path=Path(asset['path'])
            if path.is_file():
                visible_size=path.stat().st_size;declared_size=int(asset.get('size',visible_size));input_partial=input_partial or declared_size>visible_size
                identity=identify(path,asset,budget);identities.append(identity)
                if not identity.get('hash_complete',True):warnings.append(f"{path.name}: hash calcolato solo su {identity['bytes_hashed']} byte entro il byte budget")
            sources,initial_artifacts,read_warnings,bytes_read=collect(path,budget,store,max_files=min(1024,max(1,int(options.get('max_files',256)))));artifacts.extend(initial_artifacts);warnings.extend(read_warnings)
        else:
            content=asset.get('content');raw,inline_truncated=_bounded_inline_bytes(content,budget);sources=[(asset.get('name','inline.log'),raw,None)];bytes_read=len(raw);identities=[{"asset_id":asset.get('id'),"name":asset.get('name','inline.log'),"visible_bytes":len(raw),"visible_sha256":hashlib.sha256(raw).hexdigest(),"representation":"inline_utf8" if isinstance(content,(str,bytes)) else "inline_compact_json","partial_input":inline_truncated or bool(asset.get('partial_input')),"type":asset.get('type'),"original_modified":False}]
            if inline_truncated:warnings.append(f'Asset inline limitato a {len(raw)} byte dal byte budget')
            input_partial=input_partial or inline_truncated
        if input_partial and not inline_truncated:
            warnings.append('Input già limitato dal core: i risultati coprono soltanto la vista disponibile')
        execution.append(phase('Input e hash',mark,'partial' if input_partial or inline_truncated or warnings else 'completed'));reporter.log(f'{len(sources)} sorgenti entro {bytes_read} byte')

        reporter.phase('Identificazione e parsing');mark=time.monotonic();formats=[];raw_events=[];parser_stats=Counter()
        for source_name,data,source_path in sources:
            if len(raw_events)>=max_events:break
            candidates=detect_format(data,source_name,asset.get('mime',''));formats.extend({**x,"source_file":source_name} for x in candidates)
            primary=candidates[0]['detected_format']
            if primary=='journald_binary' and source_path:
                converted=runner.journal_export(source_path)
                if converted.get('stdout') and (converted.get('exit_code')==0 or converted.get('output_truncated') or converted.get('timeout')):
                    data=converted['stdout'];primary='journald_export'
                    if converted.get('output_truncated') or converted.get('timeout'):
                        warnings.append(f'{source_name}: export journal parziale entro il budget di output')
                else:warnings.append(f'{source_name}: journalctl non ha convertito il journal');continue
            available=max_events-len(raw_events)
            rows,parse_warnings=parse(primary,data,{**options,"max_events":available,"timezone":options.get('timezone','Europe/Rome')},source_path)
            accepted=rows[:available];warnings.extend(parse_warnings);raw_events.extend(accepted);parser_stats[primary]+=len(accepted)
        if len(raw_events)>=max_events:warnings.append(f'Inventario limitato a {max_events} eventi')
        invalid=sum(bool(x.get('raw_fields',{}).get('parse_error')) for x in raw_events)
        if invalid:warnings.append(f'{invalid} record non validi conservati con provenance')
        execution.append(phase('Identificazione e parsing',mark,'partial' if warnings else 'completed'));reporter.log(f'{len(raw_events)} record prodotti da {len(parser_stats)} parser')

        reporter.phase('Normalizzazione e timeline');mark=time.monotonic();events=[normalize(row,index,{"timezone":options.get('timezone','Europe/Rome'),"reference_year":options.get('reference_year')}) for index,row in enumerate(raw_events)]
        # Full raw values exist only transiently for detection/decoding; UI events use masked raw.
        hunting_events=[{**event,"raw":raw_events[index].get('raw',''),"raw_fields":raw_events[index].get('raw_fields',{})} for index,event in enumerate(events)]
        timeline,timestamp_issues=build_timeline(events);entities=[];entity_truncated=False;entity_events_not_scanned=0
        for index,event in enumerate(events):
            remaining_entities=100000-len(entities)
            if remaining_entities<=0:
                entity_truncated=True;entity_events_not_scanned=len(events)-index;break
            extracted,limited=extract_entities(event,min(5000,remaining_entities),return_truncated=True)
            entities.extend(extracted);entity_truncated=entity_truncated or limited
        if entity_truncated:warnings.append('Inventario entità limitato a 100.000 risultati e 5.000 per evento; alcuni elementi possono essere omessi')
        execution.append(phase('Normalizzazione e timeline',mark,'partial' if entity_truncated else 'completed'));reporter.log(f'{len(timeline)} timestamp e {len(entities)} entità')

        reporter.phase('Sessioni, detection e correlazione');mark=time.monotonic();sessions,session_meta=build_sessions(events,int(options.get('session_gap_seconds',1800)),return_meta=True);findings=detect_attacks(events,options);anomalies=detect_anomalies(events)
        sigma_roots=[Path(__file__).parent/'rules'/'sigma',Path(__file__).parent/'rules'/'custom'];sigma,sigma_warnings=load_and_match(events,sigma_roots);warnings.extend(sigma_warnings)
        for match in sigma:
            findings.append({"finding_id":"finding-sigma-"+match['rule_id'],"type":"sigma_match","severity":match['rule_level'],"confidence":match['confidence'],"matched_events":match['matched_events'],"source_files":sorted({next((x['source_file'] for x in events if x['event_id']==event_id),'') for event_id in match['matched_events']}),"evidence":[match['rule_title']],"explanation":match['rule_title'],"classification":"detection","rule_id":match['rule_id']})
        links=correlate(events,sessions,findings);chains=build_chains(findings,events)
        if session_meta['truncated']:warnings.append(f"Sessioni limitate a {session_meta['returned_sessions']} su {session_meta['total_sessions']} ricostruite")
        execution.append(phase('Sessioni, detection e correlazione',mark,'partial' if session_meta['truncated'] else 'completed'));reporter.log(f'{len(sessions)} sessioni, {len(findings)} detection, {len(anomalies)} anomalie')

        reporter.phase('Decoder e flag hunting');mark=time.monotonic();decoded,decoder_metrics=decode_events(hunting_events,min(2000,max(0,int(options.get('max_decoder_attempts',1000)))),min(4,max(0,int(options.get('decoder_depth',3)))),return_meta=True)
        if decoder_metrics['truncated']:warnings.append("Decoder limitato da tentativi, risultati o budget cumulativo di 32 MiB")
        decoded_public=[]
        for index,row in enumerate(decoded):
            data=row.pop('bytes',b'');public=dict(row);decoded_public.append(public)
            if data and (data.startswith((b'PK\x03\x04',b'\x89PNG',b'%PDF',b'\x7fELF',b'MZ')) or sum(32<=x<127 for x in data)/max(1,len(data))>.7):
                try:artifacts.append(store.save('decoded',f'decoded-{index}.bin',data,{"source_event":row['source_event'],"decoder_chain":row['decoder_chain'],"extraction_method":"log_decoder_chain","detected_type":"payload_candidate"}))
                except ValueError as exc:warnings.append(str(exc));break
        flags,decoys=hunt(hunting_events,decoded_public,{"prefixes":context.get('prefixes'),"patterns":context.get('patterns',[])})
        validated_flags=[x for x in flags if x['status']=='validated'];candidate_flags=[x for x in flags if x['status']!='validated'];execution.append(phase('Decoder e flag hunting',mark));reporter.log(f'{len(flags)} flag e {len(decoded_public)} catene decoder')

        event_graph=events_graph(events,entities,sessions,findings,links);chain_graph=attack_graph(chains);reconstruction_graph=flag_graph(flags);charts=build_charts(events,timeline,sessions,findings)
        visualizations=charts+[
          {"type":"network_graph","title":"Event Correlation Graph","data":event_graph,"palette":"network","options":{"interactive":True,"zoom":True,"pan":True}},
          {"type":"graph","title":"Attack Chain Graph","data":chain_graph,"palette":"signal","options":{"interactive":True,"zoom":True,"pan":True}},
          {"type":"graph","title":"Flag Reconstruction Graph","data":reconstruction_graph,"palette":"code","options":{"interactive":True,"zoom":True,"pan":True}}]
        by_domain=lambda names:[x for x in findings if x['type'] in names]
        sections=[
          section('file_identity','File Identity',10,identities),section('detected_format','Detected Format',20,formats),section('parser_used','Parser Used',30,[{"parser":k,"events":v} for k,v in parser_stats.items()]),section('parsing_statistics','Parsing Statistics',40,[{"sources":len(sources),"records":len(raw_events),"invalid_records":invalid,"bytes_read":bytes_read}]),
          section('raw_events','Raw Events',50,[{"source_file":x['source_file'],"source_line":x['source_line'],"source_offset":x['source_offset'],"raw":events[i]['raw'],"parser":x['parser']} for i,x in enumerate(raw_events)]),section('normalized_events','Normalized Events',60,events),section('timestamp_analysis','Timestamp Analysis',70,timestamp_issues),section('entities','Entities',80,entities,status='partial' if entity_truncated else 'completed'),
          section('authentication_analysis','Authentication Analysis',90,by_domain({'brute_force','password_spraying','success_after_failures'})),section('web_analysis','Web Analysis',100,by_domain({'sql_injection','path_traversal','command_injection','xss','sensitive_path','web_enumeration'})),section('network_analysis','Network Analysis',110,by_domain({'port_scan','dns_tunneling','periodic_beaconing','possible_exfiltration'})),section('windows_analysis','Windows Analysis',120,by_domain({'powershell_encoded_command','lolbin_execution','log_clearing','service_created','security_control_disabled','suspicious_download','temporary_path_execution'})),section('linux_analysis','Linux Analysis',130,by_domain({'linux_reverse_shell','cron_persistence','log_clearing','security_control_disabled','suspicious_download','temporary_path_execution'})),section('cloud_analysis','Cloud Analysis',140,by_domain({'cloud_privilege_change'})),section('container_analysis','Container Analysis',150,by_domain({'kubernetes_exec'})),
          section('sigma_matches','Sigma Matches',160,sigma),section('anomalies','Anomalies',170,anomalies),section('attack_chains','Attack Chains',180,chains),section('sessions','Sessions',190,sessions,status='partial' if session_meta['truncated'] else 'completed'),section('timeline','Timeline',200,timeline,'timeline'),section('graphs','Graphs',210,visualizations,'visualization_list'),section('extracted_artifacts','Extracted Artifacts',220,[{k:v for k,v in x.items() if k!='path'} for x in artifacts],'artifact_list'),section('decoder_chains','Decoder Chains',230,decoded_public),section('flag_candidates','Flag Candidates',240,candidate_flags),section('validated_flags','Validated Flags',250,validated_flags),section('decoys','Decoys',260,decoys),section('findings','Findings',270,findings),section('external_tools','External Tools',890,runner.inventory()+runner.audit),section('warnings','Warnings',900,warnings,'list'),section('errors','Errors',910,errors,'list')]
        metrics={"duration":round(time.monotonic()-started,4),"bytes_read":bytes_read,"tool_output_bytes":runner.output_bytes,"tool_output_limit_bytes":runner.max_total_output,"partial_input":input_partial or inline_truncated,"sources":len(sources),"events":len(events),"timestamped_events":len(timeline),"entities":len(entities),"entity_limit":100000,"entity_truncated":entity_truncated,"entity_events_not_scanned":entity_events_not_scanned,"sessions":len(sessions),"session_coverage":session_meta,"detections":len(findings),"anomalies":len(anomalies),"correlations":len(links),"attack_chains":len(chains),"flags":len(flags),"artifacts":len(artifacts),"decoder_attempts":decoder_metrics['attempts'],"decoder_bytes":decoder_metrics['decoded_bytes'],"original_modified":False};sections.append(section('metrics','Metrics',920,[metrics],'metrics'))
        if any(row.get('output_truncated') or row.get('stderr_truncated') or row.get('timeout') or row.get('budget_exhausted') for row in runner.audit):warnings.append('Uno o più strumenti log hanno raggiunto il limite di output o tempo')
        status='failed' if not events and errors else 'partial' if warnings or invalid else 'completed';result={"plugin_id":"log-forensics","status":status,"summary":f'{len(events)} eventi, {len(findings)} detection, {len(sessions)} sessioni, {len(flags)} flag',"confidence":max((x['confidence'] for x in formats),default=.4),"phase":"log correlation","findings":findings+timestamp_issues,"sections":sections,"artifacts":artifacts,"derived_assets":[],"visualizations":visualizations,"flags":flags,"timeline":timeline,"execution_events":execution,"logs":runner.audit,"warnings":warnings,"errors":errors,"metrics":metrics}
        report=json.dumps({**result,"artifacts":[{k:v for k,v in x.items() if k!='path'} for x in artifacts]},ensure_ascii=False,indent=2).encode()
        try:result['artifacts'].append(store.save('report','log-forensics-report.json',report,{"detected_type":"json","extraction_method":"plugin_report"}))
        except ValueError as exc:result['warnings'].append(str(exc));result['status']='partial'
        reporter.partial(result);return result
    def extract_artifacts(self,asset,context,reporter=None):
        """Extraction occurs during analysis so exact event provenance is retained."""
        return []
    def create_assets(self,asset,context,reporter=None):
        """The Hub registers normalized artifacts as recursive derived assets."""
        return []
    def create_visualizations(self,result,context):
        """Return declarative charts already validated by the central engine."""
        return result.get('visualizations',[])
    def search_flags(self,result,context):
        """Return reconstructed candidates with ordering and decoder evidence."""
        return result.get('flags',[])
    def cleanup(self,context):
        """No mount survives; the Hub deletes the isolated worker directory."""
        return None


def _quoted_fragments(value):
    """Yield JSON string fragments without encoding an unbounded string at once."""
    yield b'"'
    for offset in range(0,len(value),4096):
        escaped=json.dumps(value[offset:offset+4096],ensure_ascii=False)[1:-1]
        yield escaped.encode('utf-8')
    yield b'"'


def _json_fragments(value):
    """Stream a compact JSON representation in small bounded fragments."""
    if isinstance(value,str):
        yield from _quoted_fragments(value)
    elif isinstance(value,dict):
        yield b'{'
        for index,(key,item) in enumerate(value.items()):
            if index:yield b','
            yield from _quoted_fragments(str(key));yield b':'
            yield from _json_fragments(item)
        yield b'}'
    elif isinstance(value,(list,tuple)):
        yield b'['
        for index,item in enumerate(value):
            if index:yield b','
            yield from _json_fragments(item)
        yield b']'
    else:
        yield json.dumps(value,ensure_ascii=False,separators=(',',':')).encode('utf-8')


def _bounded_inline_bytes(content,limit):
    """Encode inline text/JSON only up to ``limit`` bytes and report truncation."""
    if isinstance(content,bytes):return content[:limit],len(content)>limit
    if isinstance(content,str):
        output=bytearray()
        for offset in range(0,len(content),4096):
            block=content[offset:offset+4096].encode('utf-8')
            remaining=limit-len(output)
            if len(block)>remaining:
                output.extend(block[:remaining]);return bytes(output),True
            output.extend(block)
        return bytes(output),False
    output=bytearray()
    for fragment in _json_fragments(content):
        remaining=limit-len(output)
        if len(fragment)>remaining:
            output.extend(fragment[:remaining]);return bytes(output),True
        output.extend(fragment)
    return bytes(output),False
