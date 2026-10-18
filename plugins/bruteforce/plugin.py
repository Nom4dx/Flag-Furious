"""Forensic Hub Password Recovery plugin.

The analysis endpoint inventories protection and returns `waiting_for_user` unless
an explicit, finite recovery configuration is supplied. Actual attempts are local,
bounded and adapter-verified; secrets never enter normalized persistent results.
"""
from __future__ import annotations
import time
from pathlib import Path
from app.core.plugin import BasePlugin
from .src.adapter_registry import select
from .src.attempt_engine import run as attempt
from .src.artifact_return import derived
from .src.audit import event
from .src.graph_builder import build
from .src.limits import Limits
from .src.progress import Progress
from .src.reporting import section
from .src.wordlist_discovery import roots
from .src.wordlist_manager import inventory,stream
class Plugin(BasePlugin):
    """Unlock authorized local artifacts using known passwords or selected lists.

    Input is a read-only worker copy; output is written only below output_dir.
    Missing adapters produce `not_supported`, never a generic false. This plugin
    has no network capability and does not execute extracted content.
    """
    def can_handle(self,asset,context):
        """Route known protected containers while allowing explicit binary use."""
        path=asset.get('path')
        if not path:return {'compatible':False,'score':0,'reasons':['File locale richiesto']}
        head=Path(path).open('rb').read(64*1024*1024);ext=Path(path).suffix.lower();evidence=[]
        if ext in {'.zip','.7z','.rar','.pdf','.docx','.xlsx','.pptx','.doc','.xls','.ppt','.jpg','.jpeg','.bmp','.wav','.au','.gpg','.enc','.img','.dd','.raw','.vhd','.vhdx','.bde','.fve'}:evidence.append('Formato con protezione supportabile')
        if b'/Encrypt' in head or b'EncryptedPackage' in head:evidence.append('Struttura cifrata rilevata')
        if b'-FVE-FS-' in head:evidence.append('Volume BitLocker/FVE rilevato')
        return {'compatible':bool(evidence),'score':.96 if len(evidence)>1 else .72 if evidence else 0,'reasons':evidence}
    def validate(self,asset,context):
        """Require a regular non-symlink sandbox input."""
        p=Path(asset.get('path',''));return {'valid':p.is_file() and not p.is_symlink(),'reason':'File regolare locale richiesto'}
    def analyze(self,asset,context,reporter):
        """Inspect protection and optionally run an explicitly configured attempt."""
        started=time.monotonic();path=Path(asset['path']);limits=Limits.from_context(context);options=context.get('plugin_options',{}).get('bruteforce',{});artifact={'id':asset.get('id',''),'path':str(path),'name':asset.get('name',path.name)};protection=options.get('protection_type',self._protection(path));adapter_list=select(artifact,{'protection_type':protection});project=Path(__file__).resolve().parent;needs_wordlists=bool(options.get('wordlists'));root_items=roots(project,options.get('wordlist_roots',[]),options.get('configured_roots',[])) if needs_wordlists else [];wordlists=inventory(root_items)
        reporter.phase('Rilevamento protezione');audit=[event('protected_artifact_inspected',artifact=artifact['name'],protection_type=protection)];status='waiting_for_user';response={'status':status,'attempts':0,'extracted_artifacts':[],'adapter':adapter_list[0].name if adapter_list else ''}
        known=options.get('known_password');selected=self._selected(options.get('wordlists',[]),wordlists,root_items)
        if not adapter_list:status=response['status']='not_supported'
        elif known is None and not selected:status=response['status']='waiting_for_user'
        elif not options.get('confirmed',False):status=response['status']='waiting_for_user';response['reason']='confirmation_required'
        else:
            reporter.phase('Tentativi controllati');candidates=self._candidates(known,selected);progress=Progress();attempt_context={'limits':limits,'output_dir':context['output_dir'],'protection_type':protection,'transformations':bool(options.get('transformations',False))}
            if protection.startswith('bitlocker') and known is None and selected and hasattr(adapter_list[0],'recover_wordlists'):
                response=adapter_list[0].recover_wordlists(artifact,candidates,attempt_context)
            else:response=attempt(adapter_list[0],artifact,candidates,attempt_context,progress,bool(options.get('stop_on_first_success',True)))
            status=response['status']
            if response.get('successes'):
                password=response['successes'][0]['password'];unlocked=adapter_list[0].extract(artifact,password,{'limits':limits,'output_dir':context['output_dir'],'protection_type':protection});response['extracted_artifacts']=unlocked;response['password_verified']=True;response['password_display']='********';response['successes']=[{k:v for k,v in x.items() if k!='password'} for x in response['successes']]
        persistent={k:v for k,v in response.items() if k not in {'successes'}};unlocked=derived(response.get('extracted_artifacts',[]),artifact['id'],options.get('source_plugin','manual'),persistent.get('secret_ref'),response.get('adapter',adapter_list[0].name if adapter_list else '')) if response.get('extracted_artifacts') else []
        graph=build(options.get('source_plugin','manual'),artifact,{**persistent,'extracted_artifacts':unlocked});vis={'type':'graph','title':'Catena di sblocco','data':graph,'palette':'archive','options':{'interactive':True,'zoom':True,'pan':True}}
        findings=[]
        if status not in {'success','waiting_for_user'}:findings.append({'id':'recovery-failed','type':'password_recovery_failed','severity':'info','artifact':artifact['name'],'reason':status,'attempts':response.get('attempts',0),'message':'Nessuna password trovata entro i limiti configurati' if status in {'not_found','limit_reached','timeout'} else 'Formato o adapter non disponibile','confidence':1})
        sections=[section('summary','Password Recovery Summary',10,[{'status':status,'protection_type':protection,'adapter':response.get('adapter'),'attempts':response.get('attempts',0),'password_display':response.get('password_display','')}],status),section('protected','Protected Artifact',20,[{**artifact,'path':None}]),section('adapters','Available Adapters',30,[{'name':a.name,'formats':a.supported_formats,'protections':a.supported_protections} for a in adapter_list]),section('wordlists','Wordlists',40,wordlists),section('selected','Selected Wordlists',50,[str(x) for x in selected]),section('candidates','Candidate Generation',60,[{'transformations':bool(options.get('transformations',False)),'deduplication':'sha256','streaming':True}]),section('progress','Progress',70,[{'status':status,'attempts':response.get('attempts',0),'duration':response.get('duration',0)}]),section('attempts','Attempts',80,response.get('failures',[])),section('successful','Successful Password',90,[{'password_display':'********','secret_ref':persistent.get('secret_ref'),'verified':True}] if response.get('password_verified') else []),section('unlocked','Extracted Artifacts',100,unlocked),section('errors','Errors',110,[]),section('requests','Integration Requests',120,[{'parent_plugin':options.get('source_plugin','manual'),'parent_run_id':options.get('parent_run_id'),'status':status}]),section('audit','Audit degli altri plugin',130,self._audit())]
        result={'plugin_id':'bruteforce','status':'partial' if status in {'waiting_for_user','not_supported','not_found','timeout','limit_reached'} else 'completed','summary':self._summary(status,response.get('attempts',0)),'confidence':1 if status=='success' else .8,'phase':'password recovery','findings':findings,'sections':sections,'artifacts':unlocked,'derived_assets':[],'visualizations':[vis],'flags':[],'timeline':[],'execution_events':audit,'logs':audit,'warnings':[x['path']+' non disponibile' for x in root_items if not x['exists']],'errors':[],'metrics':{'duration':round(time.monotonic()-started,4),'attempts':response.get('attempts',0),'wordlists':len(selected),'original_modified':False}}
        reporter.partial(result);return result
    def extract_artifacts(self,*a):return []
    def create_assets(self,*a):return []
    def create_visualizations(self,result,context):return result.get('visualizations',[])
    def search_flags(self,*a):return []
    def cleanup(self,context):return None
    @staticmethod
    def _protection(path):
        head=path.open('rb').read(8*1024*1024);ext=path.suffix.lower()
        if head.startswith(b'PK'):return 'zipcrypto'
        if head.startswith(b'%PDF-') and b'/Encrypt' in head:return 'pdf'
        if head.startswith(b'\xd0\xcf\x11\xe0'):return 'office'
        if ext in {'.jpg','.jpeg','.bmp','.wav','.au'}:return 'steghide'
        if ext in {'.7z','.rar'}:return ext[1:]
        if b'-FVE-FS-' in head:return 'bitlocker'
        return 'unknown'
    @staticmethod
    def _candidates(known,selected):
        if known is not None:yield known,'known_password',1
        yield from stream(selected)
    @staticmethod
    def _selected(requested,items,root_items):
        """Permit only inventoried regular wordlists beneath discovered roots."""
        allowed={str(Path(x['path']).resolve()) for x in items};out=[]
        for value in requested:
            path=Path(value).resolve()
            if str(path) in allowed:out.append(path)
        return out
    @staticmethod
    def _summary(status,attempts):
        """Create a password-free human summary."""
        return f"Recovery {status}: {attempts} tentativi"
    @staticmethod
    def _audit():
        """Expose the integration audit in the mapped dashboard."""
        from .src.integration_audit import report
        return report()['integration_status']
