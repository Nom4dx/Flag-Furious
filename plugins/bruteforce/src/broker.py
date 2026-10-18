"""Reusable in-process broker and expiring vault for local artifact unlocks."""
import secrets,threading,time,uuid
from dataclasses import replace
from pathlib import Path
from .adapter_registry import select
from .attempt_engine import run
from .progress import Progress
from .wordlist_manager import stream
from .request_model import UnlockRequest
class SecretVault:
    """Ephemeral memory-only secret vault with TTL and explicit consume."""
    def __init__(self,ttl=900):self.ttl=ttl;self._values={};self._lock=threading.Lock()
    def put(self,value):
        ref='ephemeral-secret-'+secrets.token_urlsafe(18)
        with self._lock:self._values[ref]=(value,time.monotonic()+self.ttl)
        return ref
    def get(self,ref):
        with self._lock:
            value,expiry=self._values[ref]
            if expiry<time.monotonic():del self._values[ref];raise KeyError('secret_expired')
            return value
    def forget(self,ref):
        with self._lock:self._values.pop(ref,None)
class Broker:
    """Coordinate adapter selection and attempts; caller supplies authorized paths."""
    def __init__(self):self.vault=SecretVault();self.sessions={}
    def request_unlock(self,request,context,candidate_stream=None):
        req=UnlockRequest.model_validate(request);artifact={'id':req.artifact_id,'path':req.artifact_path};choices=select(artifact,{**context,'protection_type':req.protection_type},req.metadata.get('supported_adapters'))
        request_id='unlock-'+uuid.uuid4().hex;progress=Progress();self.sessions[request_id]=progress
        if not choices:return {'request_id':request_id,'status':'not_supported','artifact_id':req.artifact_id}
        if req.mode=='ask_user' and not req.known_password and not req.wordlists:return {'request_id':request_id,'status':'waiting_for_user','artifact_id':req.artifact_id,'adapters':[x.name for x in choices]}
        candidates=candidate_stream or self._candidates(req)
        limits=replace(context['limits'],max_attempts=min(context['limits'].max_attempts,req.max_attempts),timeout_seconds=min(context['limits'].timeout_seconds,req.timeout_seconds))
        adapter=choices[0];result=run(adapter,artifact,candidates,{**context,'limits':limits,'protection_type':req.protection_type,'transformations':req.transformations},progress,req.stop_on_first_success)
        response={'request_id':request_id,'status':result['status'],'artifact_id':req.artifact_id,'adapter':adapter.name,'attempts':result['attempts'],'duration_seconds':round(result['duration'],3),'password_verified':bool(result['successes']),'password_display':'********' if result['successes'] else '','wordlists_used':req.wordlists,'failed_attempts':result['failures']}
        if result['successes']:
            password=result['successes'][0]['password'];response['secret_ref']=self.vault.put(password);response['extracted_artifacts']=adapter.extract(artifact,password,context)
        return response
    @staticmethod
    def _candidates(req):
        if req.known_password is not None:yield req.known_password,'known_password',1
        if req.allow_wordlists:
            yield from stream([Path(x) for x in req.wordlists])
    def control(self,request_id,action):
        p=self.sessions[request_id];getattr(p,action)();return p.public()
