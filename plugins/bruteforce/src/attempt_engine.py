"""Deterministic bounded password attempt engine with pause/cancel checkpoints."""
import hashlib,time
from .candidate_generator import variants
def run(adapter,artifact,candidates,context,progress,stop_on_first=True):
    """Try streamed candidates, deduplicate by hash and return rich terminal status."""
    limits=context['limits'];started=time.monotonic();seen=set();failures=[];success=[];progress.start()
    for raw,origin,line in candidates:
        for password in variants(raw,context.get('transformations',False),context.get('transformation_year')):
            if not progress.checkpoint():return {'status':'cancelled','attempts':progress.attempts,'successes':success,'failures':failures,'duration':time.monotonic()-started}
            if progress.attempts>=limits.max_attempts:return {'status':'limit_reached','attempts':progress.attempts,'successes':success,'failures':failures,'duration':time.monotonic()-started}
            if time.monotonic()-started>=limits.timeout_seconds:return {'status':'timeout','attempts':progress.attempts,'successes':success,'failures':failures,'duration':time.monotonic()-started}
            digest=hashlib.sha256(password.encode()).hexdigest()
            if digest in seen:continue
            seen.add(digest);progress.attempts+=1;progress.last_index=line;progress.current_wordlist=origin
            result=adapter.verify_password(artifact,password,context)
            if result.get('reason') in {'unsupported_encryption','corrupted_artifact','not_encrypted'}:
                failure={'candidate_hash':digest,'origin':origin,'line':line,'reason':result['reason']}
                failures.append(failure)
                status='not_supported' if result['reason']=='unsupported_encryption' else 'failed'
                progress.status=status
                return {'status':status,'attempts':progress.attempts,'successes':success,'failures':failures,'duration':time.monotonic()-started}
            if result.get('valid'):
                success.append({'password':password,'value_hash':digest,'origin':origin,'line':line,'verification':result})
                if stop_on_first:progress.status='success';return {'status':'success','attempts':progress.attempts,'successes':success,'failures':failures,'duration':time.monotonic()-started}
            elif len(failures)<50:failures.append({'candidate_hash':digest,'origin':origin,'line':line,'reason':result.get('reason','wrong_password')})
    progress.status='success' if success else 'not_found';return {'status':progress.status,'attempts':progress.attempts,'successes':success,'failures':failures,'duration':time.monotonic()-started}
