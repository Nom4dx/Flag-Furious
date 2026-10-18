"""StegCloak/stegsnow adapter; decoded text remains passive data."""
import hashlib
from pathlib import Path
from .base import PasswordAdapter
from ..subprocess_runner import run
class StegCloakAdapter(PasswordAdapter):
 name='stegcloak_adapter';supported_formats=['text'];supported_protections=['stegcloak','stegsnow']
 def can_handle(self,a,c):return c.get('protection_type') in self.supported_protections
 def _decode(self,a,p,c):
  output_limit=min(1024*1024,c['limits'].max_output)
  if c.get('protection_type')=='stegsnow':return run('stegsnow',['-C','-p',p,str(self.path(a))],c['limits'].timeout_seconds,secret_indexes=(2,),max_stdout=output_limit)
  return run('stegcloak',['reveal','-f',str(self.path(a)),'-p',p],c['limits'].timeout_seconds,secret_indexes=(4,),max_stdout=output_limit)
 def verify_password(self,a,p,c):
  r=self._decode(a,p,c);return {'valid':r['exit_code']==0 and bool(r['stdout']),'reason':'decoded_text' if r['exit_code']==0 else r['status'],'audit':r}
 def extract(self,a,p,c):
  r=self._decode(a,p,c)
  if r['exit_code']!=0 or r.get('output_truncated'):raise ValueError(r['status'])
  raw=r['stdout'].encode();target=Path(c['output_dir'])/'unlocked-steg-text.txt';target.write_bytes(raw);return [{'path':str(target),'name':target.name,'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw),'status':'extracted','detected_type':'text'}]
