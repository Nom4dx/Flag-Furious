"""OpenStego adapter using a bounded offline CLI invocation."""
import hashlib
from pathlib import Path
from .base import PasswordAdapter
from ..subprocess_runner import run
from ..bounded_io import extracted
class OpenStegoAdapter(PasswordAdapter):
 name='openstego_adapter';supported_formats=['png','bmp'];supported_protections=['openstego']
 def can_handle(self,a,c):return c.get('protection_type')=='openstego'
 def _decode(self,a,p,c,target):return run('openstego',['extract','-sf',str(self.path(a)),'-p',p,'-xf',str(target)],c['limits'].timeout_seconds,secret_indexes=(4,))
 def verify_password(self,a,p,c):
  target=Path(c['output_dir'])/'openstego-probe.bin';r=self._decode(a,p,c,target);return {'valid':r['exit_code']==0 and target.is_file() and target.stat().st_size>0,'reason':'payload_extracted' if target.is_file() else r['status'],'audit':r}
 def extract(self,a,p,c):
  target=Path(c['output_dir'])/'openstego-payload.bin';r=self._decode(a,p,c,target)
  if r['exit_code']!=0 or not target.is_file():raise ValueError(r['status'])
  return [extracted(target,c['limits'].max_output)]
