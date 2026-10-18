"""Steghide adapter for JPEG/BMP/WAV/AU; never executes extracted bytes."""
import hashlib
from pathlib import Path
from .base import PasswordAdapter
from ..subprocess_runner import run
from ..bounded_io import extracted
class SteghideAdapter(PasswordAdapter):
 name='steghide_adapter';supported_formats=['jpeg','bmp','wav','au'];supported_protections=['steghide']
 def can_handle(self,a,c):return self.path(a).suffix.lower() in {'.jpg','.jpeg','.bmp','.wav','.au'}
 def verify_password(self,a,p,c):
  target=Path(c['output_dir'])/'steghide-probe.bin';r=run('steghide',['extract','-sf',str(self.path(a)),'-p',p,'-xf',str(target),'-f'],c['limits'].timeout_seconds,secret_indexes=(4,),max_file_size=c['limits'].max_output);ok=r['exit_code']==0 and not r.get('output_truncated') and target.is_file() and target.stat().st_size<=c['limits'].max_output;return {'valid':ok,'reason':'payload_extracted' if ok else r['status'],'audit':r,'probe':str(target) if ok else None}
 def extract(self,a,p,c):
  check=self.verify_password(a,p,c)
  if not check['valid']:raise ValueError(check['reason'])
  target=Path(check['probe']);return [extracted(target,c['limits'].max_output)]
