"""GPG symmetric payload adapter using loopback passphrase in offline sandbox."""
import hashlib
from pathlib import Path
from .base import PasswordAdapter
from ..subprocess_runner import run
from ..bounded_io import extracted
class GpgAdapter(PasswordAdapter):
 name='gpg_adapter';supported_formats=['gpg','pgp'];supported_protections=['gpg','openpgp']
 def can_handle(self,a,c):return c.get('protection_type') in self.supported_protections or self.path(a).suffix.lower() in {'.gpg','.pgp'}
 def _decode(self,a,p,c,target):return run('gpg',['--batch','--yes','--pinentry-mode','loopback','--passphrase',p,'--output',str(target),'--decrypt',str(self.path(a))],c['limits'].timeout_seconds,secret_indexes=(5,),max_file_size=c['limits'].max_output)
 def verify_password(self,a,p,c):
  target=Path(c['output_dir'])/'gpg-probe.bin'
  try:
   r=self._decode(a,p,c,target);valid=r['exit_code']==0 and not r.get('output_truncated') and target.is_file() and target.stat().st_size<=c['limits'].max_output
   return {'valid':valid,'reason':'payload_extracted' if valid else r['status'],'audit':r}
  finally:target.unlink(missing_ok=True)
 def extract(self,a,p,c):
  target=Path(c['output_dir'])/'unlocked-gpg.bin';r=self._decode(a,p,c,target)
  try:
   if r['exit_code']!=0 or r.get('output_truncated') or not target.is_file():raise ValueError(r['status'])
   return [extracted(target,c['limits'].max_output)]
  except Exception:
   target.unlink(missing_ok=True)
   raise
