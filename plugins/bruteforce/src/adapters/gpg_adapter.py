"""GPG symmetric payload adapter using loopback passphrase in offline sandbox."""
import hashlib
from pathlib import Path
from .base import PasswordAdapter
from ..subprocess_runner import run
class GpgAdapter(PasswordAdapter):
 name='gpg_adapter';supported_formats=['gpg','pgp'];supported_protections=['gpg','openpgp']
 def can_handle(self,a,c):return c.get('protection_type') in self.supported_protections or self.path(a).suffix.lower() in {'.gpg','.pgp'}
 def _decode(self,a,p,c,target):return run('gpg',['--batch','--yes','--pinentry-mode','loopback','--passphrase',p,'--output',str(target),'--decrypt',str(self.path(a))],c['limits'].timeout_seconds,secret_indexes=(5,))
 def verify_password(self,a,p,c):
  target=Path(c['output_dir'])/'gpg-probe.bin';r=self._decode(a,p,c,target);return {'valid':r['exit_code']==0 and target.is_file(),'reason':'payload_extracted' if target.is_file() else r['status'],'audit':r}
 def extract(self,a,p,c):
  target=Path(c['output_dir'])/'unlocked-gpg.bin';r=self._decode(a,p,c,target)
  if r['exit_code']!=0 or not target.is_file():raise ValueError(r['status'])
  raw=target.read_bytes();return [{'path':str(target),'name':target.name,'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw),'status':'extracted','detected_type':'binary'}]
