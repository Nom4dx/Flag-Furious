"""Microsoft Office OLE/OOXML decryption via optional msoffcrypto-tool."""
import hashlib
from pathlib import Path
from .base import PasswordAdapter
from ..bounded_io import extracted
class OfficeAdapter(PasswordAdapter):
 name='office_adapter';supported_formats=['docx','xlsx','pptx','ole'];supported_protections=['office','office_agile','office_standard']
 def can_handle(self,a,c):
  path=self.path(a)
  with path.open('rb') as source:head=source.read(8)
  return head.startswith(b'\xd0\xcf\x11\xe0') or Path(a.get('name',path.name)).suffix.lower() in {'.docx','.xlsx','.pptx','.doc','.xls','.ppt'}
 def verify_password(self,a,p,c):
  try:
   import msoffcrypto
   with self.path(a).open('rb') as f:o=msoffcrypto.OfficeFile(f);o.load_key(password=p,verify_password=True)
   return {'valid':True,'reason':'msoffcrypto_verified'}
  except ImportError:return {'valid':False,'reason':'tool_missing'}
  except Exception as e:return {'valid':False,'reason':'wrong_password','message':str(e)}
 def extract(self,a,p,c):
  import msoffcrypto
  target=Path(c['output_dir'])/('unlocked'+self.path(a).suffix)
  if self.path(a).stat().st_size>c['limits'].max_output:raise ValueError('artifact_input_limit')
  with self.path(a).open('rb') as f, target.open('wb') as out:o=msoffcrypto.OfficeFile(f);o.load_key(password=p,verify_password=True);o.decrypt(out)
  with target.open('rb') as source:signature=source.read(8)
  if not signature.startswith((b'PK\x03\x04',b'\xd0\xcf\x11\xe0')):raise ValueError('invalid_derived_office')
  return [extracted(target,c['limits'].max_output,'office')]
