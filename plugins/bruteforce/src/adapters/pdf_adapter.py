"""Encrypted PDF adapter using pikepdf or qpdf without active content execution."""
from pathlib import Path
from .base import PasswordAdapter
from ..subprocess_runner import run
class PdfAdapter(PasswordAdapter):
 name='pdf_adapter';supported_formats=['pdf'];supported_protections=['pdf','pdf_user','pdf_owner']
 def can_handle(self,a,c):return self.path(a).read_bytes()[:8].startswith(b'%PDF-') and b'/Encrypt' in self.path(a).read_bytes()[:8*1024*1024]
 def verify_password(self,a,p,c):
  try:
   import pikepdf
   with pikepdf.open(self.path(a),password=p):pass
   return {'valid':True,'reason':'pikepdf_open'}
  except ImportError:
   r=run('qpdf',['--password='+p,'--check',str(self.path(a))],c['limits'].timeout_seconds,secret_indexes=(0,));return {'valid':r['exit_code']==0,'reason':'qpdf_check' if r['exit_code']==0 else r['status'],'audit':r}
  except Exception as e:return {'valid':False,'reason':'wrong_password','message':str(e)}
 def extract(self,a,p,c):
  target=Path(c['output_dir'])/'unlocked.pdf';
  try:
   import pikepdf
   with pikepdf.open(self.path(a),password=p) as pdf:pdf.save(target)
  except ImportError:
   r=run('qpdf',['--password='+p,'--decrypt',str(self.path(a)),str(target)],c['limits'].timeout_seconds,secret_indexes=(0,));
   if r['exit_code']!=0:raise ValueError(r['status'])
  import hashlib;raw=target.read_bytes()
  if not raw.startswith(b'%PDF-'):raise ValueError('invalid_derived_pdf')
  return [{'path':str(target),'name':target.name,'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw),'status':'extracted','detected_type':'pdf'}]
