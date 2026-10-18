"""Encrypted PDF adapter using pikepdf or qpdf without active content execution."""
from pathlib import Path
from .base import PasswordAdapter
from ..subprocess_runner import run
from ..bounded_io import extracted
class PdfAdapter(PasswordAdapter):
 name='pdf_adapter';supported_formats=['pdf'];supported_protections=['pdf','pdf_user','pdf_owner']
 def can_handle(self,a,c):
  path=self.path(a);size=path.stat().st_size
  with path.open('rb') as source:
   header=source.read(8);prefix=source.read(64*1024);tail=b''
   if size>len(header)+len(prefix):source.seek(max(0,size-256*1024));tail=source.read(256*1024)
  return header.startswith(b'%PDF-') and (b'/Encrypt' in prefix or b'/Encrypt' in tail)
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
   r=run('qpdf',['--password='+p,'--decrypt',str(self.path(a)),str(target)],c['limits'].timeout_seconds,secret_indexes=(0,),max_file_size=c['limits'].max_output);
   if r['exit_code']!=0:raise ValueError(r['status'])
  with target.open('rb') as source:signature=source.read(5)
  if not signature.startswith(b'%PDF-'):raise ValueError('invalid_derived_pdf')
  return [extracted(target,c['limits'].max_output,'pdf')]
