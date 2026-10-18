"""External 7z/RAR adapter using test-before-extract and isolated output."""
from pathlib import Path
from .base import PasswordAdapter
from ..subprocess_runner import run
class ArchiveAdapter(PasswordAdapter):
    name='archive_adapter';supported_formats=['7z','rar','tar','gzip'];supported_protections=['7z','rar','password']
    def can_handle(self,a,c):return self.path(a).suffix.lower() in {'.7z','.rar'}
    def _tool(self,a):return 'unrar' if self.path(a).suffix.lower()=='.rar' else '7z'
    def verify_password(self,a,p,c):
        tool=self._tool(a);args=(['t',f'-p{p}',str(self.path(a))] if tool=='7z' else ['t',f'-p{p}',str(self.path(a))]);r=run(tool,args,c['limits'].timeout_seconds,secret_indexes=(1,));return {'valid':r['exit_code']==0,'reason':'verified_structure' if r['exit_code']==0 else r['status'],'audit':r}
    def extract(self,a,p,c):
        # External archive output is accepted only inside the isolated output root.
        root=Path(c['output_dir'])/'unlocked';root.mkdir(parents=True,exist_ok=True);tool=self._tool(a);args=['x',f'-p{p}',f'-o{root}',str(self.path(a))] if tool=='7z' else ['x',f'-p{p}',str(self.path(a)),str(root)];r=run(tool,args,c['limits'].timeout_seconds,secret_indexes=(1,));
        if r['exit_code']!=0:raise ValueError(r['status'])
        import hashlib
        out=[]
        for f in root.rglob('*'):
            if f.is_file() and not f.is_symlink() and f.resolve().is_relative_to(root.resolve()):
                raw=f.read_bytes();out.append({'path':str(f),'name':f.name,'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw),'status':'extracted','detected_type':'binary'})
        return out
