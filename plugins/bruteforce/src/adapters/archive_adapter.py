"""External 7z/RAR adapter using test-before-extract and isolated output."""
from pathlib import Path
import uuid
from .base import PasswordAdapter
from ..subprocess_runner import run
from ..bounded_io import extracted
class ArchiveAdapter(PasswordAdapter):
    name='archive_adapter';supported_formats=['7z','rar','tar','gzip'];supported_protections=['7z','rar','password']
    def can_handle(self,a,c):return self.path(a).suffix.lower() in {'.7z','.rar'}
    def _tool(self,a):return 'unrar' if self.path(a).suffix.lower()=='.rar' else '7z'
    def verify_password(self,a,p,c):
        tool=self._tool(a);args=(['t',f'-p{p}',str(self.path(a))] if tool=='7z' else ['t',f'-p{p}',str(self.path(a))]);r=run(tool,args,c['limits'].timeout_seconds,secret_indexes=(1,));return {'valid':r['exit_code']==0,'reason':'verified_structure' if r['exit_code']==0 else r['status'],'audit':r}
    def extract(self,a,p,c):
        # External archive output is accepted only inside the isolated output root.
        root=Path(c['output_dir'])/'unlocked'/uuid.uuid4().hex;root.mkdir(parents=True,exist_ok=False);tool=self._tool(a);args=['x',f'-p{p}',f'-o{root}',str(self.path(a))] if tool=='7z' else ['x',f'-p{p}',str(self.path(a)),str(root)];r=run(tool,args,c['limits'].timeout_seconds,secret_indexes=(1,));
        if r['exit_code']!=0:raise ValueError(r['status'])
        out=[];total=0
        for f in root.rglob('*'):
            if f.is_file() and not f.is_symlink() and f.resolve().is_relative_to(root.resolve()):
                size=f.stat().st_size
                if size>c['limits'].max_output-total:
                    raise ValueError('archive_expansion_limit')
                out.append(extracted(f,c['limits'].max_output-total));total+=size
        return out
