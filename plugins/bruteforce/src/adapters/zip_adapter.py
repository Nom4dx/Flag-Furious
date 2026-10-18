"""ZIP ZipCrypto and optional AES adapter with CRC and safe-member validation."""
import hashlib,zipfile
from pathlib import Path
from .base import PasswordAdapter
from ..security import member_safe
class ZipAdapter(PasswordAdapter):
    name='zip_adapter';supported_formats=['zip'];supported_protections=['zipcrypto','zip_aes','password']
    def can_handle(self,a,c):
        try:return zipfile.is_zipfile(self.path(a))
        except OSError:return False
    def _open(self,path):
        try:
            import pyzipper
            return pyzipper.AESZipFile(path)
        except ImportError:return zipfile.ZipFile(path)
    def verify_password(self,a,password,c):
        try:
            with self._open(self.path(a)) as z:
                protected=[x for x in z.infolist() if x.flag_bits&1 or getattr(x,'wz_aes_version',None)]
                if not protected:return {'valid':False,'reason':'not_encrypted'}
                for i in protected[:3]:z.read(i,pwd=password.encode())
            return {'valid':True,'reason':'verified_crc'}
        except zipfile.BadZipFile as e:return {'valid':False,'reason':'corrupted_artifact','message':str(e)}
        except (RuntimeError,NotImplementedError,ValueError) as e:return {'valid':False,'reason':'wrong_password','message':str(e)}
    def extract(self,a,password,c):
        root=Path(c['output_dir'])/'unlocked';root.mkdir(parents=True,exist_ok=True);out=[];total=0;limit=c['limits'].max_output
        with self._open(self.path(a)) as z:
            for index,i in enumerate(z.infolist()):
                if i.is_dir() or not member_safe(i.filename,i.external_attr>>16):continue
                ratio=i.file_size/max(1,i.compress_size)
                if ratio>c['limits'].max_ratio or total+i.file_size>limit:raise ValueError('archive_expansion_limit')
                raw=z.read(i,pwd=password.encode());total+=len(raw);digest=hashlib.sha256(raw).hexdigest();target=root/f'{digest[:12]}-{Path(i.filename).name or index}';target.write_bytes(raw)
                out.append({'path':str(target),'name':target.name,'sha256':digest,'size':len(raw),'detected_type':'binary','status':'extracted','internal_path':i.filename})
        return out
