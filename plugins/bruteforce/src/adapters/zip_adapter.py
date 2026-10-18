"""ZIP ZipCrypto and optional AES adapter with CRC and safe-member validation."""
import hashlib,struct,zipfile
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
        except ImportError:pass
        cache=getattr(self,'_aes_cache',None)
        key=str(Path(path).resolve())
        if cache is None:self._aes_cache=cache={}
        if key not in cache:
            with zipfile.ZipFile(path) as archive:
                cache[key]=any(self._is_aes(item.extra) for item in archive.infolist())
        if cache[key]:raise UnsupportedProtection('pyzipper_required_for_aes')
        return zipfile.ZipFile(path)
    @staticmethod
    def _is_aes(extra):
        cursor=0
        while cursor+4<=len(extra):
            field,size=struct.unpack_from('<HH',extra,cursor);cursor+=4
            if cursor+size>len(extra):return False
            if field==0x9901:return True
            cursor+=size
        return False
    def verify_password(self,a,password,c):
        try:
            with self._open(self.path(a)) as z:
                protected=[x for x in z.infolist() if x.flag_bits&1 or getattr(x,'wz_aes_version',None)]
                if not protected:return {'valid':False,'reason':'not_encrypted'}
                budget=c['limits'].max_output;used=0
                for i in protected[:3]:
                    if i.file_size>budget-used:return {'valid':False,'reason':'artifact_input_limit'}
                    with z.open(i,pwd=password.encode()) as member:
                        while True:
                            chunk=member.read(min(1024*1024,budget-used+1))
                            if not chunk:break
                            used+=len(chunk)
                            if used>budget:return {'valid':False,'reason':'artifact_input_limit'}
            return {'valid':True,'reason':'verified_crc'}
        except zipfile.BadZipFile as e:return {'valid':False,'reason':'corrupted_artifact','message':str(e)}
        except UnsupportedProtection as e:return {'valid':False,'reason':'unsupported_encryption','message':str(e)}
        except NotImplementedError as e:return {'valid':False,'reason':'unsupported_encryption','message':str(e)}
        except (RuntimeError,ValueError) as e:return {'valid':False,'reason':'wrong_password','message':str(e)}
    def extract(self,a,password,c):
        root=Path(c['output_dir'])/'unlocked';root.mkdir(parents=True,exist_ok=True);out=[];total=0;limit=c['limits'].max_output
        with self._open(self.path(a)) as z:
            for index,i in enumerate(z.infolist()):
                if i.is_dir() or not member_safe(i.filename,i.external_attr>>16):continue
                ratio=i.file_size/max(1,i.compress_size)
                if ratio>c['limits'].max_ratio or total+i.file_size>limit:raise ValueError('archive_expansion_limit')
                if i.file_size>limit-total:raise ValueError('archive_expansion_limit')
                digest=hashlib.sha256();target=root/f'{index}-{Path(i.filename).name or "member"}';written=0
                with z.open(i,pwd=password.encode()) as member,target.open('wb') as output:
                    while True:
                        chunk=member.read(min(1024*1024,limit-total-written+1))
                        if not chunk:break
                        written+=len(chunk)
                        if written>limit-total:
                            target.unlink(missing_ok=True);raise ValueError('archive_expansion_limit')
                        output.write(chunk);digest.update(chunk)
                total+=written
                out.append({'path':str(target),'name':target.name,'sha256':digest.hexdigest(),'size':written,'detected_type':'binary','status':'extracted','internal_path':i.filename})
        return out


class UnsupportedProtection(RuntimeError):
    """Required encryption support is unavailable in this environment."""
