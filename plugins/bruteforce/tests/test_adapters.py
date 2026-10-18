"""Adapter verification and extraction safety tests."""
from pathlib import Path
import pytest
from plugins.bruteforce.src.adapters.zip_adapter import ZipAdapter
from plugins.bruteforce.src.adapters.encrypted_text_adapter import EncryptedTextAdapter
from plugins.bruteforce.src.limits import Limits
from plugins.bruteforce.src.security import member_safe
FIX=Path(__file__).parents[1]/'fixtures'
def context(tmp_path,protection='password'):return {'output_dir':str(tmp_path),'limits':Limits(100,10,1,1024*1024,100),'protection_type':protection}
def test_zipcrypto_known_password_and_wrong_password(tmp_path):
 path=FIX/'zipcrypto-secret.zip'
 if not path.exists():pytest.skip('zip fixture generator unavailable')
 a={'path':str(path)};adapter=ZipAdapter();assert adapter.verify_password(a,'wrong',context(tmp_path))['reason']=='wrong_password';assert adapter.verify_password(a,'secret',context(tmp_path))['valid']
 out=adapter.extract(a,'secret',context(tmp_path));assert out and Path(out[0]['path']).read_text().startswith('FLAG{')
def test_xor_adapter_password(tmp_path):
 plain=b'FLAG{xor}';key=b'key';source=tmp_path/'x.enc';source.write_bytes(bytes(v^key[i%3] for i,v in enumerate(plain)));a={'path':str(source)};adapter=EncryptedTextAdapter();c=context(tmp_path,'xor');assert adapter.verify_password(a,'key',c)['valid'];assert Path(adapter.extract(a,'key',c)[0]['path']).read_bytes()==plain
def test_member_security():
 assert not member_safe('../escape') and not member_safe('/absolute') and not member_safe('link',0o120777)

def test_sevenzip_password_when_tool_available(tmp_path):
 from plugins.bruteforce.src.adapters.archive_adapter import ArchiveAdapter
 import shutil
 if not shutil.which('7z'):pytest.skip('7z unavailable')
 source=FIX/'sevenzip-secret.7z';adapter=ArchiveAdapter();c=context(tmp_path)
 assert not adapter.verify_password({'path':str(source)},'wrong',c)['valid']
 assert adapter.verify_password({'path':str(source)},'secret',c)['valid']
 assert adapter.extract({'path':str(source)},'secret',c)

def test_steghide_password_when_tool_available(tmp_path):
 from plugins.bruteforce.src.adapters.steghide_adapter import SteghideAdapter
 import shutil
 if not shutil.which('steghide'):pytest.skip('steghide unavailable')
 source=FIX/'steghide-secret.jpg';adapter=SteghideAdapter();c=context(tmp_path)
 assert adapter.verify_password({'path':str(source)},'secret',c)['valid']
 assert b'FLAG{steghide_unlocked}' in Path(adapter.extract({'path':str(source)},'secret',c)[0]['path']).read_bytes()
