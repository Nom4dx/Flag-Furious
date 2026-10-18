"""Known/candidate single-byte XOR adapter for extracted local payloads."""
import hashlib
from pathlib import Path
from .base import PasswordAdapter
class EncryptedTextAdapter(PasswordAdapter):
 name='encrypted_text_adapter';supported_formats=['text','binary'];supported_protections=['xor','encrypted_text']
 def can_handle(self,a,c):return c.get('protection_type') in self.supported_protections
 def _key(self,p):
  if p.startswith('0x'):
   try:return bytes.fromhex(p[2:])
   except ValueError:return b''
  return p.encode()
 def verify_password(self,a,p,c):
  key=self._key(p);raw=self.path(a).read_bytes()
  if not key:return {'valid':False,'reason':'wrong_password'}
  out=bytes(v^key[i%len(key)] for i,v in enumerate(raw));ratio=sum(x in b'\r\n\t' or 32<=x<127 for x in out)/max(1,len(out));return {'valid':ratio>.75,'reason':'readable_plaintext' if ratio>.75 else 'wrong_password','preview':out[:80].decode(errors='replace')}
 def extract(self,a,p,c):
  key=self._key(p);raw=self.path(a).read_bytes();out=bytes(v^key[i%len(key)] for i,v in enumerate(raw));target=Path(c['output_dir'])/'unlocked-text.bin';target.write_bytes(out);return [{'path':str(target),'name':target.name,'sha256':hashlib.sha256(out).hexdigest(),'size':len(out),'status':'extracted','detected_type':'text'}]
