"""Explicit unsupported fallback; never guesses unknown encryption."""
from .base import PasswordAdapter
class GenericAdapter(PasswordAdapter):
 name='generic_adapter';supported_formats=['binary'];supported_protections=['unknown']
 def can_handle(self,a,c):return True
 def verify_password(self,a,p,c):return {'valid':False,'reason':'not_supported'}
