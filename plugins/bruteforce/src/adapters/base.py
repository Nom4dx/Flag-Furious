"""Common adapter contract for password protected local artifacts."""
from pathlib import Path
class PasswordAdapter:
    """Adapter interface. Verification must parse/decrypt, never trust exit code alone."""
    name='generic';supported_formats=[];supported_protections=[]
    def can_handle(self,artifact,context):return False
    def verify_password(self,artifact,password,context):return {'valid':False,'reason':'not_supported'}
    def extract(self,artifact,password,context):return []
    def inspect_error(self,error):return {'reason':'adapter_error','message':str(error)}
    def cleanup(self,context):return None
    @staticmethod
    def path(artifact):return Path(artifact['path'])
