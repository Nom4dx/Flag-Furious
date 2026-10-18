"""Persistent-safe response model: raw passwords are deliberately absent."""
from pydantic import BaseModel,Field
class UnlockResponse(BaseModel):
    """Broker outcome containing only an expiring opaque secret reference."""
    request_id:str; status:str; artifact_id:str=""; password_verified:bool=False; password_display:str=""; secret_ref:str|None=None; adapter:str=""; extracted_artifacts:list[dict]=Field(default_factory=list); attempts:int=0; duration_seconds:float=0; wordlists_used:list[str]=Field(default_factory=list); reason:str|None=None
