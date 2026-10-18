"""Validated broker request shared by callers and the plugin."""
from pydantic import BaseModel,Field
class UnlockRequest(BaseModel):
    """One local artifact unlock request; paths are validated by the caller/broker."""
    artifact_id:str=""; artifact_path:str=""; source_plugin:str="manual"; detected_format:str=""; protection_type:str="password"; operation:str="extract"; mode:str="ask_user"; allow_wordlists:bool=True; max_attempts:int=100000; timeout_seconds:int=900; stop_on_first_success:bool=True; parent_run_id:str=""; metadata:dict=Field(default_factory=dict); known_password:str|None=None; wordlists:list[str]=Field(default_factory=list); transformations:bool=False
