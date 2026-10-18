"""Normalized section, finding and phase helpers for the Hub contract."""

from __future__ import annotations
import time


def section(section_id:str,title:str,order:int,data,status:str="completed",kind:str="table",visualization=None)->dict:
    """Create a stable mapped dashboard section."""
    return {"id":section_id,"section_id":section_id,"title":title,"description":"","order":order,"status":status,
            "content":data,"data":data,"type":kind,"visualization":visualization,
            "result_count":len(data) if isinstance(data,list) else int(data is not None),"artifacts":[]}


def finding(kind:str,severity:str,confidence:float,description:str,source:str,offset:int|None=None,evidence:list|None=None,artifacts:list|None=None)->dict:
    """Create an evidence-backed statement without exposing a secret."""
    return {"type":kind,"severity":severity,"confidence":confidence,"description":description,"explanation":description,
            "source":source,"offset":offset,"evidence":evidence or [description],"related_artifacts":artifacts or [],"parser":"encrypted-volume-forensics"}


def event(name:str,started:float,status:str="completed",details:dict|None=None)->dict:
    """Finish a phase event with duration and optional non-secret details."""
    return {"phase":name,"status":status,"duration":round(time.monotonic()-started,4),**(details or {})}
