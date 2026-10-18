"""Normalized section/finding helpers for the Forensic Hub contract."""


def section(section_id:str,title:str,order:int,data,status:str="completed",kind:str="table",visualization=None)->dict:
    """Create a mapped plugin-dashboard section with stable ordering."""
    return {"id":section_id,"section_id":section_id,"title":title,"description":"","order":order,"status":status,"content":data,"data":data,"type":kind,"visualization":visualization,"result_count":len(data) if isinstance(data,list) else 1,"artifacts":[]}


def finding(kind:str,severity:str,confidence:float,explanation:str,offset:int=0,section_name=None,evidence=None)->dict:
    """Create an evidence-backed indicator without a malware verdict."""
    return {"type":kind,"severity":severity,"confidence":confidence,"evidence":evidence or [explanation],"offset":offset,"section":section_name,"explanation":explanation}
