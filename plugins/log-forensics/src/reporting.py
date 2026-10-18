"""Normalized section and execution-event constructors."""
import time
def section(section_id,title,order,data,kind='table',status='completed',description=''):
    """Create one independently mapped plugin-dashboard section."""
    return {"id":section_id,"section_id":section_id,"title":title,"description":description,"order":order,"status":status,"content":data,"data":data,"type":kind,"result_count":len(data) if isinstance(data,list) else 1,"artifacts":[]}
def phase(name,started,status='completed'):
    """Return a phase duration for the Hub execution graph."""
    return {"phase":name,"status":status,"duration":round(time.monotonic()-started,4)}
