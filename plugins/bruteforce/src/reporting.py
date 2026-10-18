"""Output section helpers for the common Hub contract."""
def section(i,title,order,data,status='completed'):
    """Create a mapped dashboard section."""
    return {'id':i,'title':title,'order':order,'status':status,'data':data,'count':len(data) if isinstance(data,list) else 1}
