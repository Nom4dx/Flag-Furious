"""Build the caller→protected→recovery→unlocked→caller execution graph."""
def build(parent,artifact,response):
    """Return graph JSON using the Hub's source/target edge names."""
    nodes=[{'id':'parent','type':'plugin','label':parent},{'id':'protected','type':'protected_artifact','label':artifact.get('name','artifact')},{'id':'recovery','type':'plugin','label':'bruteforce','status':response.get('status')}];edges=[{'source':'parent','target':'protected','relation':'found'},{'source':'protected','target':'recovery','relation':'requires_unlock'}]
    if response.get('password_verified'):nodes.append({'id':'verified','type':'result','label':'Password verificata','status':'success'});edges.append({'source':'recovery','target':'verified','relation':'verified'})
    for i,item in enumerate(response.get('extracted_artifacts',[])):
        key=f'unlocked-{i}';nodes.append({'id':key,'type':'unlocked_artifact','label':item.get('name',key),'status':'unlocked'});edges.extend([{'source':'verified','target':key,'relation':'unlocked'},{'source':key,'target':'parent','relation':'returned_to_parent'}])
    return {'nodes':nodes,'edges':edges}
