"""Interactive event, attack-chain and flag-reconstruction graph builders."""
def events_graph(events,entities,sessions,findings,links,limit=600):
    """Build file→event→entity/session/finding relationships with stable IDs."""
    nodes=[];edges=[];files=sorted({x['source_file'] for x in events})
    nodes.extend({"id":"file:"+x,"type":"file","label":x,"status":"validated"} for x in files)
    visible=events[:min(limit,600)];ids={x['event_id'] for x in visible}
    for event in visible:
        nodes.append({"id":event['event_id'],"type":"event","label":event.get('action') or event.get('event_type'),"timestamp":event.get('timestamp'),"source":event['source_file'],"line":event['source_line'],"offset":event['source_offset'],"confidence":event['confidence'],"status":"validated"});edges.append({"source":"file:"+event['source_file'],"target":event['event_id'],"relation":"contains"})
    entity_ids={}
    for entity in entities[:600]:
        if entity['event_id'] not in ids:continue
        key=f"entity:{entity['type']}:{entity['value']}";entity_ids[key]=entity;edges.append({"source":entity['event_id'],"target":key,"relation":"contains"})
    nodes.extend({"id":key,"type":value['type'],"label":value['value'],"confidence":value['confidence'],"status":"validated"} for key,value in entity_ids.items())
    for session in sessions[:200]:
        nodes.append({"id":session['session_id'],"type":"session","label":session['correlation_key'][:80],"status":"validated","confidence":session['confidence']})
        for event_id in session['events'][:100]:
            if event_id in ids:edges.append({"source":event_id,"target":session['session_id'],"relation":"belongs_to"})
    for finding in findings[:200]:
        nodes.append({"id":finding['finding_id'],"type":"finding","label":finding['type'],"severity":finding['severity'],"confidence":finding['confidence'],"status":"partial"})
        for event_id in finding.get('matched_events',[])[:100]:
            if event_id in ids:edges.append({"source":event_id,"target":finding['finding_id'],"relation":"related_to"})
    edges.extend(x for x in links[:10000] if x['source'] in ids and x['target'] in ids)
    return {"nodes":nodes,"edges":edges,"hidden_events":max(0,len(events)-len(visible))}
def attack_graph(chains):
    """Represent ordered attack stages and their finding evidence."""
    nodes=[];edges=[]
    for chain in chains:
        previous=None
        for index,stage in enumerate(chain['attack_stage']):
            key=f"{chain['chain_id']}:stage:{index}";nodes.append({"id":key,"type":"attack_stage","label":stage['stage'],"status":"candidate","confidence":chain['confidence']})
            if previous:edges.append({"source":previous,"target":key,"relation":"followed_by"})
            previous=key
    return {"nodes":nodes,"edges":edges}
def flag_graph(flags):
    """Represent source events, decoder chains and reconstructed candidates."""
    nodes=[];edges=[];seen=set()
    for index,flag in enumerate(flags[:300]):
        flag_id=f'flag:{index}';nodes.append({"id":flag_id,"type":"flag","label":flag['value'][:80],"status":flag['status'],"confidence":flag['confidence']})
        for event in flag.get('events',[])[:5]:
            if event not in seen:nodes.append({"id":event,"type":"event","label":event,"status":"validated"});seen.add(event)
            edges.append({"source":event,"target":flag_id,"relation":"contains"})
    return {"nodes":nodes,"edges":edges}
