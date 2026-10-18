"""Declarative charts compatible with the centralized 2D visualization engine."""
from collections import Counter,defaultdict
from datetime import datetime
def build(events:list[dict],timeline:list[dict],sessions:list[dict],findings:list[dict])->list[dict]:
    """Create timeline, volume, authentication and network visualizations."""
    buckets=Counter();auth=Counter();network=Counter()
    for event in events:
        if event.get('timestamp'):
            try:key=datetime.fromisoformat(event['timestamp'].replace('Z','+00:00')).strftime('%Y-%m-%dT%H:00Z');buckets[key]+=1
            except ValueError:pass
        if event.get('action') in {'login_failed','login_success'}:auth[(event.get('source_ip') or '?',event.get('user') or '?',event['action'])]+=1
        if event.get('source_ip') and event.get('destination_ip'):network[(event['source_ip'],event['destination_ip'],str(event.get('destination_port') or ''))]+=1
    return [
      {"type":"timeline","title":"Event Timeline","data":timeline[:10000],"filters":["category","source_file","host","user","source_ip"],"source_events":[x['id'] for x in timeline[:10000]],"palette":"network","options":{"interactive":True,"zoom":True,"pan":True,"tooltip":True}},
      {"type":"bar","title":"Event Volume","data":[{"x":k,"y":v} for k,v in sorted(buckets.items())],"encoding":{"x":{"field":"x","type":"datetime"},"y":{"field":"y","type":"number"}},"palette":"signal","options":{"interactive":True,"zoom":True,"tooltip":True}},
      {"type":"network_graph","title":"Authentication Graph","data":{"nodes":_nodes(auth,'auth'),"edges":[{"source":"ip:"+ip,"target":"user:"+user,"relation":action,"weight":count} for (ip,user,action),count in auth.items()]},"palette":"network","options":{"interactive":True,"zoom":True,"pan":True}},
      {"type":"network_graph","title":"Network Graph","data":{"nodes":_network_nodes(network),"edges":[{"source":"ip:"+src,"target":"ip:"+dst,"relation":"connected_to","port":port,"weight":count} for (src,dst,port),count in network.items()]},"palette":"network","options":{"interactive":True,"zoom":True,"pan":True}}
    ]
def _nodes(values,prefix):
    ips={x[0] for x in values};users={x[1] for x in values};return [{"id":"ip:"+x,"label":x,"type":"ip"} for x in ips]+[{"id":"user:"+x,"label":x,"type":"user"} for x in users]
def _network_nodes(values):
    values={x for pair in values for x in pair[:2]};return [{"id":"ip:"+x,"label":x,"type":"ip"} for x in values]
