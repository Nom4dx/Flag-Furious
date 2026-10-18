"""Windows Event XML mapper preserving provider, IDs, execution and event data."""
import xml.etree.ElementTree as ET
from .generic import event
from .xml_logs import local
def parse(data,source,context):
    """Convert Event elements into structured raw fields and retain original XML."""
    try:root=ET.fromstring(data)
    except ET.ParseError as exc:return [event(source,1,0,data[:4096].decode('utf-8','replace'),{"parse_error":str(exc)},'windows_xml_corrupt')]
    nodes=[root] if local(root.tag)=='Event' else [x for x in root.iter() if local(x.tag)=='Event'];out=[]
    for index,node in enumerate(nodes[:context.get('max_events',200000)],1):
        fields={}
        for child in node.iter():
            name=local(child.tag);text=(child.text or '').strip()
            if name=='Provider':fields['provider']=child.attrib.get('Name')
            elif name=='TimeCreated':fields['timestamp']=child.attrib.get('SystemTime')
            elif name=='Execution':fields.update(process_id=child.attrib.get('ProcessID'),thread_id=child.attrib.get('ThreadID'))
            elif name=='Security':fields['user_sid']=child.attrib.get('UserID')
            elif name=='Data':fields[child.attrib.get('Name') or f'data_{len(fields)}']=text
            elif text and name in {'EventID','Version','Level','Task','Opcode','Keywords','EventRecordID','Channel','Computer','Message'}:fields[name.casefold()]=text
        raw=ET.tostring(node,encoding='unicode');out.append(event(source,index,0,raw,fields,'windows_xml',fields.get('timestamp'))|{"event_xml":raw})
    return out
