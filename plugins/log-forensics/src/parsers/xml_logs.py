"""Namespace-aware passive XML log parser with bounded element flattening."""
import xml.etree.ElementTree as ET
from .generic import event
def local(tag):return tag.rsplit('}',1)[-1]
def flatten(node,prefix='',limit=2048):
    """Flatten attributes/text to path keys without evaluating XML content."""
    fields={}
    for element in node.iter():
        key=(prefix+'.' if prefix else '')+local(element.tag)
        for name,value in element.attrib.items():fields[f'{key}.@{local(name)}']=value
        if element.text and element.text.strip():fields[key]=element.text.strip()
        if len(fields)>=limit:break
    return fields
def parse(data,source,context):
    """Parse one XML document; entities and external resources are unsupported."""
    try:root=ET.fromstring(data)
    except ET.ParseError as exc:return [event(source,1,0,data[:4096].decode('utf-8','replace'),{"parse_error":str(exc)},'xml_corrupt')]
    nodes=[x for x in root.iter() if local(x.tag) in {'Event','event','record','Record'}] or [root];out=[]
    for index,node in enumerate(nodes[:context.get('max_events',200000)],1):
        fields=flatten(node);ts=next((v for k,v in fields.items() if k.casefold().endswith(('@systemtime','.timestamp','.timecreated'))),None);out.append(event(source,index,0,ET.tostring(node,encoding='unicode'),fields,'xml',ts)|{"xml_path":f'/{local(root.tag)}/{local(node.tag)}[{index}]'})
    return out
