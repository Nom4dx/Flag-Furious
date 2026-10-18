"""Heuristic segmentation for unidentified raw binary data.

The analyzer finds padding, repeated blocks, aligned integer tables and abrupt
entropy changes. Results remain candidates with moderate confidence; they are not
presented as parsed sections or executable code.
"""

from collections import Counter
import struct

from .entropy_analyzer import shannon


def analyze(data:bytes,base_offset:int=0)->dict:
    """Return candidate regions and plausible endian values from a bounded view."""
    regions=[]
    cursor=0
    while cursor<len(data):
        value=data[cursor];end=cursor+1
        while end<len(data) and data[end]==value:end+=1
        if end-cursor>=64 and value in (0,0xff):regions.append({"start_offset":base_offset+cursor,"end_offset":base_offset+end,"length":end-cursor,"type":"padding","confidence":.98,"evidence":[f"byte {value:02x} ripetuto"]})
        cursor=end
    block=256
    counts=Counter(data[i:i+block] for i in range(0,len(data)-block+1,block))
    for sample,count in counts.most_common(16):
        if count>=3 and len(set(sample))>1:
            first=data.find(sample);regions.append({"start_offset":base_offset+first,"end_offset":base_offset+first+block,"length":block,"type":"repeated_block","repetitions":count,"confidence":.8,"evidence":["blocco da 256 byte ripetuto"]})
    integers=[]
    for offset in range(0,min(len(data)-4,4096),4):
        little,big=struct.unpack_from("<I",data,offset)[0],struct.unpack_from(">I",data,offset)[0]
        for endian,value in (("little",little),("big",big)):
            if value and value<len(data) and value%4==0:integers.append({"offset":base_offset+offset,"value":value,"endian":endian,"interpretation":"possible_offset","confidence":.52})
    return {"regions":regions[:1024],"integer_candidates":integers[:1024],"entropy":shannon(data),"classification":"unknown_region"}
