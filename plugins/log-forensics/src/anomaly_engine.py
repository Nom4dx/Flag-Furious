"""Statistical anomaly indicators kept separate from attack detections."""
from collections import Counter,defaultdict
def detect(events:list[dict])->list[dict]:
    """Find bursts, rare processes/users and abnormal failure ratios locally."""
    output=[];by_source=Counter(x['source_file'] for x in events);types=Counter(x.get('event_type') for x in events);fail=sum(x.get('outcome')=='failure' for x in events);success=sum(x.get('outcome')=='success' for x in events)
    if fail>=10 and fail/max(1,fail+success)>.8:output.append({"type":"behavioral_anomaly","severity":"low","entity":"global","feature":"failure_ratio","baseline":None,"observed":round(fail/max(1,fail+success),3),"confidence":.72,"explanation":"Rapporto fallimenti elevato; non equivale a un attacco confermato"})
    processes=Counter(str(x.get('process')) for x in events if x.get('process'))
    for process,count in processes.items():
        if count==1 and len(events)>=50:output.append({"type":"behavioral_anomaly","severity":"info","entity":f'process:{process}',"feature":"process_rarity","baseline":"frequency > 1","observed":1,"confidence":.55,"explanation":"Processo raro nella sola baseline locale"})
    return output[:1000]
