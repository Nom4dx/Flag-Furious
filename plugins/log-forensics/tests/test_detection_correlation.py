"""Detection, session and cross-event correlation tests."""
import importlib

def normalized(package,path,fmt):
    registry=importlib.import_module(package+'.src.parser_registry');normalizer=importlib.import_module(package+'.src.normalizer');rows,_=registry.parse(fmt,path.read_bytes(),path.name,{})
    return [normalizer.normalize(x,i,{'timezone':'UTC','reference_year':2026}) for i,x in enumerate(rows)]

def test_bruteforce_and_success_sequence(package,fixtures):
    events=normalized(package,fixtures/'auth.log','syslog');engine=importlib.import_module(package+'.src.detection_engine');findings=engine.detect(events,{})
    assert {'brute_force','success_after_failures'}<={x['type'] for x in findings}

def test_sql_injection_has_event_evidence(package,fixtures):
    events=normalized(package,fixtures/'apache.log','apache');engine=importlib.import_module(package+'.src.detection_engine');rows=engine.detect(events,{})
    item=next(x for x in rows if x['type']=='sql_injection');assert item['matched_events'] and item['confidence']<1

def test_suricata_flow_builds_session_and_scan(package,fixtures):
    events=normalized(package,fixtures/'suricata.jsonl','suricata_eve_json');sessions=importlib.import_module(package+'.src.session_builder').build(events);findings=importlib.import_module(package+'.src.detection_engine').detect(events,{'scan_port_threshold':4})
    assert any(x['correlation_key']=='99' and x['event_count']==5 for x in sessions)
    assert any(x['type']=='port_scan' for x in findings)

def test_anomaly_is_not_attack(package,fixtures):
    events=normalized(package,fixtures/'auth.log','syslog')*3;rows=importlib.import_module(package+'.src.anomaly_engine').detect(events)
    assert rows and all(x['type']=='behavioral_anomaly' for x in rows)
