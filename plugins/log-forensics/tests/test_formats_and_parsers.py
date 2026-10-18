"""Content-first detection and parser recovery tests."""
import importlib

def test_web_syslog_and_iis_detection(package,fixtures):
    detector=importlib.import_module(package+'.src.format_detector')
    assert detector.detect((fixtures/'apache.log').read_bytes(),'wrong.bin')[0]['detected_format']=='apache'
    assert detector.detect((fixtures/'syslog.log').read_bytes(),'x.txt')[0]['detected_format']=='syslog'
    assert detector.detect((fixtures/'iis.log').read_bytes(),'x.log')[0]['detected_format']=='iis_w3c'

def test_suricata_schema_over_extension(package,fixtures):
    detector=importlib.import_module(package+'.src.format_detector');result=detector.detect((fixtures/'suricata.jsonl').read_bytes(),'events.log')
    assert result[0]['detected_format']=='suricata_eve_json' and result[0]['confidence']>.9

def test_jsonl_corrupt_line_is_preserved(package,fixtures):
    parser=importlib.import_module(package+'.src.parsers.jsonl');rows=parser.parse((fixtures/'mixed.jsonl').read_bytes(),'mixed.jsonl',{})
    assert len(rows)==3 and any(x['parser']=='jsonl_corrupt' for x in rows)

def test_csv_cef_leef_and_zeek(package,fixtures):
    registry=importlib.import_module(package+'.src.parser_registry')
    for fmt,name in [('csv_tsv','events.csv'),('cef','cef.log'),('leef','leef.log'),('zeek_tsv','zeek.log')]:
        rows,warnings=registry.parse(fmt,(fixtures/name).read_bytes(),name,{})
        assert rows and not warnings,(fmt,warnings)

def test_windows_xml_is_structured(package,fixtures):
    parser=importlib.import_module(package+'.src.parsers.windows_xml');rows=parser.parse((fixtures/'windows.xml').read_bytes(),'windows.xml',{})
    assert rows[0]['raw_fields']['eventid']=='1' and rows[0]['raw_fields']['provider']=='Microsoft-Windows-Sysmon'
