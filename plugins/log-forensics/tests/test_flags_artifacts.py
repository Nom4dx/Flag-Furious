"""Recursive decoding, flag reconstruction and safe compressed-input tests."""
import importlib,tempfile
from pathlib import Path

def _events(package,path):
    parser=importlib.import_module(package+'.src.parsers.jsonl');normalizer=importlib.import_module(package+'.src.normalizer');raw=parser.parse(path.read_bytes(),path.name,{})
    return [{**normalizer.normalize(x,i,{'timezone':'UTC'}),'raw':x['raw'],'raw_fields':x['raw_fields']} for i,x in enumerate(raw)]

def test_cross_event_flag_reconstruction(package,fixtures):
    events=_events(package,fixtures/'fragments.jsonl');flags,_=importlib.import_module(package+'.src.flag_hunter').hunt(events,[],{'prefixes':['picoCTF'],'patterns':[]})
    assert any(x['value']=='picoCTF{cross_event}' and x['ordering_strategy']=='timestamp' for x in flags)

def test_base64_flag_has_decoder_chain(package,fixtures):
    generic=importlib.import_module(package+'.src.parsers.logfmt');normalizer=importlib.import_module(package+'.src.normalizer');raw=generic.parse((fixtures/'encoded.log').read_bytes(),'encoded.log',{});events=[{**normalizer.normalize(x,i,{'timezone':'UTC'}),'raw':x['raw'],'raw_fields':x['raw_fields']} for i,x in enumerate(raw)]
    decoded=importlib.import_module(package+'.src.decoder_pipeline').decode_events(events);public=[{k:v for k,v in x.items() if k!='bytes'} for x in decoded];flags,_=importlib.import_module(package+'.src.flag_hunter').hunt(events,public,{'prefixes':['picoCTF'],'patterns':[]})
    assert any(x['value']=='picoCTF{decoded}' and 'base64' in x['decoder_chain'] for x in flags)

def test_gzip_and_zip_safe_extraction(package,fixtures,tmp_path):
    manager=importlib.import_module(package+'.src.artifact_manager').ArtifactManager(tmp_path,10_000_000);collect=importlib.import_module(package+'.src.archive_reader').collect
    for name in ('rotated.log.gz','logs.zip'):
        sources,artifacts,warnings,used=collect(fixtures/name,1_000_000,manager)
        assert sources and artifacts and used>0
