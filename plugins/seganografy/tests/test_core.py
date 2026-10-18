"""Regression tests for extraction/validation boundaries and false-positive controls."""
from pathlib import Path
import gzip
import io
import zipfile
import pytest
from plugins.seganografy.src import unicode_steg, whitespace_steg, image_steg, audio_steg
from plugins.seganografy.src.container_extract import ArtifactStore, extract_zip
from plugins.seganografy.src.decoders import decode_candidates
from plugins.seganografy.src.limits import Limits
from plugins.seganografy.src.signatures import scan, validate_candidates

FIX=Path(__file__).parents[1]/'fixtures'

def test_unicode_invisible_extracts_bits():
 r=unicode_steg.analyze((FIX/'zero-width.txt').read_text(), 'x', '0'*64)
 assert any(x['output'].startswith(b'FLAG{unicode_fixture}') for x in r['symbol_channels'])
 assert r['suspicious'] and r['variants']['codepoints.txt']

def test_bidi_and_homoglyph_inventory():
 r=unicode_steg.analyze((FIX/'bidi-homoglyph.txt').read_text(), 'x', '0'*64)
 assert r['visual_logical_difference_possible']
 assert r['mixed_script']

def test_whitespace_bits():
 r=whitespace_steg.analyze((FIX/'whitespace.txt').read_text(), 'x')
 assert any(b'FLAG{unicode_fixture}' in x['output'] for x in r['candidates'])

def test_recursive_compression_is_bounded():
 encoded=(FIX/'base64-gzip.txt').read_bytes()
 first=next(x for x in decode_candidates(encoded, 4096, ['FLAG']) if x['decoder_chain']==['base64'])
 second=next(x for x in decode_candidates(first['output'],4096,['FLAG']) if x['decoder_chain']==['gzip'])
 assert second['output']==b'FLAG{recursive_fixture}'
 bomb=gzip.compress(b'A'*10000)
 assert not any(x['decoder_chain']==['gzip'] for x in decode_candidates(bomb, 100, []))

def test_png_lsb_and_wav_lsb():
 pytest.importorskip('PIL')
 image=image_steg.analyze(FIX/'lsb-rgb.png','quick',32,4096,2,4096)
 assert any(b'FLAG{png_fixture}' in x['data'] for x in image['candidates'])
 audio=audio_steg.analyze(FIX/'lsb.wav',4096,32)
 assert any(b'FLAG{wav_fixture}' in x['data'] for x in audio['candidates'])

def test_signature_hit_requires_validation(tmp_path):
 fake=tmp_path/'fake.bin'; fake.write_bytes(b'noise PK\x03\x04 not a zip')
 hits,_=scan(fake,1024)
 valid,rejected=validate_candidates(fake,hits,fake.stat().st_size,1024)
 assert any(x['format']=='zip' for x in rejected)
 assert not any(x['format']=='zip' for x in valid)

def test_zip_slip_and_symlink_are_blocked(tmp_path):
 stream=io.BytesIO()
 with zipfile.ZipFile(stream,'w') as z:
  z.writestr('../escape.txt','no')
  info=zipfile.ZipInfo('link'); info.external_attr=(0o120777<<16); z.writestr(info,'target')
  z.writestr('safe.txt','FLAG{safe}')
 store=ArtifactStore(tmp_path/'out',Limits(1024*1024,1024*1024))
 result=extract_zip(stream.getvalue(),store,Limits(1024*1024,1024*1024),'fixture')
 assert len(result['artifacts'])==1
 assert not (tmp_path/'escape.txt').exists()
 assert any('path traversal' in x for x in result['warnings']) and any('symlink' in x for x in result['warnings'])

def test_every_required_fixture_is_local():
 required={'zero-width.txt','bidi-homoglyph.txt','whitespace.txt','base64-gzip.txt','brainfuck.txt','unknown-payload.bin','lsb.wav'}
 assert required <= {x.name for x in FIX.iterdir()}
