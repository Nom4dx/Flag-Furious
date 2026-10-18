"""Loader-contract and immutable-evidence integration tests."""
from pathlib import Path
import hashlib
import json
from plugins.seganografy.plugin import Plugin

class Reporter:
 def phase(self,*a,**k): pass
 def log(self,*a,**k): pass
 def progress(self,*a,**k): pass
 def partial(self,*a,**k): pass

FIX=Path(__file__).parents[1]/'fixtures'

def test_plugin_output_json_and_original_immutable(tmp_path):
 source=tmp_path/'input.txt'; source.write_bytes((FIX/'zero-width.txt').read_bytes())
 before=hashlib.sha256(source.read_bytes()).hexdigest()
 result=Plugin().analyze({'path':str(source),'name':source.name,'type':'file'}, {'output_dir':str(tmp_path/'out'),'prefixes':['FLAG'],'mode':'quick','byte_budget':2**20,'output_budget':2**20}, Reporter())
 assert hashlib.sha256(source.read_bytes()).hexdigest()==before
 assert result['status'] in {'completed','partial'} and result['flags']
 assert any(x['id']=='metrics' for x in result['sections'])
 json.dumps({k:v for k,v in result.items() if k!='artifacts'})

def test_manifest_and_alias():
 manifest=json.loads((Path(__file__).parents[1]/'plugin.json').read_text())
 assert manifest['id']=='seganografy'
 assert 'steganography-forensics' in manifest['aliases']
 assert manifest['requires_network'] is False and manifest['requires_root'] is False
