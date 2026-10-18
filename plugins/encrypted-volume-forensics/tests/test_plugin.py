"""End-to-end contract test over a synthetic metadata-only volume."""
from conftest import load_module

class Reporter:
    def __init__(self):self.phases=[];self.logs=[];self.results=[]
    def phase(self,value):self.phases.append(value)
    def log(self,value):self.logs.append(value)
    def partial(self,value):self.results.append(value)

def test_plugin_normalized_output_and_original_immutable(whole_fve,tmp_path):
    before=whole_fve.read_bytes();plugin=load_module('plugin').Plugin();reporter=Reporter()
    asset={'id':'asset-1','name':'renamed.dat','type':'disk_image','path':str(whole_fve)}
    context={'output_dir':str(tmp_path/'out'),'byte_budget':whole_fve.stat().st_size,'output_bytes':16*1024*1024,'prefixes':['picoCTF'],'plugin_options':{'encrypted-volume-forensics':{'extract_hash':False}}}
    result=plugin.analyze(asset,context,reporter)
    assert result['plugin_id']=='encrypted-volume-forensics'
    assert result['metrics']['bitlocker_volumes']==1 and result['metrics']['original_modified'] is False
    assert result['unlock_requests'][0]['protection_type']=='bitlocker'
    assert {'findings','sections','artifacts','visualizations','flags','timeline','warnings','errors','metrics'}<=result.keys()
    assert before==whole_fve.read_bytes()
