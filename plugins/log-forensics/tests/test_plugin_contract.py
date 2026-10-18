"""Loader, normalized output, UI mapping and immutable evidence tests."""
import hashlib,importlib,json
from app.config import Settings
from app.core.plugin_loader import discover
class Reporter:
    def __init__(self):self.result=None
    def phase(self,value):pass
    def log(self,value):pass
    def partial(self,value):self.result=value

def test_loader_and_mapping():
    plugins,errors=discover(Settings().plugins);assert 'log-forensics' in plugins;assert not [x for x in errors if x['plugin']=='log-forensics']

def test_end_to_end_contract(package,fixtures,tmp_path):
    plugin=importlib.import_module(package+'.plugin').Plugin();path=fixtures/'auth.log';before=hashlib.sha256(path.read_bytes()).hexdigest();reporter=Reporter()
    result=plugin.analyze({'id':'asset','type':'file','path':str(path),'name':path.name,'mime':'text/plain'},{'output_dir':str(tmp_path),'byte_budget':1_000_000,'output_bytes':10_000_000,'prefixes':['flag'],'patterns':[],'plugin_options':{}},reporter)
    json.dumps(result);required={'findings','sections','artifacts','derived_assets','visualizations','flags','timeline','execution_events','logs','warnings','errors','metrics'}
    assert required<=result.keys() and result['metrics']['events']==7
    assert {'Event Timeline','Event Correlation Graph','Attack Chain Graph'}<={x['title'] for x in result['visualizations']}
    assert hashlib.sha256(path.read_bytes()).hexdigest()==before and reporter.result is result

def test_ui_filters_and_scroll_contract():
    root=Settings().root;presentation=(root/'frontend/js/presentation.js').read_text();app=(root/'frontend/js/app.js').read_text()
    for field in ('parser','host','user','source_ip','session_id','severity'):assert f'"{field}"' in presentation
    assert '$("follow-logs").checked && nearBottom' in app and '$("outputs").scrollTop = 0' in app
