"""End-to-end normalized-output, loader and immutability tests."""
import hashlib
import importlib
import json
from app.config import Settings
from app.core.plugin_loader import discover

class Reporter:
    """Minimal reporter recording the public calls used by the plugin."""
    def __init__(self):self.phases=[];self.logs=[];self.results=[]
    def phase(self,value):self.phases.append(value)
    def log(self,value):self.logs.append(value)
    def partial(self,value):self.results.append(value)


def test_loader_contract():
    plugins,errors=discover(Settings().plugins)
    assert "binary-static-analysis" in plugins
    assert not [x for x in errors if x["plugin"]=="binary-static-analysis"]


def test_complete_result_and_original_immutable(package,fixtures,tmp_path):
    module=importlib.import_module(package+".plugin");path=fixtures/"elf64.bin"
    before=hashlib.sha256(path.read_bytes()).hexdigest();reporter=Reporter()
    asset={"id":"asset-1","type":"file","path":str(path),"name":path.name,"mime":"application/octet-stream","hashes":{}}
    context={"output_dir":str(tmp_path),"byte_budget":path.stat().st_size,"output_bytes":10_000_000,"prefixes":["flag"],"patterns":[],"max_flags":20,"plugin_options":{}}
    result=module.Plugin().analyze(asset,context,reporter)
    json.dumps(result)
    assert result["plugin_id"]=="binary-static-analysis"
    assert {"findings","sections","artifacts","derived_assets","visualizations","flags","timeline","execution_events","logs","warnings","errors","metrics"}<=result.keys()
    assert {x["title"] for x in result["visualizations"]}>={"File Structure Graph","Code Analysis Graph"}
    assert hashlib.sha256(path.read_bytes()).hexdigest()==before
    assert result["metrics"]["original_modified"] is False and reporter.results
