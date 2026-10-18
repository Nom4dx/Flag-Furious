"""Audited adapters for optional passive local log-analysis tools."""
from pathlib import Path
import shutil
from app.core.bounded_process import run_bounded
MAX_TOTAL_OUTPUT = 64 * 1024 * 1024

class ToolRunner:
    """Run allow-listed parsers without shell, network or unbounded output."""
    ALLOWED={'journalctl','chainsaw','hayabusa','EvtxECmd','jq','rg','zeek','suricata','logstash'}
    def __init__(self,max_total_output=MAX_TOTAL_OUTPUT):self.audit=[];self.max_total_output=max(0,int(max_total_output));self.output_bytes=0
    def available(self,name):return name in self.ALLOWED and shutil.which(name) is not None
    def run(self,args,timeout=30,max_output=16*1024*1024):
        """Execute a fixed argument array and retain bounded stdout/stderr metadata."""
        if not args or args[0] not in self.ALLOWED:raise ValueError('Tool log non autorizzato')
        if not self.available(args[0]):return {"command":args,"available":False,"exit_code":None,"stdout":b'',"stderr":"tool non installato","duration":0}
        remaining=self.max_total_output-self.output_bytes
        if remaining<=0:
            row={"command":args,"available":True,"exit_code":None,"stdout":b'',"stderr":"budget output cumulativo esaurito","duration":0,"output_truncated":True,"stderr_truncated":False,"timeout":False,"budget_exhausted":True}
            self.audit.append({**row,"stdout":""});return row
        bounded=run_bounded(args,timeout=min(120,max(1,timeout)),max_stdout=min(max(0,max_output),remaining),max_stderr=1024*1024)
        self.output_bytes+=len(bounded["stdout"])
        row={"command":args,"available":True,"exit_code":bounded["returncode"],"stdout":bounded["stdout"],"stderr":bounded["stderr"].decode('utf-8','replace'),"duration":round(bounded["duration"],4),"output_truncated":bounded["stdout_truncated"],"stderr_truncated":bounded["stderr_truncated"],"timeout":bounded["timed_out"],"budget_exhausted":bounded["stdout_truncated"] and self.output_bytes>=self.max_total_output}
        self.audit.append({**row,"stdout":row['stdout'][:2048].decode('utf-8','replace')});return row
    def journal_export(self,path:Path):
        """Convert one binary journal to export format using read-only journalctl."""
        return self.run(['journalctl','--file',str(path),'--output=export','--no-pager'],60)
    def inventory(self):
        """Return installed state without executing every heavy third-party tool."""
        return [{"tool":name,"available":self.available(name)} for name in sorted(self.ALLOWED)]
