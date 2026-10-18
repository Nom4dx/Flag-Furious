"""Audited adapters for optional passive local log-analysis tools."""
from pathlib import Path
import shutil,subprocess,time
class ToolRunner:
    """Run allow-listed parsers without shell, network or unbounded output."""
    ALLOWED={'journalctl','chainsaw','hayabusa','EvtxECmd','jq','rg','zeek','suricata','logstash'}
    def __init__(self):self.audit=[]
    def available(self,name):return name in self.ALLOWED and shutil.which(name) is not None
    def run(self,args,timeout=30,max_output=16*1024*1024):
        """Execute a fixed argument array and retain bounded stdout/stderr metadata."""
        if not args or args[0] not in self.ALLOWED:raise ValueError('Tool log non autorizzato')
        if not self.available(args[0]):return {"command":args,"available":False,"exit_code":None,"stdout":b'',"stderr":"tool non installato","duration":0}
        started=time.monotonic()
        try:
            done=subprocess.run(args,capture_output=True,shell=False,check=False,timeout=min(120,max(1,timeout)))
            row={"command":args,"available":True,"exit_code":done.returncode,"stdout":done.stdout[:max_output],"stderr":done.stderr[:1024*1024].decode('utf-8','replace'),"duration":round(time.monotonic()-started,4),"output_truncated":len(done.stdout)>max_output}
        except subprocess.TimeoutExpired as exc:row={"command":args,"available":True,"exit_code":None,"stdout":bytes(exc.stdout or b'')[:max_output],"stderr":"timeout","duration":round(time.monotonic()-started,4),"timeout":True}
        self.audit.append({**row,"stdout":row['stdout'][:2048].decode('utf-8','replace')});return row
    def journal_export(self,path:Path):
        """Convert one binary journal to export format using read-only journalctl."""
        return self.run(['journalctl','--file',str(path),'--output=export','--no-pager'],60)
    def inventory(self):
        """Return installed state without executing every heavy third-party tool."""
        return [{"tool":name,"available":self.available(name)} for name in sorted(self.ALLOWED)]
