"""Optional local-tool inventory and bounded shell-free execution."""

from __future__ import annotations
import shutil,subprocess,time
from .security import mask_command


class ToolRunner:
    """Run fixed argv arrays with timeout, bounded output and secret masking."""
    def __init__(self):self.audit=[]
    def run(self,argv:list[str],timeout:int=60,stdin:bytes|None=None)->dict:
        started=time.monotonic();record={"command":mask_command([str(x) for x in argv]),"version":None}
        try:
            completed=subprocess.run(argv,input=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,timeout=timeout,check=False)
            result={"exit_code":completed.returncode,"stdout":completed.stdout.decode("utf-8","replace")[:1024*1024],"stderr":completed.stderr.decode("utf-8","replace")[:1024*1024]}
        except subprocess.TimeoutExpired as exc:
            result={"exit_code":None,"stdout":bytes(exc.stdout or b"").decode("utf-8","replace")[:1024*1024],"stderr":"timeout","timed_out":True}
        except OSError as exc:result={"exit_code":None,"stdout":"","stderr":str(exc)}
        record.update(result,duration=round(time.monotonic()-started,4));self.audit.append(record);return result
    def inventory(self,names:list[str])->list[dict]:
        """Report binary paths and short versions without failing analysis."""
        rows=[]
        for name in names:
            path=shutil.which(name);version=None
            if path:
                args=[path,"--version"] if name not in {"bitlocker2john","mmls","fls","icat","fsstat"} else [path]
                result=self.run(args,5);version=(result["stdout"] or result["stderr"]).splitlines()[:1]
                version=version[0][:240] if version else "available"
            rows.append({"tool":name,"available":bool(path),"path":path,"version":version})
        return rows
