"""Audited subprocess adapter for optional passive analysis tools.

Commands are fixed argument arrays, run without a shell, with time/output limits
and no sample execution. The Hub's bubblewrap namespace removes network access and
writable host mounts before this code runs.
"""

from pathlib import Path
import shutil
import subprocess
import time


class ToolRunner:
    """Execute allow-listed local parsers and retain bounded audit records."""
    ALLOWED={"file","readelf","objdump","strings","binwalk","yara","r2","llvm-objdump","llvm-readobj","uefiextract","unsquashfs","dtc","7z"}
    def __init__(self):self.audit=[]

    def available(self,name:str)->bool:
        """Return whether an allow-listed executable exists in the sandbox PATH."""
        return name in self.ALLOWED and shutil.which(name) is not None

    def run(self,args:list[str],timeout:int=15,max_output:int=1024*1024)->dict:
        """Run one fixed passive command and return exit code/stdout/stderr/duration."""
        if not args or args[0] not in self.ALLOWED:raise ValueError("Tool non autorizzato")
        if not self.available(args[0]):
            result={"command":args,"available":False,"exit_code":None,"stdout":"","stderr":"tool non installato","duration":0};self.audit.append(result);return result
        started=time.monotonic()
        try:
            completed=subprocess.run(args,capture_output=True,timeout=max(1,min(timeout,60)),shell=False,check=False)
            result={"command":args,"available":True,"exit_code":completed.returncode,"stdout":completed.stdout[:max_output].decode("utf-8","replace"),"stderr":completed.stderr[:max_output].decode("utf-8","replace"),"duration":round(time.monotonic()-started,4),"output_truncated":len(completed.stdout)>max_output or len(completed.stderr)>max_output}
        except subprocess.TimeoutExpired as exc:
            result={"command":args,"available":True,"exit_code":None,"stdout":bytes(exc.stdout or b"")[:max_output].decode("utf-8","replace"),"stderr":"timeout","duration":round(time.monotonic()-started,4),"timeout":True}
        self.audit.append(result);return result

    def inventory(self)->list[dict]:
        """Return installed state and bounded version text for optional tools."""
        rows=[]
        for name in sorted(self.ALLOWED):
            present=self.available(name);version=""
            if present:
                flag="-version" if name=="file" else "--version"
                version=self.run([name,flag],timeout=3,max_output=2048).get("stdout","").splitlines()[:1]
                version=version[0] if version else "disponibile"
            rows.append({"tool":name,"available":present,"version":version})
        return rows
