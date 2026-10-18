"""Audited subprocess adapter for optional passive analysis tools.

Commands are fixed argument arrays, run without a shell, with time/output limits
and no sample execution. The Hub's bubblewrap namespace removes network access and
writable host mounts before this code runs.
"""

from pathlib import Path
import shutil
from app.core.bounded_process import run_bounded


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
        bounded=run_bounded(args,timeout=max(1,min(timeout,60)),max_stdout=max_output,max_stderr=max_output)
        result={"command":args,"available":True,"exit_code":bounded["returncode"],"stdout":bounded["stdout"].decode("utf-8","replace"),"stderr":bounded["stderr"].decode("utf-8","replace"),"duration":round(bounded["duration"],4),"output_truncated":bounded["truncated"],"timeout":bounded["timed_out"]}
        self.audit.append(result);return result

    def inventory(self)->list[dict]:
        """Return availability for optional tools and versions for tools actually used."""
        used = {
            Path(record["command"][0]).name
            for record in self.audit
            if record.get("command") and isinstance(record["command"][0], str)
        }
        rows=[]
        for name in sorted(self.ALLOWED):
            present=self.available(name);version=""
            if present and name in used:
                flag="-version" if name=="file" else "--version"
                version=self.run([name,flag],timeout=3,max_output=2048).get("stdout","").splitlines()[:1]
                version=version[0] if version else "disponibile"
            elif present:
                version="disponibile; non invocato in questa analisi"
            rows.append({"tool":name,"available":present,"version":version})
        return rows
