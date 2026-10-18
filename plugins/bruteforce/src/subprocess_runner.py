"""Allow-listed offline subprocess runner with bounded output and redaction."""
import os
import selectors
import shutil
import subprocess
import time
from pathlib import Path
try:
    import resource
except ImportError:  # Windows does not expose RLIMIT_FSIZE.
    resource = None

ALLOW={'7z','7zz','unrar','qpdf','steghide','stegseek','openstego','stegcloak','stegsnow','gpg','openssl','bitlocker2john','dislocker-file','hashcat'}
OUTPUT_LIMIT=1024*1024

def run(tool,args,timeout,cwd=None,secret_indexes=(),output_path=None,max_stdout=OUTPUT_LIMIT,input_data=None,max_file_size=None):
    """Run an allow-listed command with bounded time, streams and optional file growth."""
    binary=shutil.which(tool) if tool in ALLOW else None
    display=[tool,*map(str,args)]
    for i in secret_indexes:
        if 0<=i+1<len(display):display[i+1]='********'
    if not binary:return {'tool':tool,'available':False,'status':'tool_missing','command':display,'exit_code':None,'stdout':'','stderr':'tool not installed','duration':0}
    if max_file_size is not None and resource is None:
        return {'tool':tool,'available':True,'status':'file_size_limit_unavailable','command':display,'exit_code':None,'stdout':'','stderr':'file size limit unavailable','duration':0}
    output=Path(output_path).open('xb') if output_path is not None else None
    start=time.monotonic();p=None;streams={'stdout':bytearray(),'stderr':bytearray()};truncated=False
    try:
        def set_file_limit():
            if max_file_size is not None:
                resource.setrlimit(resource.RLIMIT_FSIZE,(max(0,int(max_file_size)),max(0,int(max_file_size))))
        p=subprocess.Popen([binary,*map(str,args)],cwd=cwd,stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'LANG':'C.UTF-8','HOME':'/nonexistent'},start_new_session=True,preexec_fn=set_file_limit if max_file_size is not None else None)
        if input_data is not None:
            try:p.stdin.write(input_data);p.stdin.close()
            except BrokenPipeError:pass
        with selectors.DefaultSelector() as selector:
            for name,pipe in (('stdout',p.stdout),('stderr',p.stderr)):
                selector.register(pipe,selectors.EVENT_READ,name)
            while selector.get_map():
                remaining=timeout-(time.monotonic()-start)
                if remaining<=0:raise TimeoutError
                for key,_ in selector.select(min(remaining,0.25)):
                    data=os.read(key.fileobj.fileno(),65536)
                    if not data:
                        selector.unregister(key.fileobj);key.fileobj.close();continue
                    if key.data=='stdout' and output is not None:
                        room=max_stdout-output.tell()
                        if room>0:output.write(data[:room])
                    else:
                        target=streams[key.data];room=(max_stdout if key.data=='stdout' else OUTPUT_LIMIT)-len(target)
                        if room>0:target.extend(data[:room])
                    if len(data)>room:
                        truncated=True
                        os.killpg(p.pid,9)
                        for active in list(selector.get_map().values()):
                            selector.unregister(active.fileobj);active.fileobj.close()
                        break
        code=p.wait(timeout=max(0.1,timeout-(time.monotonic()-start)))
        status='output_limit' if truncated else 'completed' if code==0 else 'failed'
        return {'tool':tool,'available':True,'status':status,'command':display,'exit_code':code,'stdout':bytes(streams['stdout']).decode(errors='replace'),'stderr':bytes(streams['stderr']).decode(errors='replace'),'output_truncated':truncated,'stdout_bytes':output.tell() if output is not None else len(streams['stdout']),'output_path':str(output_path) if output_path is not None else None,'duration':round(time.monotonic()-start,4)}
    except TimeoutError:
        if p and p.poll() is None:
            os.killpg(p.pid,9);p.wait()
        return {'tool':tool,'available':True,'status':'timeout','command':display,'exit_code':None,'stdout':bytes(streams['stdout']).decode(errors='replace'),'stderr':bytes(streams['stderr']).decode(errors='replace'),'output_truncated':False,'stdout_bytes':output.tell() if output is not None else len(streams['stdout']),'output_path':str(output_path) if output_path is not None else None,'duration':round(time.monotonic()-start,4)}
    except OSError as error:
        if p and p.poll() is None:os.killpg(p.pid,9);p.wait()
        return {'tool':tool,'available':True,'status':'failed','command':display,'exit_code':None,'stdout':'','stderr':type(error).__name__,'output_truncated':False,'stdout_bytes':output.tell() if output is not None else 0,'output_path':str(output_path) if output_path is not None else None,'duration':round(time.monotonic()-start,4)}
    finally:
        if output is not None:output.close()
