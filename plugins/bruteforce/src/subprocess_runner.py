"""Allow-listed offline subprocess runner with bounded output and redaction."""
import os
import selectors
import shutil
import subprocess
import time

ALLOW={'7z','7zz','unrar','qpdf','steghide','stegseek','openstego','stegcloak','stegsnow','gpg','openssl','bitlocker2john'}
OUTPUT_LIMIT=1024*1024

def run(tool,args,timeout,cwd=None,secret_indexes=()):
    """Run argv without shell/network, capping captured bytes and elapsed time."""
    binary=shutil.which(tool) if tool in ALLOW else None
    display=[tool,*map(str,args)]
    for i in secret_indexes:
        if 0<=i+1<len(display):display[i+1]='********'
    if not binary:return {'tool':tool,'available':False,'status':'tool_missing','command':display,'exit_code':None,'stdout':'','stderr':'tool not installed','duration':0}
    start=time.monotonic();p=None;streams={'stdout':bytearray(),'stderr':bytearray()};truncated=False
    try:
        p=subprocess.Popen([binary,*map(str,args)],cwd=cwd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'LANG':'C.UTF-8','HOME':'/nonexistent'},start_new_session=True)
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
                    target=streams[key.data];room=OUTPUT_LIMIT-len(target)
                    target.extend(data[:room])
                    if len(data)>room:
                        truncated=True
                        os.killpg(p.pid,9)
                        for active in list(selector.get_map().values()):
                            selector.unregister(active.fileobj);active.fileobj.close()
                        break
        code=p.wait(timeout=max(0.1,timeout-(time.monotonic()-start)))
        status='output_limit' if truncated else 'completed' if code==0 else 'failed'
        return {'tool':tool,'available':True,'status':status,'command':display,'exit_code':code,'stdout':bytes(streams['stdout']).decode(errors='replace'),'stderr':bytes(streams['stderr']).decode(errors='replace'),'output_truncated':truncated,'duration':round(time.monotonic()-start,4)}
    except TimeoutError:
        if p and p.poll() is None:
            os.killpg(p.pid,9);p.wait()
        return {'tool':tool,'available':True,'status':'timeout','command':display,'exit_code':None,'stdout':bytes(streams['stdout']).decode(errors='replace'),'stderr':bytes(streams['stderr']).decode(errors='replace'),'output_truncated':False,'duration':round(time.monotonic()-start,4)}
    except OSError as error:
        if p and p.poll() is None:os.killpg(p.pid,9);p.wait()
        return {'tool':tool,'available':True,'status':'failed','command':display,'exit_code':None,'stdout':'','stderr':type(error).__name__,'output_truncated':False,'duration':round(time.monotonic()-start,4)}
