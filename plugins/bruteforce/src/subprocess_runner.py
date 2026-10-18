"""Allow-listed offline subprocess runner with redacted commands."""
import os,shutil,subprocess,time
ALLOW={'7z','7zz','unrar','qpdf','steghide','stegseek','openstego','stegcloak','stegsnow','gpg','openssl'}
def run(tool,args,timeout,cwd=None,secret_indexes=()):
    """Run argv without shell/network; redact designated secret arguments in audit output."""
    binary=shutil.which(tool) if tool in ALLOW else None
    display=[tool,*map(str,args)]
    for i in secret_indexes:
        if 0<=i+1<len(display):display[i+1]='********'
    if not binary:return {'tool':tool,'available':False,'status':'tool_missing','command':display,'exit_code':None,'stdout':'','stderr':'tool not installed','duration':0}
    start=time.monotonic()
    try:
        p=subprocess.run([binary,*map(str,args)],cwd=cwd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,shell=False,check=False,env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'LANG':'C.UTF-8','HOME':'/nonexistent'})
        return {'tool':tool,'available':True,'status':'completed' if p.returncode==0 else 'failed','command':display,'exit_code':p.returncode,'stdout':p.stdout[:65536].decode(errors='replace'),'stderr':p.stderr[:65536].decode(errors='replace'),'duration':round(time.monotonic()-start,4)}
    except subprocess.TimeoutExpired:return {'tool':tool,'available':True,'status':'timeout','command':display,'exit_code':None,'stdout':'','stderr':'timeout','duration':round(time.monotonic()-start,4)}
