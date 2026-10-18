"""BitLocker adapter backed by pybde/libbde; source volumes stay immutable."""
from __future__ import annotations
import hashlib,os,shutil,subprocess,time
from pathlib import Path
from .base import PasswordAdapter

class _Slice:
    """Seekable read-only partition view accepted by libyal bindings."""
    def __init__(self,path,offset,size):self.stream=Path(path).open('rb',buffering=0);self.offset=offset;self.size=size;self.position=0
    def read(self,size=-1):
        if size<0:size=self.size-self.position
        size=max(0,min(size,self.size-self.position));self.stream.seek(self.offset+self.position);data=self.stream.read(size);self.position+=len(data);return data
    def seek(self,value,whence=os.SEEK_SET):
        base=0 if whence==os.SEEK_SET else self.position if whence==os.SEEK_CUR else self.size;self.position=max(0,min(self.size,base+value));return self.position
    def tell(self):return self.position
    def get_size(self):return self.size
    def close(self):self.stream.close()

def _volume(path):
    """Find a FVE VBR within a bounded 64 MiB prefix."""
    path=Path(path);size=path.stat().st_size;limit=min(size,64*1024*1024);tail=b'';offset=0
    with path.open('rb') as source:
        while offset<limit:
            block=source.read(min(4*1024*1024,limit-offset));data=tail+block;base=offset-len(tail);hit=data.find(b'-FVE-FS-')
            if hit>=3:
                start=base+hit-3;sector=data[hit-3:hit+61]
                bps=int.from_bytes(sector[11:13],'little') if len(sector)>=14 else 0;clusters=sector[13] if len(sector)>=14 else 0
                if bps in {512,1024,2048,4096} and clusters and clusters & (clusters-1)==0:return start,size-start
            tail=data[-16:];offset+=len(block)
    return None

class BitLockerAdapter(PasswordAdapter):
    """Verify and export local BitLocker volumes without mounting them."""
    name='bitlocker_adapter';supported_formats=['bitlocker','fve','raw_disk'];supported_protections=['bitlocker','bitlocker_password','bitlocker_recovery_password']
    def __init__(self):self._pending={}
    def can_handle(self,artifact,context):
        if context.get('protection_type') in self.supported_protections:return True
        # A bounded 64 MiB VBR scan is useful for disk evidence but wasteful on
        # every ordinary file during adapter routing.
        name=Path(artifact.get('name',self.path(artifact).name)).suffix.lower()
        if artifact.get('type')!='disk_image' and name not in {'.raw','.img','.dd','.001','.vhd','.vhdx','.bde','.fve'}:return False
        return _volume(self.path(artifact)) is not None
    def _open(self,artifact,password):
        import pybde
        path=self.path(artifact);region=_volume(path)
        if not region:raise ValueError('bitlocker signature not found')
        view=_Slice(path,*region);handle=pybde.volume();handle.open_file_object(view)
        compact=''.join(c for c in password if c.isdigit())
        if len(compact)==48:handle.set_recovery_password(password)
        else:handle.set_password(password)
        return view,handle,bool(handle.unlock() and not handle.locked)
    def verify_password(self,artifact,password,context):
        """Ask libbde to validate the VMK; parsing alone is not success."""
        try:view,handle,valid=self._open(artifact,password);handle.close();view.close();return {'valid':valid,'reason':'verified_by_libbde' if valid else 'wrong_password'}
        except ImportError:
            result=self._dislocker(artifact,password,context)
            if result:
                self._pending[(str(self.path(artifact)),hashlib.sha256(password.encode()).hexdigest())]=result
                return {'valid':True,'reason':'verified_by_dislocker_and_ntfs_output'}
            return {'valid':False,'reason':'wrong_password'}
        except Exception as exc:return {'valid':False,'reason':'wrong_password' if any(x in str(exc).casefold() for x in ('unlock','key','password')) else 'corrupted_artifact'}
    def extract(self,artifact,password,context):
        """Write a bounded decrypted filesystem image as a separate artifact."""
        try:view,handle,valid=self._open(artifact,password)
        except ImportError:
            key=(str(self.path(artifact)),hashlib.sha256(password.encode()).hexdigest())
            target=self._pending.pop(key,None) or self._dislocker(artifact,password,context)
            if not target:return []
            digest=hashlib.sha256()
            with target.open('rb') as source:
                while block:=source.read(8*1024*1024):digest.update(block)
            return [{'artifact_id':'artifact-'+digest.hexdigest()[:16],'path':str(target),'name':target.name,'sha256':digest.hexdigest(),'size':target.stat().st_size,'detected_type':'decrypted NTFS filesystem image','writable':False}]
        except Exception:return []
        try:
            if not valid:return []
            limit=context['limits'].max_output;size=int(handle.size)
            if size>limit:return []
            root=Path(context['output_dir'])/'bruteforce'/'unlocked';root.mkdir(parents=True,exist_ok=True);target=root/'bitlocker-volume.raw';digest=hashlib.sha256()
            with target.open('xb') as destination:
                remaining=size
                while remaining:
                    data=handle.read(min(8*1024*1024,remaining))
                    if not data:break
                    destination.write(data);digest.update(data);remaining-=len(data)
            if remaining:target.unlink(missing_ok=True);return []
            target.chmod(0o400);return [{'artifact_id':'artifact-'+digest.hexdigest()[:16],'path':str(target),'name':target.name,'sha256':digest.hexdigest(),'size':size,'detected_type':'decrypted filesystem image','writable':False}]
        finally:handle.close();view.close()

    def _dislocker(self,artifact,password,context):
        """Perform one full read-only validation without leaking the secret in argv."""
        binary=shutil.which('dislocker-file');region=_volume(self.path(artifact))
        if not binary or not region:return None
        _,size=region
        if size>context['limits'].max_output:return None
        root=Path(context['output_dir'])/'bruteforce'/'unlocked';root.mkdir(parents=True,exist_ok=True)
        target=root/f'bitlocker-{time.time_ns()}.raw'
        compact=''.join(c for c in password if c.isdigit())
        switch='-p' if len(compact)==48 else '-u'
        try:
            done=subprocess.run([binary,'-r','-q','-V',str(self.path(artifact)),'-O',str(region[0]),switch,'--',str(target)],input=(password+'\n').encode(),stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,shell=False,timeout=context['limits'].timeout_seconds,check=False)
        except (OSError,subprocess.TimeoutExpired):return None
        if done.returncode or not target.is_file() or target.stat().st_size<512:
            target.unlink(missing_ok=True);return None
        with target.open('rb') as source:boot=source.read(512)
        if boot[3:11]!=b'NTFS    ' and boot[510:512]!=b'\x55\xaa':
            target.unlink(missing_ok=True);return None
        target.chmod(0o400);return target

    def recover_wordlists(self,artifact,candidates,context):
        """Crack a derived user-password hash in one bounded Hashcat batch.

        Candidates are materialized below the isolated output directory up to
        ``max_attempts``. The recovered password is returned only to the caller
        frame and is removed from generated files immediately after reading.
        """
        bitlocker2john=shutil.which('bitlocker2john');hashcat=shutil.which('hashcat')
        if not bitlocker2john or not hashcat:return {'status':'not_supported','attempts':0,'successes':[],'failures':[],'duration':0}
        root=Path(context['output_dir'])/'bruteforce'/'bitlocker-recovery';root.mkdir(parents=True,exist_ok=True)
        hash_file=root/'bitlocker.hash';candidate_file=root/'candidates.txt';found_file=root/'found.txt';started=time.monotonic()
        probe=subprocess.run([bitlocker2john,'-i',str(self.path(artifact))],stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,timeout=min(120,context['limits'].timeout_seconds),check=False)
        lines=[line[line.find(b'$bitlocker$'):].strip() for line in (probe.stdout+b'\n'+probe.stderr).splitlines() if b'$bitlocker$0$' in line]
        if not lines:return {'status':'corrupted_artifact','attempts':0,'successes':[],'failures':[],'duration':time.monotonic()-started}
        hash_file.write_bytes(lines[0]+b'\n');seen=set();attempts=0
        with candidate_file.open('w',encoding='utf-8',newline='\n') as output:
            for value,_origin,_line in candidates:
                if value in seen:continue
                seen.add(value);output.write(value+'\n');attempts+=1
                if attempts>=context['limits'].max_attempts:break
        if not attempts:return {'status':'not_found','attempts':0,'successes':[],'failures':[],'duration':time.monotonic()-started}
        timeout=max(1,context['limits'].timeout_seconds-int(time.monotonic()-started))
        try:done=subprocess.run([hashcat,'-m','22100','--potfile-disable','--outfile',str(found_file),'--outfile-format','2','--quiet',str(hash_file),str(candidate_file)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,shell=False,timeout=timeout,check=False)
        except subprocess.TimeoutExpired:return {'status':'timeout','attempts':attempts,'successes':[],'failures':[],'duration':time.monotonic()-started}
        password=found_file.read_text(encoding='utf-8',errors='replace').splitlines()[0] if found_file.is_file() and found_file.stat().st_size else None
        found_file.unlink(missing_ok=True);candidate_file.unlink(missing_ok=True);hash_file.unlink(missing_ok=True)
        return {'status':'success' if password else 'not_found','attempts':attempts,'successes':[{'password':password,'origin':'selected_wordlists','line':None,'verification':{'valid':True,'reason':'hashcat_bitlocker_22100'}}] if password else [],'failures':[],'duration':time.monotonic()-started}
