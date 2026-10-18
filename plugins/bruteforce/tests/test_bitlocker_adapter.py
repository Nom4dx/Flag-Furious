"""BitLocker integration remains local and content-first."""
import struct
from plugins.bruteforce.src.adapters.bitlocker_adapter import BitLockerAdapter

def test_adapter_detects_fve_at_partition_offset(tmp_path):
    path=tmp_path/'renamed.dat';data=bytearray(2*1024*1024);offset=1024*1024
    data[offset:offset+3]=b'\xeb\x58\x90';data[offset+3:offset+11]=b'-FVE-FS-';struct.pack_into('<H',data,offset+11,512);data[offset+13]=8;path.write_bytes(data)
    assert BitLockerAdapter().can_handle({'path':str(path)},{'protection_type':'unknown'})
