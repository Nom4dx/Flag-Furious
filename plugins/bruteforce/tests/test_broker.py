"""Broker known-password, wordlist, secret-vault and lifecycle tests."""
from pathlib import Path
import pytest
from plugins.bruteforce.src.broker import Broker
from plugins.bruteforce.src.limits import Limits
FIX=Path(__file__).parents[1]/'fixtures'
def ctx(tmp):return {'output_dir':str(tmp),'limits':Limits(100,10,1,1024*1024,100)}
def request(**extra):
 return {'artifact_id':'a1','artifact_path':str(FIX/'zipcrypto-secret.zip'),'source_plugin':'seganografy','detected_format':'zip','protection_type':'password','mode':'known',**extra}
def test_waiting_for_user(tmp_path):
 if not (FIX/'zipcrypto-secret.zip').exists():pytest.skip('fixture absent')
 r=Broker().request_unlock(request(mode='ask_user'),ctx(tmp_path));assert r['status']=='waiting_for_user'
def test_known_secret_is_vaulted_and_masked(tmp_path):
 if not (FIX/'zipcrypto-secret.zip').exists():pytest.skip('fixture absent')
 b=Broker();r=b.request_unlock(request(known_password='secret'),ctx(tmp_path));assert r['status']=='success' and r['password_display']=='********' and 'known_password' not in r;assert b.vault.get(r['secret_ref'])=='secret'
def test_wordlist_finds_after_wrong_candidate(tmp_path):
 if not (FIX/'zipcrypto-secret.zip').exists():pytest.skip('fixture absent')
 r=Broker().request_unlock(request(mode='wordlist',wordlists=[str(FIX/'wordlists/common.txt')]),ctx(tmp_path));assert r['status']=='success' and r['attempts']==2
def test_limit_reached(tmp_path):
 if not (FIX/'zipcrypto-secret.zip').exists():pytest.skip('fixture absent')
 r=Broker().request_unlock(request(mode='wordlist',wordlists=[str(FIX/'wordlists/common.txt')],max_attempts=1),{'output_dir':str(tmp_path),'limits':Limits(1,10,1,1024,10)});assert r['status']=='limit_reached'
