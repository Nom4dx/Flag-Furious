"""Recovery-password tests ensure structural validation and masking."""
from conftest import load_module

def test_known_valid_recovery_password():
    recovery=load_module('src.recovery_key');value='563200-557084-108284-218900-019151-415437-694144-239976';result=recovery.validate(value)
    assert result['valid'] and value not in result['masked']

def test_wrong_recovery_password_is_rejected():
    result=load_module('src.recovery_key').validate('111112-111112-111112-111112-111112-111112-111112-111112')
    assert not result['valid']

def test_persistable_record_never_contains_secret():
    _,method,record=load_module('src.password_handler').select({'unlock':True,'password':'super secret'})
    assert method=='password' and 'super secret' not in repr(record) and record['password_display']=='********'
