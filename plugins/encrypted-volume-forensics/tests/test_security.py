"""Output-path and secret-redaction safety tests."""
from pathlib import Path
import pytest
from conftest import load_module

def test_safe_names_are_flat():
    security=load_module('src.security');assert security.safe_name('../../flag.txt')=='flag.txt'

def test_containment_rejects_escape(tmp_path):
    with pytest.raises(ValueError):load_module('src.security').contained(tmp_path,tmp_path/'..'/'escape')

def test_command_masks_passwords():
    security=load_module('src.security');masked=security.mask_command(['tool','-uSecret','--password=other'])
    assert 'Secret' not in repr(masked) and 'other' not in repr(masked)
