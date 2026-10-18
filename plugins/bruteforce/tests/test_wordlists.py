"""Portable root discovery, metadata and streaming candidate tests."""
from pathlib import Path
from plugins.bruteforce.src.wordlist_discovery import roots
from plugins.bruteforce.src.wordlist_manager import inventory,stream
from plugins.bruteforce.src.candidate_generator import variants
FIX=Path(__file__).parents[1]/'fixtures'
def test_relative_discovery_independent_of_cwd(tmp_path,monkeypatch):
 (tmp_path/'wordlists').mkdir(); monkeypatch.chdir('/')
 found=roots(tmp_path);assert found[0]['path']==str((tmp_path/'wordlists').resolve()) and found[0]['exists']
def test_inventory_hash_lines_duplicates():
 items=inventory([{'path':str(FIX/'wordlists'),'source':'test','exists':True}])
 assert len(items)==2 and all(len(x['sha256'])==64 and x['estimated_lines'] for x in items)
def test_stream_preserves_unicode_spaces_and_dedup_variants():
 values=list(stream([FIX/'wordlists/common.txt']))
 assert any(x[0]=='password with spaces' for x in values) and any(x[0]=='pässwörd' for x in values)
 assert list(variants('Test',False))==['Test'] and len(list(variants('Test',True)))==len(set(variants('Test',True)))
