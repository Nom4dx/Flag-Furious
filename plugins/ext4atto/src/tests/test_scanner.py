from io import BytesIO
from diskhunt.budget import ByteBudget, BudgetExhausted
from diskhunt.scanner import compile_flag_patterns, scan_bytes, scan_ranges


def test_flag_search_and_ranking():
    result=scan_bytes(b"xx picoCTF{real_flag} yy",100,compile_flag_patterns("picoCTF{",False))[0]
    assert result["candidate"]=="picoCTF{real_flag}"; assert result["absolute_offset"]==103; assert result["confidence"]>=85


def test_default_prefixes_and_utf16():
    data="noise FLAG{wide_value}".encode("utf-16le"); found=scan_bytes(data,0,compile_flag_patterns(None,False)); assert any(x["candidate"]=="FLAG{wide_value}" for x in found)


def test_regex_prefix():
    found=scan_bytes(b"CTF2026{regex_ok}",0,compile_flag_patterns(r"CTF\d{4}\{",True)); assert found[0]["candidate"]=="CTF2026{regex_ok}"


def test_flag_split_between_chunks(tmp_path):
    path=tmp_path/"split.img"; path.write_bytes(b"A"*1018+b"picoCTF{across_blocks}"+b"B"*2000)
    budget=ByteBudget(4096,{"search":4096},0); results=scan_ranges(path,[(0,path.stat().st_size,None,"raw")],compile_flag_patterns("picoCTF{",False),budget,1024)
    assert any(x["candidate"]=="picoCTF{across_blocks}" for x in results)


def test_budget_exhaustion_and_accounting():
    b=ByteBudget(4,{"search":4},8); h=BytesIO(b"abcdefgh")
    assert b.read(h,0,4,"search",8)==b"abcd"; assert b.read(h,0,4,"search",8)==b"abcd"
    with __import__('pytest').raises(BudgetExhausted): b.read(h,4,4,"search",8)
    assert b.stats()["cache_hits"]==1 and b.stats()["remaining"]==0

