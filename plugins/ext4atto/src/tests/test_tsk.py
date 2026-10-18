from pathlib import Path
from diskhunt.tsk import TSK


def test_fls_long_format_parser(monkeypatch, tmp_path):
    tsk=TSK(tmp_path/"x.img",lambda *args: None)
    output="r/r 13:\tflag.txt\t2026-01-01\t2026-01-01\t2026-01-01\t2026-01-01\t41\t0\t0\nr/r * 14:\tdeleted.txt (deleted)\t0\t0\t0\t0\t9\t0\t0\nV/V 15:\t$OrphanFiles\t0\t0\t0\t0\t0\t0\t0\n"
    monkeypatch.setattr(tsk,"run",lambda *args:(0,output))
    files=tsk.list_files(0); assert files[0]["name"]=="flag.txt"; assert files[0]["size"]==41
    assert files[1]["deleted"] is True and files[1]["name"]=="deleted.txt"
    assert files[2]["status"] == "ORPHAN"
