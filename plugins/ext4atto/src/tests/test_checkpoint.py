from pathlib import Path
from threading import Event
from diskhunt.analyzer import Analyzer
from diskhunt.db import Database


def options(total, search, carving):
    return {"prefix":"CTF{","prefix_is_regex":False,"mode":"balanced","budgets":{"total":total,"metadata":512,"search":search,"journal":0,"carving":carving,"max_request":512,"cache_size":0},"custom_signatures":[]}


def test_checkpoint_and_resume_with_larger_budget(tmp_path):
    image=tmp_path/"case.img"; image.write_bytes(b"x"*600+b"CTF{checkpoint}"+b"y"*2400)
    db=Database(tmp_path/"db.sqlite"); db.create_job("job","case.img",str(image),options(1024,512,0))
    Analyzer(db,"job",Event()).run(); first=db.get_job("job")
    assert first["status"]=="PARTIAL"; assert first["stats"]["completed_phases"]
    with db.connect() as con:
        import json
        con.execute("UPDATE jobs SET options=?, cancel_requested=0 WHERE id='job'",(json.dumps(options(8192,4096,3072)),))
    db.clear_results("job"); Analyzer(db,"job",Event()).run(); second=db.get_job("job")
    assert second["status"]=="COMPLETED"; assert db.results("job","flag")[0]["candidate"]=="CTF{checkpoint}"
