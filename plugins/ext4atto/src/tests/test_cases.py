from diskhunt.db import Database


def test_case_record_and_complete_deletion(tmp_path):
    db=Database(tmp_path/"db.sqlite"); image=tmp_path/"case.img"; image.write_bytes(b"evidence")
    db.create_job("case","case.img",str(image),{},"Investigation")
    db.add_result("case","artifact",{"artifact":"x"}); db.log("case","INFO","created")
    assert db.list_jobs()[0]["case_name"]=="Investigation"
    db.delete_job("case")
    assert db.get_job("case") is None and db.results("case","artifact")==[] and db.logs("case")==[]
