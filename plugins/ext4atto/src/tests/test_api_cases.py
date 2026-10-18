import pytest
pytest.importorskip("multipart")
from fastapi.testclient import TestClient
import diskhunt.main as main
from diskhunt.db import Database


def test_delete_case_removes_directory_and_database(tmp_path, monkeypatch):
    data=tmp_path/"data"; work=data/"jobs"/"abc"; work.mkdir(parents=True); image=work/"case.img"; image.write_bytes(b"image")
    database=Database(data/"db.sqlite"); database.create_job("abc","case.img",str(image),{},"Delete me"); database.update_job("abc",status="COMPLETED")
    monkeypatch.setattr(main,"db",database); monkeypatch.setattr(main.settings,"data_dir",data)
    response=TestClient(main.app).delete("/api/jobs/abc")
    assert response.status_code==200; assert response.json()["message"]=="Caso eliminato correttamente."
    assert not work.exists() and database.get_job("abc") is None
