from diskhunt.budget import ByteBudget
from diskhunt.scanner import carve


def test_file_carving(tmp_path):
    image=tmp_path/"x.img"; image.write_bytes(b"x"*20+b"%PDF-1.4 body %%EOF"+b"y"*20)
    budget=ByteBudget(1024,{"carving":1024},0); result=carve(image,tmp_path/"out",[(0,image.stat().st_size,None,"raw")],budget,1024)
    assert result[0]["type"]=="pdf"; assert result[0]["status"]=="CARVED"; assert (tmp_path/"out"/result[0]["name"]).exists()


def test_custom_carving_signature(tmp_path):
    image=tmp_path/"x.img"; image.write_bytes(b"AADEADBEEFpayloadBEEFZZ")
    budget=ByteBudget(100,{"carving":100},0); r=carve(image,tmp_path/"out",[(0,22,None,"raw")],budget,100,[{"name":"custom","header":"4445414442454546","footer":"42454546"}]); assert r[0]["type"]=="custom"
