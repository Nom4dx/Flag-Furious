import gzip
from pathlib import Path
import pytest
from diskhunt.security import resolve_artifact, safe_filename
from diskhunt.source import prepare_image, validate_nbd_url


def test_path_traversal_and_malicious_name(tmp_path):
    root=tmp_path/"artifacts"; root.mkdir(); (root/"ok.bin").write_bytes(b"x")
    assert safe_filename("../../evil;name") == "evil_name"
    with pytest.raises(ValueError): resolve_artifact(root,"../../etc/passwd")


def test_compressed_image(tmp_path):
    src=tmp_path/"x.img.gz"
    with gzip.open(src,"wb") as out: out.write(b"disk image")
    result,kind=prepare_image(src,tmp_path); assert result.read_bytes()==b"disk image"; assert "compressed" in kind


def test_segmented_image(tmp_path):
    (tmp_path/"x.001").write_bytes(b"aa"); (tmp_path/"x.002").write_bytes(b"bb")
    result,kind=prepare_image(tmp_path/"x.001",tmp_path); assert result.read_bytes()==b"aabb"; assert "2 parts" in kind


@pytest.mark.parametrize("url",["nbd://127.0.0.1:10809/x","nbd://10.0.0.1/x","http://example.com/x"])
def test_nbd_ssrf_protection(url):
    with pytest.raises(ValueError): validate_nbd_url(url,set(),True)


def test_nbd_disabled_and_interrupted_policy():
    with pytest.raises(ValueError,match="disabled"): validate_nbd_url("nbd://example.com/x",{"example.com"},False)

