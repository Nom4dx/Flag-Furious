import io

import pytest

from picup_web.cases import CaseStore
from picup_web.util import inside, safe_name


def test_case_is_read_only_and_delete_is_scoped(tmp_path):
    external = tmp_path / "do-not-delete"; external.write_text("original")
    store = CaseStore(tmp_path / "cases")
    case = store.create("fixture", "../../malicious.img", io.BytesIO(b"evidence"))
    case_dir = store.path(case["id"]); evidence = case_dir / case["original"]
    assert evidence.name == "malicious.img" and evidence.stat().st_mode & 0o222 == 0
    store.delete(case["id"])
    assert external.read_text() == "original" and not case_dir.exists()


def test_path_traversal_rejected(tmp_path):
    with pytest.raises(ValueError):
        inside(tmp_path / "case", tmp_path / "outside")
