"""Embedded signatures inside declared PNG chunks are validated independently."""

from fixture_support import load_module, png_bytes, zip_bytes
import io
import stat
import zipfile


def test_zip_inside_png_custom_chunk(fixture_factory):
    archive = zip_bytes({"inner.txt": b"inside"}); path = fixture_factory("chunk.png", png_bytes((b"pOLY", archive)))
    sig = load_module("src.signatures"); bd = load_module("src.boundary_detector")
    candidates, _ = sig.scan_signatures(path, len(path.read_bytes())); valid, _ = bd.detect_boundaries(path, candidates, path.stat().st_size)
    assert {x["format"] for x in valid} == {"png", "zip"}
    assert load_module("src.polyglot_detector").classify_polyglot(path.stat().st_size, valid)["primary_classification"] == "embedded_polyglot"


def test_zip_slip_symlink_and_bomb_are_not_extracted(fixture_factory, tmp_path):
    """Unsafe entries remain visible in the inventory but create no files."""
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../escape.txt", b"escape")
        link = zipfile.ZipInfo("link")
        link.create_system = 3; link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "target")
        archive.writestr("bomb.txt", b"A" * 100000)
    path = fixture_factory("unsafe.zip", raw.getvalue())
    sig = load_module("src.signatures"); bd = load_module("src.boundary_detector")
    candidates, _ = sig.scan_signatures(path, path.stat().st_size); valid, _ = bd.detect_boundaries(path, candidates, path.stat().st_size)
    store = load_module("src.artifact_store").ArtifactStore(tmp_path / "out", 200000)
    result = load_module("src.archive_analyzer").analyze_zip(path, next(x for x in valid if x["format"] == "zip"), store, {"max_entries": 10, "max_ratio": 10, "max_member_bytes": 200000, "max_total_bytes": 200000})
    assert not result["artifacts"]
    assert {x["rejection_reason"] for x in result["entries"]} >= {"path traversal", "symlink", "rapporto di espansione oltre il limite"}


def test_zip_slip_symlink_and_bomb_are_refused(fixture_factory, tmp_path):
    """Unsafe ZIP members remain inventoried but never become artifacts."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../escape.txt", b"no")
        link = zipfile.ZipInfo("link"); link.create_system = 3; link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "target")
        archive.writestr("bomb.txt", b"A" * 100000)
    path = fixture_factory("unsafe.zip", output.getvalue())
    sig = load_module("src.signatures"); bd = load_module("src.boundary_detector")
    candidates, _ = sig.scan_signatures(path, path.stat().st_size); valid, _ = bd.detect_boundaries(path, candidates, path.stat().st_size)
    store = load_module("src.artifact_store").ArtifactStore(tmp_path / "out", 200000)
    result = load_module("src.archive_analyzer").analyze_zip(path, next(x for x in valid if x["format"] == "zip"), store, {"max_entries": 10, "max_ratio": 10, "max_member_bytes": 200000, "max_total_bytes": 200000})
    assert not result["artifacts"]
    assert any("path traversal" in x for x in result["warnings"])
    assert any("symlink" in x for x in result["warnings"])
    assert any("rapporto" in x for x in result["warnings"])
