"""Carving copies exact validated ranges and deduplicates identical bytes."""

from fixture_support import load_module


def test_artifact_store_deduplicates_and_sanitizes(tmp_path):
    store = load_module("src.artifact_store").ArtifactStore(tmp_path, 1000)
    one = store.save_bytes("embedded", "../../flag.txt", b"same")
    two = store.save_bytes("embedded", "other.txt", b"same")
    assert one["sha256"] == two["sha256"] and two["deduplicated"]
    assert ".." not in one["name"] and (tmp_path / "embedded" / one["name"]).is_file()

