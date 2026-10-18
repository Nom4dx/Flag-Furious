"""Regression tests for the Bitlocker-2 memory-to-FVEK workflow."""

from pathlib import Path

from conftest import load_module


def test_windows10_pool_becomes_dislocker_candidate(tmp_path):
    """A corroborated `None` pool yields one deduplicated 66-byte key."""
    scanner = load_module("src.memory_fvek")
    data = bytearray(8192)
    pool = 1024
    data[pool + 2] = 80  # 80 * 16 = 1280, inside the documented range.
    data[pool + 4 : pool + 8] = b"None"
    material = bytes(range(1, 65))
    data[pool + 0x9C : pool + 0x9C + 64] = material
    data[pool + 0xE0 : pool + 0xE0 + 64] = material
    source = tmp_path / "memory.mem"
    source.write_bytes(data)
    rows, warnings = scanner.scan(source, len(data))
    assert not warnings and len(rows) == 1
    assert rows[0]["payload"][:2] == b"\x04\x80"
    assert len(rows[0]["payload"]) == 66
    assert rows[0]["status"] == "candidate_requires_volume_validation"


def test_truncated_memory_scan_is_explicit(tmp_path):
    """A byte budget never silently claims full-memory coverage."""
    scanner = load_module("src.memory_fvek")
    source = tmp_path / "large.vmem"
    source.write_bytes(b"\0" * 4096)
    rows, warnings = scanner.scan(source, 512)
    assert rows == [] and any("limitata" in value for value in warnings)
