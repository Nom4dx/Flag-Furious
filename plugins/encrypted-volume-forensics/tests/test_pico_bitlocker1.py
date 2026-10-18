"""Optional real-fixture regression for the picoCTF Bitlocker-1 chain."""

import shutil
from pathlib import Path

import pytest

from conftest import load_module


class Reporter:
    """Minimal Hub reporter used by the direct contract test."""
    def phase(self, _value): pass
    def log(self, _value): pass
    def partial(self, _value): pass


@pytest.mark.skipif(
    not Path("/home/nomad/Scrivania/test/bitlocker-1.dd").is_file()
    or shutil.which("dislocker-file") is None,
    reason="local authorized Bitlocker-1 fixture or Dislocker unavailable",
)
def test_pico_bitlocker1_unlocks_and_finds_flag(tmp_path):
    """Known challenge password decrypts a copy and exposes flag.txt read-only."""
    source = Path("/home/nomad/Scrivania/test/bitlocker-1.dd")
    before = source.stat().st_mtime_ns
    plugin = load_module("plugin").Plugin()
    result = plugin.analyze(
        {"id":"pico-bitlocker-1","name":source.name,"type":"disk_image","path":str(source)},
        {
            "output_dir":str(tmp_path / "out"),
            "byte_budget":source.stat().st_size,
            "output_bytes":256 * 1024 * 1024,
            "prefixes":["picoCTF"],
            "plugin_options":{"encrypted-volume-forensics":{
                "extract_hash":False,
                "unlock":True,
                "unlock_engine":"dislocker",
                "password":"jacqueline",
                "max_unlocked_bytes":128 * 1024 * 1024,
                "filesystem":{"extensions":[".txt"],"max_extract_files":8},
            }},
        },
        Reporter(),
    )
    assert result["metrics"]["unlocked_volumes"] == 1
    assert any(flag["value"].startswith("picoCTF{") for flag in result["flags"])
    assert not any("volume is locked" in warning for warning in result["warnings"])
    assert source.stat().st_mtime_ns == before
