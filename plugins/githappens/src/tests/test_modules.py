import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

from picup_web.modules import cache, history, legacy, slack, virtual
from picup_web.scanner import ScanConfig


def test_slack_export_thread(tmp_path):
    root = tmp_path / "export"; channel = root / "general"; channel.mkdir(parents=True)
    (root / "users.json").write_text(json.dumps([{"id":"U1","name":"alice","profile":{"email":"a@example.test"}}]))
    (channel / "2026-01-01.json").write_text(json.dumps([{"type":"message","user":"U1","ts":"1767225600.123","thread_ts":"1767225600.000","text":"flag{slack_thread}"}]))
    result = slack.analyze(root, ScanConfig())
    assert result["messages"][0]["timestamp_utc"].startswith("2026-")
    assert any(x.value == "flag{slack_thread}" for x in result["findings"])


def test_mmls_offsets_include_slot_column():
    sample = "002:  000:000   0000002048   0000616447   0000614400   Linux (0x83)"
    assert legacy._partition_offsets(sample) == [0, 2048]


def test_virtual_legacy_container_detection(tmp_path):
    vdi = tmp_path / "disk.vdi"; vdi.write_bytes(b"<<< Oracle VM VirtualBox Disk Image >>>" + b"\0" * 512)
    assert virtual.identify(vdi)["format"] == "vdi"
    vhd = tmp_path / "disk.bin"; vhd.write_bytes(b"\0" * 512 + b"conectix" + b"\0" * 504)
    assert virtual.identify(vhd)["format"] == "vhd"


def test_fragmented_cache_json(tmp_path):
    root = tmp_path / "Slack" / "Cache"; root.mkdir(parents=True)
    (root / "data_0.ldb").write_bytes(b'fragment...{"value":"CTF{cache_fragment}"}...')
    result = cache.analyze(tmp_path, tmp_path / "copies", ScanConfig())
    assert result["entries"]
    assert any(x.value == "CTF{cache_fragment}" for x in result["findings"])


def test_cache_sensitive_columns_are_redacted(tmp_path):
    db = tmp_path / "Cookies"; conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE cookies(host TEXT, encrypted_value BLOB, session_token TEXT)")
    conn.execute("INSERT INTO cookies VALUES('example.test',X'010203','do-not-display')"); conn.commit(); conn.close()
    report, _ = cache.sqlite_inventory(db, tmp_path / "copy", ScanConfig())
    row = report["rows"][0]
    assert row["credentials_redacted"] is True
    assert "do-not-display" not in json.dumps(row) and "sha256=" in row["data"]["session_token"]


def test_browser_history_and_wal(tmp_path):
    profile = tmp_path / "Chrome" / "Default"; profile.mkdir(parents=True)
    db = profile / "History"
    conn = sqlite3.connect(db); conn.execute("PRAGMA journal_mode=WAL"); conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.executescript("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT); CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER,from_visit INTEGER);")
    conn.execute("INSERT INTO urls VALUES(1,'https://example.test/flag{browser_history}','fixture')")
    conn.execute("INSERT INTO visits VALUES(1,1,13400000000000000,0)"); conn.commit()
    result = history.analyze(tmp_path, tmp_path / "history-copy", ScanConfig())
    assert result["events"][0]["url"].endswith("flag{browser_history}")
    assert any(x.value == "flag{browser_history}" for x in result["findings"])
    cached, findings = cache.sqlite_inventory(db, tmp_path / "db-copy", ScanConfig())
    assert cached["wal"] is True
    assert any(x.value == "flag{browser_history}" for x in findings)
    conn.close()


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="qemu-img unavailable")
def test_qcow_backing_layer_flag(tmp_path):
    base = tmp_path / "base.raw"; base.write_bytes(b"flag{backing_layer}" + b"\0" * 1048560)
    overlay = tmp_path / "overlay.qcow2"
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "raw", "-b", base.name, overlay.name], cwd=tmp_path, check=True)
    info = virtual.identify(overlay)
    assert info["format"] == "qcow2" and info["backing_file"] == base.name
    result = virtual.analyze(overlay, ScanConfig())
    assert any(x.value == "flag{backing_layer}" for x in result["findings"])
    assert result["chain"]


@pytest.mark.skipif(shutil.which("mkfs.ext4") is None or shutil.which("debugfs") is None, reason="ext tools unavailable")
def test_ext_deleted_flag_fixture(tmp_path):
    image = tmp_path / "deleted.img"
    with image.open("wb") as handle: handle.truncate(16 * 1024 * 1024)
    subprocess.run(["mkfs.ext4", "-q", "-F", str(image)], check=True)
    secret = tmp_path / "secret.txt"; secret.write_text("picoCTF{deleted_ext_fixture}")
    subprocess.run(["debugfs", "-w", "-R", f"write {secret} /secret.txt", str(image)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["debugfs", "-w", "-R", "rm /secret.txt", str(image)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = legacy.analyze(image, ScanConfig(), tmp_path / "recover")
    assert any(x["filesystem"].startswith("ext") for x in result["signatures"])
    assert any(x.value == "picoCTF{deleted_ext_fixture}" for x in result["findings"])
