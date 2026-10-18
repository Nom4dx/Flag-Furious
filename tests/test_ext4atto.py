"""Real filesystem parity: late partition, deleted inode and nested archive."""

import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import zipfile

import pytest
from app.core.plugin_loader import discover
from app.config import Settings
from test_hub import upload, start

ROOT = Path(__file__).resolve().parents[1]


def test_ext4atto_rejects_generic_compressed_files(client, case):
    generic = upload(client, case, gzip.compress(b"ordinary recovered log"), "recovered.log.gz")
    compressed_disk = upload(client, case, gzip.compress(b"disk payload"), "evidence.dd.gz")

    generic_plugins = {item["plugin_id"] for item in client.get("/api/assets/" + generic["id"]).json()["compatible_plugins"]}
    disk_plugins = {item["plugin_id"] for item in client.get("/api/assets/" + compressed_disk["id"]).json()["compatible_plugins"]}

    assert "ext4atto" not in generic_plugins
    assert "ext4atto" in disk_plugins


def test_budget_triage_does_not_starve_ext4atto(client, case):
    asset = upload(client, case, b"\0" * 8192 + b"flag{plugin_budget}", "budget.dd")
    job = start(client, case, asset, ["ext4atto"], byte_budget=4096, recursive=False)
    results = client.get("/api/jobs/" + job["id"] + "/results").json()
    result = next(r for r in results if r["plugin_id"] == "ext4atto")
    assert result["status"] in ("completed", "partial"), result
    assert result["metrics"]["size"] == asset["size"]


def make_disk(tmp_path):
    for tool in ("mkfs.ext4", "debugfs", "fls", "icat"):
        if not shutil.which(tool):
            pytest.skip(f"{tool} required for real filesystem regression")
    fs = tmp_path / "filesystem.img"
    with fs.open("wb") as f:
        f.truncate(8 * 1024**2)
    subprocess.run(["mkfs.ext4", "-q", "-F", str(fs)], check=True)
    files = {"visible.txt": b"SRDNLEN{late_partition}", "deleted.txt": b"flag{deleted_inode}"}
    for name, content in files.items():
        (tmp_path / name).write_bytes(content)
    with zipfile.ZipFile(tmp_path / "nested.zip", "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("secret.txt", "picoCTF{nested_recovery}")
    for name in (*files, "nested.zip"):
        subprocess.run(
            ["debugfs", "-w", "-R", f"write {tmp_path / name} /{name}", str(fs)],
            check=True,
            capture_output=True,
        )
    subprocess.run(["debugfs", "-w", "-R", "rm /deleted.txt", str(fs)], check=True, capture_output=True)
    image = tmp_path / "challenge.dd"
    offset = 80 * 1024**2
    mbr = bytearray(512)
    mbr[446 + 4] = 0x83
    struct.pack_into("<II", mbr, 446 + 8, offset // 512, fs.stat().st_size // 512)
    mbr[510:512] = b"\x55\xaa"
    with image.open("wb") as f:
        f.truncate(96 * 1024**2)
        f.write(mbr)
        f.seek(offset)
        with fs.open("rb") as source:
            shutil.copyfileobj(source, f)
    return image


def test_ext4atto_matches_original_on_late_partition(client, tmp_path):
    image = make_disk(tmp_path)
    before = hashlib.file_digest(image.open("rb"), "sha256").hexdigest()
    # Separate process avoids polluting imports of the isolated plugin.
    original = Path("/home/nomad/Scrivania/RootRunnersForensicTools/Ext4atto/backend")
    if not original.exists():
        original = ROOT / "plugins/ext4atto/src/backend"
    baseline_root = tmp_path / "baseline"
    (baseline_root / "original").mkdir(parents=True)
    shutil.copyfile(image, baseline_root / "original/challenge.dd")
    script = """from diskhunt.db import Database
from diskhunt.analyzer import Analyzer
from diskhunt.models import AnalysisOptions
from threading import Event
from pathlib import Path
import json,sys
root=Path(sys.argv[1]);db=Database(root/'db.sqlite3')
db.create_job('analysis','challenge.dd',str(root/'original/challenge.dd'),AnalysisOptions().model_dump())
Analyzer(db,'analysis',Event()).run()
print(json.dumps({'status':db.get_job('analysis')['status'],'flags':db.results('analysis','flag')}))
"""
    baseline = subprocess.run(
        [sys.executable, "-c", script, str(baseline_root)],
        env={**os.environ, "PYTHONPATH": str(original)},
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    expected = {f["candidate"] for f in json.loads(baseline.stdout)["flags"]}
    assert {"SRDNLEN{late_partition}", "flag{deleted_inode}", "picoCTF{nested_recovery}"} <= expected
    plugins, errors = discover(Settings().plugins)
    assert not errors
    result = client.app.state.sandbox.run(
        "analyze",
        {"id": "test", "name": image.name, "path": str(image), "type": "file", "size": image.stat().st_size},
        plugins["ext4atto"],
        {"byte_budget": 64 * 1024**2, "prefixes": ["flag", "CTF", "HTB", "picoCTF"]},
    )
    assert result["status"] in ("completed", "partial"), result.get("errors")
    assert expected <= {f["value"] for f in result["flags"]}
    assert all(0 <= f["confidence"] <= 1 for f in result["flags"])
    assert result["metrics"]["size"] == image.stat().st_size
    assert result["metrics"]["input_visible_bytes"] == image.stat().st_size
    assert not any("Vista input limitata" in w for w in result["warnings"])
    assert any(
        base64.b64decode(a["content_base64"]) == b"picoCTF{nested_recovery}" for a in result["artifacts"]
    )
    assert hashlib.file_digest(image.open("rb"), "sha256").hexdigest() == before

    compressed = tmp_path / "challenge.dd.gz"
    with image.open("rb") as src, gzip.open(compressed, "wb") as dst:
        shutil.copyfileobj(src, dst)
    plugin = plugins["ext4atto"]
    plugin["manifest"]["output_bytes"] = 1024
    converted = client.app.state.sandbox.run(
        "analyze",
        {
            "id": "compressed",
            "name": compressed.name,
            "path": str(compressed),
            "type": "file",
            "size": compressed.stat().st_size,
        },
        plugin,
        {"byte_budget": 64 * 1024**2, "prefixes": []},
    )
    assert converted["status"] == "partial", converted.get("errors")
    assert not converted["errors"]
    assert converted["metrics"]["analysis_size"] == image.stat().st_size
    assert expected <= {f["value"] for f in converted["flags"]}
    assert converted["metrics"]["omitted_artifacts"] > 0
