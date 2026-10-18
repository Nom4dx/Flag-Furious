import base64
import hashlib
import io
import json
import struct
import time
import zipfile
import zlib
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import create_app
from app.config import Settings
from app.core.visualization_engine import TYPES, validate_visualization
from app.core.result_normalizer import normalize
from app.core.security import contained
from conftest import make_plugin


def png(signature=b"\x89PNG\r\n\x1a\n"):
    def chunk(name, data):
        return struct.pack(">I", len(data)) + name + data + struct.pack(">I", zlib.crc32(name + data))

    return (
        signature
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
        + chunk(b"IEND", b"")
    )


def upload(client, case, data, name="evidence.bin"):
    r = client.post("/api/assets", data={"case_id": case["id"]}, files={"file": (name, data)})
    assert r.status_code == 201, r.text
    return r.json()["assets"][0]


def wait(client, id):
    for _ in range(300):
        result = client.get("/api/jobs/" + id).json()
        if result["status"] not in ("running", "queued"):
            return result
        time.sleep(0.05)
    raise AssertionError("Job did not terminate")


def start(client, case, asset, plugins=None, **opts):
    r = client.post(
        "/api/jobs", json={"case_id": case["id"], "asset_ids": [asset["id"]], "plugin_ids": plugins, **opts}
    )
    assert r.status_code == 202, r.text
    return wait(client, r.json()["id"])


def test_registry_real_tools(client):
    health = client.get("/api/health").json()
    assert health["sandbox"], health
    registry = client.get("/api/plugins").json()
    assert {p["manifest"]["id"] for p in registry["plugins"]} == {
        "archive-extractor",
        "bruteforce",
        "binary-static-analysis",
        "document-metadata-forensics",
        "text-inspector",
        "ext4atto",
        "githappens",
        "log-forensics",
        "hidgrabber",
        "pic-up",
            "polyglot-and-embedded-content",
            "seganografy",
            "encrypted-volume-forensics",
        }
    assert all(p["available"] for p in registry["plugins"]), registry["errors"]
    assert client.get("/api/plugins/text-inspector/about").json()["network"] is False


def test_start_without_plugins(tmp_path):
    settings = Settings(storage=tmp_path / "store", plugins=tmp_path / "plugins")
    settings.plugins.mkdir()
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/health").json()["status"] == "ok"
        assert "Nessun plugin" in client.get("/api/plugins").json()["message"]
        case = client.post("/api/cases", json={"name": "Empty registry"}).json()
        a = upload(client, case, b"flag{fallback}")
        j = start(client, case, a)
        assert j["flags"][0]["value"] == "flag{fallback}"
        assert client.get("/api/jobs/" + j["id"] + "/results").json()[0]["plugin_id"] == "magic-wrapper"


def test_faulty_plugin_and_cycle(tmp_path):
    root = tmp_path / "plugins"
    make_plugin(root, "broken", 'raise RuntimeError("bad import")')
    make_plugin(root, "good")
    make_plugin(root, "cyclic", dependencies=["cyclic"])
    with TestClient(create_app(Settings(storage=tmp_path / "store", plugins=root))) as c:
        values = {x["manifest"]["id"]: x for x in c.get("/api/plugins").json()["plugins"]}
        assert values["good"]["available"]
        assert not values["broken"]["available"]
        assert not values["cyclic"]["available"]


def test_hashes_magic_false_extension(client, case):
    data = png()
    a = upload(client, case, data, "actually.txt")
    for algorithm in (
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "sha224",
        "sha384",
        "sha3_256",
        "blake2b",
        "blake2s",
    ):
        assert a["hashes"][algorithm] == hashlib.new(algorithm, data).hexdigest()
    assert a["triage"]["format"] == "png"
    assert a["triage"]["extension_mismatch"]
    assert len(a["triage"]["findings"]) >= 2
    assert a["triage"]["structures"][0]["evidence"]


def test_damaged_magic_explicit_repair(client, case):
    original = png(b"BROKEN!!")
    a = upload(client, case, original, "damaged.png")
    assert a["triage"]["repair_available"]
    assert client.post("/api/assets/" + a["id"] + "/repair", json={}).status_code == 400
    r = client.post("/api/assets/" + a["id"] + "/repair", json={"confirm": True})
    assert r.status_code == 201, r.text
    repaired = r.json()
    assert repaired["repair"]["old_magic"] != repaired["repair"]["new_magic"]
    downloaded = client.get("/api/artifacts/" + repaired["artifact"]["id"] + "/download").content
    assert downloaded == png()
    source = client.app.state.store.get("asset", a["id"])
    assert Path(source["path"]).read_bytes() == original
    assert client.get("/api/cases/" + case["id"]).json()["audit"][0]["action"] == "explicit magic repair"


def test_corrupt_crc_refuses_repair(client, case):
    data = bytearray(png(b"BROKEN!!"))
    data[-1] ^= 1
    a = upload(client, case, bytes(data), "bad.png")
    assert not a["triage"]["repair_available"]
    assert client.post("/api/assets/" + a["id"] + "/repair", json={"confirm": True}).status_code == 400


def test_artifact_bytes_are_deduplicated_inside_case(client, case):
    """Repeated plugin runs keep distinct provenance without duplicating evidence bytes."""
    parent = upload(client, case, b"source", "source.bin")
    stored_parent = client.app.state.store.get("asset", parent["id"])
    item = {
        "name": "recovered.txt",
        "content_base64": base64.b64encode(b"same recovered bytes").decode(),
        "method": "fixture extraction",
    }

    first, first_asset = client.app.state.artifacts.register(item, stored_parent, "fixture", "job-1")
    second, second_asset = client.app.state.artifacts.register(item, stored_parent, "fixture", "job-2")

    assert first_asset["id"] == second_asset["id"]
    assert first["deduplicated"] is False
    assert second["deduplicated"] is True
    assert len(client.app.state.store.list("asset", case["id"])) == 2


@pytest.mark.parametrize(
    "kind,content",
    [
        ("text", "flag{text}"),
        ("json", {"x": "flag{json}"}),
        ("hex", b"flag{hex}".hex()),
        ("url", "https://example.invalid/flag{url}"),
        ("new_custom_type", "flag{custom}"),
    ],
)
def test_non_file_assets(client, case, kind, content):
    r = client.post("/api/assets", json={"case_id": case["id"], "type": kind, "content": content})
    assert r.status_code == 201, r.text
    a = r.json()["assets"][0]
    assert "triage" not in a
    j = start(client, case, a, plugins=[])
    assert j["flags"], j
    assert all(
        x["plugin_id"] != "magic-wrapper" for x in client.get("/api/jobs/" + j["id"] + "/results").json()
    )


def test_recursive_zip_graph_artifacts_report(client, case):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("flag.txt", "flag{inside_zip}")
        z.writestr("../escape.txt", "no escape")
    a = upload(client, case, archive.getvalue(), "archive.zip")
    j = start(client, case, a, ["archive-extractor"])
    assert any(f["value"] == "flag{inside_zip}" for f in j["flags"]), j
    results = client.get("/api/jobs/" + j["id"] + "/results").json()
    extracted = next(r for r in results if r["plugin_id"] == "archive-extractor")
    assert len(extracted["artifacts"]) == 1, extracted
    assert extracted["warnings"]
    artifact = extracted["artifacts"][0]
    assert client.get("/api/artifacts/" + artifact["id"] + "/download").content == b"flag{inside_zip}"
    assert "flag{inside_zip}" in client.get("/api/artifacts/" + artifact["id"] + "/preview").json()["text"]
    derived = client.get("/api/assets/" + artifact["asset_id"]).json()
    assert derived["parent_id"] == a["id"] and derived["depth"] == 1
    graph = client.get("/api/jobs/" + j["id"] + "/graph").json()
    assert graph["edges"]
    assert {"asset", "plugin", "artifact", "flag", "report"}.issubset({n["type"] for n in graph["nodes"]})
    assert any(r["visualizations"] for r in results), results
    report = client.get("/api/reports/" + case["id"]).json()
    assert report["jobs"] and report["artifacts"]
    assert client.get("/api/reports/" + case["id"] + "?format=html").status_code == 200
    assert client.delete("/api/cases/" + case["id"]).status_code == 200
    assert client.get("/api/assets/" + a["id"]).status_code == 404
    assert not (client.app.state.settings.storage / "cases" / case["id"]).exists()


@pytest.mark.parametrize(
    "encoded,method",
    [
        (base64.b64encode(b"flag{base64}").decode(), "base64"),
        (b"flag{hex}".hex(), "hex"),
        ("flag%7Burl%7D", "url"),
        ("synt{ebg}", "rot13"),
        ("}esrever{galf", "reverse"),
        ("fl ag{sp lit}", "split"),
    ],
)
def test_flag_decodings(client, encoded, method):
    r = client.post("/api/flags/search", json={"text": encoded, "prefixes": ["flag"]})
    assert r.status_code == 200, r.text
    assert any(f["method"] == method for f in r.json()["flags"]), r.json()


def test_flag_regex_timeout(client):
    r = client.post(
        "/api/flags/search", json={"text": "a" * 30000 + "!", "prefixes": [], "patterns": ["(a+)+$"]}
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "partial"


def test_multi_plugin_and_schema(client, case):
    a = upload(client, case, b"plain flag{both}", "notes.txt")
    j = start(client, case, a, ["text-inspector", "pic-up"], recursive=False)
    results = client.get("/api/jobs/" + j["id"] + "/results").json()
    assert {"text-inspector", "pic-up"}.issubset({r["plugin_id"] for r in results})
    pic = next(r for r in results if r["plugin_id"] == "pic-up")
    assert pic["status"] == "completed", pic
    inspector = next(r for r in results if r["plugin_id"] == "text-inspector")
    assert inspector["sections"][0]["type"] == "table"


def test_cancel_timeout_and_partial_events(tmp_path):
    root = tmp_path / "plugins"
    make_plugin(
        root,
        "slow",
        "from app.core.plugin import BasePlugin\nimport time\nclass Plugin(BasePlugin):\n def analyze(self,a,c,r):\n  r.phase('working'); r.partial({'summary':'checkpoint'}); r.log('started')\n  time.sleep(10)\n  return {'summary':'done'}\n",
        timeout=1,
    )
    with TestClient(create_app(Settings(storage=tmp_path / "store", plugins=root))) as client:
        case = client.post("/api/cases", json={"name": "Timeout"}).json()
        a = client.post(
            "/api/assets", json={"case_id": case["id"], "type": "text", "content": "hello"}
        ).json()["assets"][0]
        j = start(client, case, a, ["slow"])
        r = client.get("/api/jobs/" + j["id"] + "/results").json()[0]
        assert r["status"] == "partial" and "Timeout" in r["summary"], r
        assert client.get("/api/jobs/" + j["id"] + "/logs").json()
        request = client.post(
            "/api/jobs", json={"case_id": case["id"], "asset_ids": [a["id"]], "plugin_ids": ["slow"]}
        ).json()
        assert client.delete("/api/cases/" + case["id"]).status_code == 400
        client.post("/api/jobs/" + request["id"] + "/cancel", json={})
        assert wait(client, request["id"])["status"] == "cancelled"


@pytest.mark.parametrize("input_access", ["bounded", "random_access"])
def test_sandbox_denies_network_and_original_write(tmp_path, input_access):
    root = tmp_path / "plugins"
    make_plugin(
        root,
        "isolation",
        "from app.core.plugin import BasePlugin\nimport socket\nclass Plugin(BasePlugin):\n def analyze(self,a,c,r):\n  failures=[]\n  try: open(a['path'],'wb').write(b'changed')\n  except OSError: failures.append('readonly')\n  try: socket.create_connection(('1.1.1.1',80),timeout=.2)\n  except OSError: failures.append('network')\n  try: open('/etc/passwd').read()\n  except OSError: failures.append('host')\n  return {'summary':','.join(failures)}\n",
    )
    manifest_path = root / "isolation/plugin.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["input_access"] = input_access
    manifest_path.write_text(json.dumps(manifest))
    with TestClient(create_app(Settings(storage=tmp_path / "store", plugins=root))) as client:
        case = client.post("/api/cases", json={"name": "Isolation"}).json()
        a = upload(client, case, b"evidence")
        j = start(client, case, a, ["isolation"])
        r = client.get("/api/jobs/" + j["id"] + "/results").json()
        assert r[-1]["summary"] == "readonly,network,host", r
        assert Path(client.app.state.store.get("asset", a["id"])["path"]).read_bytes() == b"evidence"


def test_budget_partial(client, case):
    a = upload(client, case, b"a" * 5000)
    j = start(client, case, a, [], byte_budget=1024)
    assert j["status"] == "partial" and j["bytes_remaining"] == 0


def test_cross_case_path_and_origin(client, case, tmp_path):
    a = upload(client, case, b"safe", "../../escape.txt")
    assert a["name"] == "escape.txt"
    other = client.post("/api/cases", json={"name": "Other"}).json()
    assert client.post("/api/jobs", json={"case_id": other["id"], "asset_ids": [a["id"]]}).status_code == 400
    assert client.post("/api/cases", json={}, headers={"Origin": "https://evil.example"}).status_code == 403
    with pytest.raises(ValueError):
        contained(tmp_path, tmp_path / ".." / "escape")


def test_normalizer_and_visualization_types():
    r = normalize(
        {"sections": [{"id": "second", "data": []}, {"id": "first", "data": []}]},
        "p",
        "a",
        {
            "sections": [
                {"id": "first", "type": "table", "order": 1},
                {"id": "second", "type": "json", "order": 2},
            ]
        },
    )
    assert r["sections"][0]["id"] == "first"
    for kind in TYPES:
        data = (
            {"nodes": [], "edges": []}
            if kind in ("tree", "graph", "execution_graph", "network_graph")
            else [{"x": 0, "y": 1}]
        )
        visual = validate_visualization({"type": kind, "data": data})
        assert visual["palette"] == "forensic"
        assert visual["style"]["primary"] == "#27d6a1"
    assert validate_visualization({"type": "bar", "data": [{"x": 0, "y": 1}], "palette": "network"})["palette"] == "network"
    with pytest.raises(ValueError):
        validate_visualization({"type": "bar", "data": [{"x": 0, "y": 1}], "palette": "arbitrary"})
    with pytest.raises(ValueError):
        validate_visualization({"type": "line", "data": "wrong"})
    with pytest.raises(ValueError):
        validate_visualization({"type": "invented", "data": []})


def test_directory_analysis_and_traversal(client, case):
    response = client.post(
        "/api/assets",
        data={"case_id": case["id"], "asset_type": "directory"},
        files=[("files", ("notes/flag.txt", b"flag{directory}")), ("files", ("notes/data.json", b'{"a":1}'))],
    )
    assert response.status_code == 201, response.text
    directory = response.json()["assets"][0]
    assert directory["type"] == "directory" and "triage" not in directory
    j = start(client, case, directory, ["githappens"])
    assert any(f["value"] == "flag{directory}" for f in j["flags"]), j
    result = client.get("/api/jobs/" + j["id"] + "/results").json()[0]
    assert result["status"] == "completed", result
    assert result["sections"][0]["data"].keys() == {"git", "cache", "history", "slack"}
    malicious = client.post(
        "/api/assets",
        data={"case_id": case["id"], "asset_type": "directory"},
        files={"files": ("../escape.txt", b"no")},
    )
    assert malicious.status_code == 400


def test_legacy_adapters_execute(client, case):
    # Empty but valid PCAP global header, plus a small raw image for disk parsers.
    capture = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    a = upload(client, case, capture, "empty.pcap")
    j = start(client, case, a, ["hidgrabber", "pic-up"], recursive=False)
    results = client.get("/api/jobs/" + j["id"] + "/results").json()
    for id in ["hidgrabber", "pic-up"]:
        item = next(r for r in results if r["plugin_id"] == id)
        assert item["status"] == "completed", item
    assert any(entry.get("command") for entry in client.get("/api/jobs/" + j["id"] + "/logs").json())
    disk = upload(client, case, b"\x00" * 8192, "disk.dd")
    job = start(client, case, disk, ["ext4atto"], recursive=False)
    item = next(
        r for r in client.get("/api/jobs/" + job["id"] + "/results").json() if r["plugin_id"] == "ext4atto"
    )
    assert item["status"] == "completed", item


def test_embedded_multiple_and_custom_signature(client, case, tmp_path):
    from app.core.magic_wrapper import all_matches

    data = b"PREFIX123" + png() + b"\x7fELF" + b"\x00" * 64
    found, partial = all_matches(data, {})
    assert any(f["offset"] == 9 and "png" in f["description"].lower() for f in found)
    assert any(f["offset"] > 9 and "Linkable" in f["description"] for f in found)
    extra = tmp_path / "rules.json"
    extra.write_text(json.dumps([{"pattern": "41 42 ?? 44 45", "offset": 3, "description": "custom format"}]))
    found, _ = all_matches(b"---ABZDE", {"signature_files": [str(extra)]})
    assert any(f["description"] == "custom format" and f["offset"] == 3 for f in found)


def test_per_signature_embedded_cap_is_not_reported_as_incomplete():
    """Repeated short binary patterns are capped as noise without a partial warning."""
    from app.core.magic_wrapper import all_matches
    from app.vendor.magic_wrapper import app as legacy

    rule = next(r for r in legacy.COMPILED_MAGIC_RULES if "TrueType font" in r.description)
    pattern = bytes(0 if value is None else value for value in rule.tokens)
    found, partial = all_matches(pattern * 80, {"embedded_matches_per_signature": 4})

    assert found
    assert partial is False


def test_plugin_symlinks_rejected(tmp_path):
    from app.core.plugin_loader import discover

    root = tmp_path / "plugins"
    p = make_plugin(root)
    (p / "secret").symlink_to("/etc/passwd")
    valid, errors = discover(root)
    assert not valid and "Symlink" in errors[0]["error"]


def test_invalid_budgets_and_plugin_named_evidence(client, case):
    response = client.post("/api/flags/search", json={"text": "flag{x}", "byte_budget": -1})
    assert response.status_code == 400
    a = upload(client, case, b"plain text", "plugin")
    j = start(client, case, a, ["text-inspector"])
    result = next(
        r
        for r in client.get("/api/jobs/" + j["id"] + "/results").json()
        if r["plugin_id"] == "text-inspector"
    )
    assert result["status"] == "completed", result
    assert client.post("/api/cases", json=[]).status_code == 400


def test_streaming_dependencies_and_cycle_prevention(tmp_path):
    root = tmp_path / "plugins"
    make_plugin(
        root,
        "producer",
        "from app.core.plugin import BasePlugin\nclass Plugin(BasePlugin):\n def analyze(self,a,c,r):\n  yield {'sections':[{'id':'a','data':{'first':1}}]}\n  yield {'summary':'checkpoint final','derived_assets':[{'name':'same.txt','type':'text','content':'same'}]}\n",
    )
    make_plugin(
        root,
        "consumer",
        "from app.core.plugin import BasePlugin\nclass Plugin(BasePlugin):\n def analyze(self,a,c,r):\n  return {'summary':c['dependency_results']['producer']['summary']}\n",
        dependencies=["producer"],
    )
    with TestClient(create_app(Settings(storage=tmp_path / "store", plugins=root))) as client:
        case = client.post("/api/cases", json={"name": "Streaming"}).json()
        a = client.post(
            "/api/assets", json={"case_id": case["id"], "type": "text", "content": "same"}
        ).json()["assets"][0]
        j = start(client, case, a, ["consumer"])
        results = client.get("/api/jobs/" + j["id"] + "/results").json()
        assert [r["plugin_id"] for r in results] == ["producer", "consumer"]
        assert results[1]["summary"] == "checkpoint final"
        assert len(results[0]["derived_assets"]) == 1
        graph = client.get("/api/jobs/" + j["id"] + "/graph").json()
        assert any(e["type"] == "dependency" for e in graph["edges"])
        assert any(n.get("partial_result") for n in graph["nodes"])


def test_persistence_and_restart_marker(tmp_path):
    settings = Settings(storage=tmp_path / "store", plugins=tmp_path / "empty")
    settings.plugins.mkdir()
    with TestClient(create_app(settings)) as client:
        case = client.post("/api/cases", json={"name": "Persistent"}).json()
        a = upload(client, case, b"flag{persist}")
        j = start(client, case, a, [])
        stored = client.app.state.store.get("job", j["id"])
        stored["status"] = "running"
        client.app.state.store.put("job", stored)
    with TestClient(create_app(settings)) as client:
        assert (
            client.get("/api/assets/" + a["id"]).json()["hashes"]["sha256"]
            == hashlib.sha256(b"flag{persist}").hexdigest()
        )
        assert client.get("/api/jobs/" + j["id"]).json()["status"] == "partial"


def test_memory_and_output_limits(tmp_path):
    root = tmp_path / "plugins"
    make_plugin(
        root,
        "limits",
        "from app.core.plugin import BasePlugin\nfrom pathlib import Path\nclass Plugin(BasePlugin):\n def analyze(self,a,c,r):\n  checks=[]\n  try: huge=bytearray(1024**3)\n  except MemoryError: checks.append('memory limited')\n  try: Path('/work/large').write_bytes(b'x'*2048)\n  except OSError: checks.append('file limited')\n  return {'summary':','.join(checks)}\n",
        memory_mb=128,
        output_bytes=1024,
    )
    with TestClient(create_app(Settings(storage=tmp_path / "store", plugins=root))) as client:
        case = client.post("/api/cases", json={"name": "Resource limits"}).json()
        a = client.post(
            "/api/assets", json={"case_id": case["id"], "type": "text", "content": "small"}
        ).json()["assets"][0]
        j = start(client, case, a, ["limits"])
        r = client.get("/api/jobs/" + j["id"] + "/results").json()[0]
        assert r["summary"] == "memory limited,file limited", r
