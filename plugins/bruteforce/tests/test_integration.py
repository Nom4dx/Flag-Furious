"""Loader, manifest integrations, UI and original immutability tests."""

import hashlib
from pathlib import Path
from app.core.plugin_loader import discover

ROOT = Path(__file__).parents[3]


def test_loader_and_integration_manifests():
    plugins, errors = discover(ROOT / "plugins")
    assert not errors and plugins["bruteforce"]["available"]
    for pid in (
        "archive-extractor",
        "polyglot-and-embedded-content",
        "seganografy",
        "ext4atto",
        "document-metadata-forensics",
    ):
        assert plugins[pid]["manifest"]["unlock_capabilities"]["broker_plugin"] == "bruteforce"


def test_recovery_ui_exists_only_in_connector_workspace():
    html = (ROOT / "frontend/index.html").read_text()
    js = (ROOT / "frontend/js/workflows.js").read_text()
    assert 'id="bruteforce-options"' not in html
    assert (
        'id="workflow-canvas"' in html and "wordlist_multiselect" in js and 'field.type === "password"' in js
    )
    plugins, _ = discover(ROOT / "plugins")
    assert plugins["bruteforce"]["manifest"]["activation"] == "connector_only"


def test_scroll_guard_preserved():
    js = (ROOT / "frontend/js/app.js").read_text()
    assert "scrollIntoView(false)" not in js and "document.body.scrollHeight" not in js


def test_fixture_immutable_after_adapter(tmp_path):
    source = ROOT / "plugins/bruteforce/fixtures/zipcrypto-secret.zip"
    if not source.exists():
        return
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    from plugins.bruteforce.src.adapters.zip_adapter import ZipAdapter
    from plugins.bruteforce.src.limits import Limits

    ZipAdapter().extract(
        {"path": str(source)},
        "secret",
        {"output_dir": str(tmp_path), "limits": Limits(10, 10, 1, 1024 * 1024, 100)},
    )
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before


def test_shared_request_contract():
    from app.core.unlock_requests import request

    a = request("a", "zipcrypto", "archive-extractor", ["zip_adapter"])
    b = request("b", "steghide", "seganografy", ["steghide_adapter"])
    assert a["status"] == b["status"] == "waiting_for_user"
    assert a["parent_plugin"] != b["parent_plugin"]


def test_wordlist_api_and_job_secret_masking(tmp_path):
    from fastapi.testclient import TestClient
    from app.config import Settings
    from app.main import create_app

    wordroot = tmp_path / "lists"
    wordroot.mkdir()
    (wordroot / "ctf.txt").write_text("secret\n")
    with TestClient(create_app(Settings(storage=tmp_path / "storage"))) as client:
        remembered = client.post("/api/plugins/bruteforce/wordlist-roots", json={"path": str(wordroot)})
        assert remembered.status_code == 200
        listed = client.get("/api/plugins/bruteforce/wordlists").json()
        assert listed["wordlists"][0]["name"] == "ctf.txt"
        case = client.post("/api/cases", json={"name": "masked"}).json()
        asset = client.post(
            "/api/assets", json={"case_id": case["id"], "name": "x.enc", "type": "text", "content": "cipher"}
        ).json()["assets"][0]
        job = client.post(
            "/api/jobs",
            json={
                "case_id": case["id"],
                "asset_ids": [asset["id"]],
                "plugin_ids": ["bruteforce"],
                "recursive": False,
                "plugin_options": {"bruteforce": {"known_password": "never-persist-this", "confirmed": True}},
            },
        ).json()
        assert job["options"]["plugin_options"]["bruteforce"]["known_password"] == "********"
        assert "never-persist-this" not in str(client.get("/api/jobs/" + job["id"]).json())
        client.post("/api/jobs/" + job["id"] + "/cancel")
