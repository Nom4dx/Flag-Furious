"""Connector registry, editable DAG, execution and secret-lifetime tests."""

import json
import time
from pathlib import Path


def upload(client, case, data, name):
    response = client.post(
        "/api/assets",
        data={"case_id": case["id"]},
        files={"file": (name, data)},
    )
    assert response.status_code == 201, response.text
    return response.json()["assets"][0]


def wait_for_workflow(client, run_id):
    for _ in range(600):
        run = client.get(f"/api/workflow-runs/{run_id}").json()
        if run["status"] not in {"queued", "running", "paused"}:
            return run
        time.sleep(0.05)
    raise AssertionError("Il workflow non ha terminato")


def save(client, case, nodes, edges):
    response = client.post(
        "/api/workflows",
        json={"case_id": case["id"], "name": "Estrazione controllata", "nodes": nodes, "edges": edges},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_connector_catalog_and_workflow_validation(client, case):
    catalog = client.get("/api/connectors").json()
    ids = {item["id"] for item in catalog["connectors"]}
    assert {"bruteforce", "known-password", "plugin-archive-extractor"} <= ids
    assert catalog["errors"] == []

    asset = upload(client, case, b"plain", "evidence.txt")
    body = {
        "case_id": case["id"],
        "name": "Ciclo",
        "nodes": [
            {"id": "asset-a", "kind": "asset", "asset_id": asset["id"]},
            {"id": "connector-a", "kind": "connector", "connector_id": "plugin-archive-extractor"},
            {"id": "connector-b", "kind": "connector", "connector_id": "plugin-seganografy"},
        ],
        "edges": [
            {"id": "edge-a", "source": "connector-a", "target": "connector-b"},
            {"id": "edge-b", "source": "connector-b", "target": "connector-a"},
        ],
    }
    response = client.post("/api/workflows", json=body)
    assert response.status_code == 400
    assert "ciclo" in response.text.lower()


def test_plugin_connector_extracts_and_forwards_assets(client, case):
    import io
    import zipfile

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("note.txt", "flag{workflow_connector}")
    asset = upload(client, case, archive.getvalue(), "source.zip")
    workflow = save(
        client,
        case,
        [
            {"id": "asset-source", "kind": "asset", "asset_id": asset["id"], "x": 20, "y": 20},
            {
                "id": "connector-extract",
                "kind": "connector",
                "connector_id": "plugin-archive-extractor",
                "x": 280,
                "y": 20,
            },
        ],
        [{"id": "edge-extract", "source": "asset-source", "target": "connector-extract"}],
    )
    run_response = client.post(f"/api/workflows/{workflow['id']}/run", json={"secrets": {}})
    assert run_response.status_code == 202, run_response.text
    run = wait_for_workflow(client, run_response.json()["id"])
    connector = next(node for node in run["nodes"] if node["kind"] == "connector")
    assert run["status"] == "completed", run
    assert connector["output_count"] == 1
    assert run["artifacts"]
    assert client.get(f"/api/workflows?case_id={case['id']}").json()[0]["id"] == workflow["id"]


def test_known_password_connector_never_persists_secret(client, case):
    fixture = Path("plugins/bruteforce/fixtures/zipcrypto-secret.zip")
    asset = upload(client, case, fixture.read_bytes(), fixture.name)
    assert "bruteforce" not in {item["plugin_id"] for item in asset["compatible_plugins"]}
    workflow = save(
        client,
        case,
        [
            {"id": "asset-protected", "kind": "asset", "asset_id": asset["id"]},
            {
                "id": "connector-unlock",
                "kind": "connector",
                "connector_id": "known-password",
                "config": {"protection_type": "zipcrypto", "password": "must-be-removed"},
            },
        ],
        [{"id": "edge-unlock", "source": "asset-protected", "target": "connector-unlock"}],
    )
    assert "must-be-removed" not in json.dumps(workflow)
    response = client.post(
        f"/api/workflows/{workflow['id']}/run",
        json={"secrets": {"connector-unlock": {"password": "secret"}}},
    )
    assert response.status_code == 202, response.text
    run = wait_for_workflow(client, response.json()["id"])
    assert run["status"] == "completed", run
    assert next(node for node in run["nodes"] if node["kind"] == "connector")["output_count"] >= 1
    assert "secret" not in json.dumps(client.get(f"/api/workflow-runs/{run['id']}").json())
    for job_id in run["jobs"]:
        options = client.get(f"/api/jobs/{job_id}").json()["options"]["plugin_options"]["bruteforce"]
        assert options["known_password"] == "********"


def test_workflow_ui_contains_drag_drop_and_password_connector():
    html = Path("frontend/index.html").read_text()
    javascript = Path("frontend/js/workflows.js").read_text()
    assert 'id="workflow-pool-mode"' in html
    assert 'id="workflow-canvas"' in html
    assert "ondragstart" in javascript and "ondrop" in javascript
    assert 'field.type === "password"' in javascript
    assert "secrets = {}" in javascript


def test_encrypted_volume_connector_and_job_secrets_are_masked(client, case):
    """BitLocker credentials remain runtime-only and are masked in job APIs."""
    listed = client.get("/api/connectors").json()["connectors"]
    assert any(item["id"] == "bitlocker-readonly" for item in listed)
    asset = upload(client, case, b"x" * 1024, "volume.raw")
    response = client.post(
        "/api/jobs",
        json={
            "case_id": case["id"],
            "asset_ids": [asset["id"]],
            "plugin_ids": ["encrypted-volume-forensics"],
            "recursive": False,
            "plugin_options": {
                "encrypted-volume-forensics": {
                    "unlock": True,
                    "password": "never-store-volume-secret",
                }
            },
        },
    )
    assert response.status_code == 202
    job = response.json()
    options = job["options"]["plugin_options"]["encrypted-volume-forensics"]
    assert options["password"] == "********"
    assert "never-store-volume-secret" not in str(client.get("/api/jobs/" + job["id"]).json())
    client.post("/api/jobs/" + job["id"] + "/cancel")


def test_bitlocker_workflow_forwards_all_inputs_as_companion_candidates():
    """A disk and one or more FVEK nodes remain connected to one unlock run."""
    from app.core.workflow_manager import WorkflowManager

    connector = {
        "id": "bitlocker-readonly",
        "plugin_id": "encrypted-volume-forensics",
    }
    options = WorkflowManager._options(
        connector,
        {"config": {"unlock": True, "use_companion_keys": True}},
        {},
        ["disk-asset", "candidate-fvek"],
    )
    configured = options["encrypted-volume-forensics"]
    assert configured["companion_asset_ids"] == ["disk-asset", "candidate-fvek"]
    assert configured["use_companion_keys"] is True
