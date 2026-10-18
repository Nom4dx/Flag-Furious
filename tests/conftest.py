import json
import pytest
from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app


@pytest.fixture
def client(tmp_path):
    settings = Settings(storage=tmp_path / "storage")
    with TestClient(create_app(settings)) as client:
        yield client


@pytest.fixture
def case(client):
    return client.post("/api/cases", json={"name": "Test case"}).json()


def make_plugin(root, id="example", code=None, **extra):
    directory = root / id
    directory.mkdir(parents=True)
    manifest = {
        "id": id,
        "name": id,
        "version": "1.0",
        "class": "Plugin",
        "supported_asset_types": ["text", "file"],
        "domains": ["future-domain"],
        **extra,
    }
    (directory / "plugin.json").write_text(json.dumps(manifest))
    (directory / "extensions.json").write_text(json.dumps({"asset_types": ["text", "file"]}))
    (directory / "output_schema.json").write_text(
        json.dumps({"sections": [{"id": "a", "type": "json", "order": 1}]})
    )
    (directory / "plugin.py").write_text(
        code
        or "from app.core.plugin import BasePlugin\nclass Plugin(BasePlugin):\n def analyze(self,a,c,r): return {'summary':'ok'}\n"
    )
    return directory
