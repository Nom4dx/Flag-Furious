from copy import deepcopy
import pytest
from app.core.presentation import present, present_graph, resolve, MISSING, validate_mapping
from app.core.plugin_loader import discover
from app.config import Settings


def mapping():
    return {
        "presentation": {
            "palette": "network",
            "groups": [{"id": "net", "title": "Rete"}],
            "sections": [
                {
                    "id": "hosts",
                    "title": "Host rilevati",
                    "source": "data.analysis.hosts",
                    "type": "table",
                    "group": "net",
                    "fields": [{"field": "bytes", "label": "Dimensione", "format": "bytes"}],
                },
                {
                    "id": "count",
                    "title": "Contatore",
                    "source": "metrics.count",
                    "type": "auto",
                    "group": "net",
                },
                {"id": "disabled", "title": "Disabilitato", "source": "metrics.disabled", "group": "net"},
                {"id": "absent", "title": "Assente", "source": "metrics.missing", "group": "net"},
                {"id": "empty", "title": "Vuota", "source": "data.analysis.empty", "group": "net"},
            ],
        }
    }


def test_mapping_nested_paths_and_evidence_unchanged():
    raw = {
        "plugin_id": "future",
        "sections": [
            {
                "id": "analysis",
                "data": {"hosts": [{"bytes": 2048, "name": "a"}], "extra": {"secret": "kept"}, "empty": []},
            }
        ],
        "metrics": {"count": 0, "disabled": False},
    }
    original = deepcopy(raw)
    result = present(raw, mapping())
    assert raw == original
    assert result["presentation"]["palette"] == "network"
    assert result["presentation"]["style"]["primary"] == "#42bce8"
    sections = {s["id"]: s for s in result["presentation"]["sections"]}
    assert sections["hosts"]["data"] == [{"bytes": 2048, "name": "a"}]
    assert sections["hosts"]["fields"][0]["label"] == "Dimensione"
    assert sections["count"]["data"] == 0 and sections["disabled"]["data"] is False
    assert "absent" not in sections and "empty" not in sections
    assert sections["unmapped-analysis"]["data"]["extra"]["secret"] == "kept"
    assert "hosts" not in sections["unmapped-analysis"]["data"]
    assert "empty" not in sections["unmapped-analysis"]["data"]
    assert "result-metrics" not in sections


def test_legacy_results_get_structured_fallback():
    output = present({"sections": [{"id": "legacy", "type": "json", "data": {"a": 1}}]})
    assert output["presentation"]["sections"][0]["type"] == "auto"
    assert output["sections"][0]["type"] == "json"


@pytest.mark.parametrize(
    "change",
    [
        {"sections": [{"id": "a", "title": "A", "source": "data.x", "group": "unknown"}]},
        {"sections": [{"id": "a", "title": "A", "source": "data..x", "group": "net"}]},
        {
            "sections": [
                {
                    "id": "a",
                    "title": "A",
                    "source": "data.x",
                    "group": "net",
                    "fields": [{"field": "a", "format": "javascript"}],
                }
            ]
        },
        {"groups": [{"id": "net", "title": "Net"}, {"id": "net", "title": "Duplicate"}]},
        {"palette": "not-registered"},
    ],
)
def test_invalid_mapping_rejected(change):
    value = mapping()
    value["presentation"].update(change)
    with pytest.raises(ValueError):
        validate_mapping(value)


def test_graph_outputs_and_index_paths():
    raw = {
        "nodes": [
            {
                "id": "x",
                "plugin_id": "future",
                "result": {"sections": [{"id": "analysis", "data": {"hosts": []}}]},
            }
        ],
        "edges": [],
    }
    original = deepcopy(raw)
    result = present_graph(raw, {"future": mapping()})
    assert "presentation" in result["nodes"][0]["result"]
    assert raw == original
    assert resolve({"a": [{"b": 3}]}, "a.0.b") == 3
    assert resolve({"a": []}, "a.1") is MISSING


def test_all_shipped_plugins_have_valid_precise_mappings():
    plugins, errors = discover(Settings().plugins)
    assert not errors
    for plugin in plugins.values():
        value = validate_mapping(plugin["output_schema"])
        assert value.groups and value.sections
    assert {s.id for s in validate_mapping(plugins["pic-up"]["output_schema"]).sections}.issuperset(
        {"picup-hosts", "picup-streams", "picup-dns"}
    )
    assert {s.id for s in validate_mapping(plugins["ext4atto"]["output_schema"]).sections}.issuperset(
        {"partitions", "deleted", "carved"}
    )


def test_results_endpoint_maps_saved_legacy_outputs_without_reanalysis(client, case):
    value = {
        "id": "mapping-test",
        "case_id": case["id"],
        "results": [
            {
                "plugin_id": "text-inspector",
                "sections": [
                    {"id": "inventory", "data": [{"metric": "Byte", "value": 10}]},
                    {"id": "analysis", "data": {"name": "legacy"}},
                ],
            }
        ],
    }
    client.app.state.store.put("job", value)
    response = client.get("/api/jobs/mapping-test/results").json()
    assert response[0]["presentation"]["sections"][0]["type"] == "metrics"
    assert client.app.state.store.get("job", "mapping-test") == value


def test_unmapped_root_fields_are_visible():
    result = present({"sections": [], "findings": [{"offset": 64}], "future_data": {"value": 0}})
    sections = {s["id"]: s for s in result["presentation"]["sections"]}
    assert sections["result-findings"]["data"] == [{"offset": 64}]
    assert sections["result-future_data"]["data"] == {"value": 0}
