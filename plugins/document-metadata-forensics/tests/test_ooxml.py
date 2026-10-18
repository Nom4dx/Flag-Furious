"""Office container tests cover properties, comments, revisions and hidden state."""

from src.ooxml_analyzer import analyze_ooxml


def test_ooxml_static_inventory(office_fixture):
    result = analyze_ooxml(office_fixture, "fixture.docx")
    assert any("BVAULT{office}" in x.get("normalized_value", "") for x in result.items)
    assert {x["type"] for x in result.findings} >= {
        "office_revision",
        "hidden_office_content",
        "macro_or_embedded_object",
    }
    assert result.artifacts
