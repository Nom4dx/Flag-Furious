"""PDF tests cover revisions, post-EOF, layers, actions and Flate streams."""

from src.pdf_analyzer import analyze_pdf


def test_pdf_static_analysis(pdf_fixture):
    result = analyze_pdf(pdf_fixture, "fixture.pdf")
    kinds = {x["type"] for x in result.findings}
    assert {
        "incremental_revisions",
        "post_eof_data",
        "active_or_embedded_content",
        "white_text",
        "invisible_render_mode",
    } <= kinds
    assert any(x["content"] == b"decoded stream BVAULT{stream}" for x in result.artifacts)
