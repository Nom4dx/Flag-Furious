"""Metadata parser fixtures cover XMP, PDF Info, PNG text and provenance."""

from src.image_analyzer import analyze_image
from src.metadata import extract_metadata


def test_pdf_info_and_xmp(pdf_fixture):
    items = extract_metadata(pdf_fixture, "fixture.pdf").items
    assert any(
        x["field"].lower().endswith("creatortool") and "BVAULT" in x["normalized_value"] for x in items
    )
    assert all("source" in x and "parser" in x for x in items)


def test_png_text_chunk(png_fixture):
    result = analyze_image(png_fixture, "fixture.png")
    assert any("BVAULT{png_text}" in x.get("normalized_value", "") for x in result.items)


def test_jpeg_exif_xmp_iptc_and_comment(jpeg_fixture):
    items = extract_metadata(jpeg_fixture, "fixture.jpg").items
    values = {x.get("normalized_value") for x in items}
    assert {
        "BVAULT{exif}",
        "BVAULT{xmp}",
        "BVAULT{iptc_tag}",
        "BVAULT{comment}",
    } <= values
