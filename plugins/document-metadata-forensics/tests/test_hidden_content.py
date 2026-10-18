"""Hidden-content tests cover zero-width, RTF hidden text and polyglot signatures."""

from src.hidden_content import analyze_hidden
from src.rtf_analyzer import analyze_rtf


def test_zero_width_payload():
    secret = b"BVAULT{zero_width}"
    encoded = "T" + "".join("\u200b" if bit == "0" else "\u200c" for byte in secret for bit in f"{byte:08b}")
    result = analyze_hidden(encoded.encode(), "void.txt")
    assert result.items[0]["normalized_value"] == secret.decode()


def test_rtf_hidden_and_polyglot():
    rtf = b"{\\rtf1 visible {\\v BVAULT{hidden}} \\field DDEAUTO}"
    assert "BVAULT" in analyze_rtf(rtf, "x.rtf").items[0]["text"]
    assert analyze_hidden(b"%PDF-1.7\nPK\x03\x04", "poly.pdf").findings
