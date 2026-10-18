"""Deterministic passive fixture builders for document parser tests."""

import io
import struct
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))


@pytest.fixture
def pdf_fixture():
    """PDF with Info, XMP, invisible text, two revisions, action and trailing data."""
    xmp = b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description CreatorTool="BVAULT{pdf_metadata}"/></rdf:RDF></x:xmpmeta>'
    stream = zlib.compress(b"decoded stream BVAULT{stream}")
    return (
        b"%PDF-1.7\n1 0 obj << /Author (Alice) /CreatorTool (Tool) /JavaScript 2 0 R /EmbeddedFile 4 0 R >> endobj\n"
        + xmp
        + b"\n2 0 obj << /Length "
        + str(len(stream)).encode()
        + b" /Filter /FlateDecode >> stream\n"
        + stream
        + b"\nendstream endobj\n1 1 1 rg 3 Tr (hidden) Tj\nstartxref\n10\n%%EOF\n3 0 obj << /Type /OCG >> endobj\nstartxref\n20\n%%EOF\nTRAILING"
    )


@pytest.fixture
def office_fixture():
    """OOXML container with custom properties, comments, revision and hidden sheet."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr(
            "docProps/custom.xml",
            '<Properties xmlns="x"><property name="Flag">BVAULT{office}</property></Properties>',
        )
        archive.writestr("word/comments.xml", "<comments><comment>review</comment></comments>")
        archive.writestr("word/document.xml", '<w:document xmlns:w="w"><w:ins>new</w:ins></w:document>')
        archive.writestr("xl/workbook.xml", '<workbook><sheet state="veryHidden"/></workbook>')
        archive.writestr(
            "ppt/presentation.xml", '<p:presentation xmlns:p="p"><p:sldId show="0"/></p:presentation>'
        )
        archive.writestr("word/vbaProject.bin", b"passive macro bytes")
    return output.getvalue()


@pytest.fixture
def png_fixture():
    """One-pixel-like PNG structure with embedded textual metadata."""

    def chunk(kind, value):
        return (
            struct.pack(">I", len(value))
            + kind
            + value
            + struct.pack(">I", zlib.crc32(kind + value) & 0xFFFFFFFF)
        )

    return b"\x89PNG\r\n\x1a\n" + chunk(b"tEXt", b"Comment\x00BVAULT{png_text}") + chunk(b"IEND", b"")


@pytest.fixture
def jpeg_fixture():
    """JPEG carrying EXIF ASCII, XMP, IPTC and comment records."""
    value = b"BVAULT{exif}\x00"
    tiff = b"II*\x00" + struct.pack("<I", 8)
    tiff += struct.pack("<H", 1) + struct.pack("<HHII", 0x010E, 2, len(value), 26)
    tiff += b"\x00\x00\x00\x00" + value
    exif = b"Exif\x00\x00" + tiff
    xmp = b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><title>BVAULT{xmp}</title></x:xmpmeta>'
    iptc_value = b"BVAULT{iptc_tag}"
    iptc = b"\x1c\x02\x78" + struct.pack(">H", len(iptc_value)) + iptc_value
    segments = b""
    for marker, payload in (
        (b"\xff\xe1", exif),
        (b"\xff\xe1", xmp),
        (b"\xff\xed", iptc),
        (b"\xff\xfe", b"BVAULT{comment}"),
    ):
        segments += marker + struct.pack(">H", len(payload) + 2) + payload
    return b"\xff\xd8" + segments + b"\xff\xd9"
