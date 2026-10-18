"""End-to-end contract, sandbox, artifact and immutability test for documents."""

import hashlib
from pathlib import Path

from test_hub import start, upload


def test_document_plugin_end_to_end(client, case):
    """A hub job exposes an XMP flag with provenance and a report artifact."""
    data = b'%PDF-1.7\n1 0 obj << /CreatorTool (BVAULT{document_fixture}) >> endobj\n<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description CreatorTool="BVAULT{document_fixture}"/></rdf:RDF></x:xmpmeta>\nstartxref\n0\n%%EOF\n'
    asset = upload(client, case, data, "metadata.pdf")
    original = Path(client.app.state.store.get("asset", asset["id"])["path"])
    before = hashlib.sha256(original.read_bytes()).hexdigest()
    job = start(
        client,
        case,
        asset,
        ["document-metadata-forensics"],
        prefixes=["BVAULT"],
        recursive=False,
    )
    results = client.get(f"/api/jobs/{job['id']}/results").json()
    result = next(item for item in results if item["plugin_id"] == "document-metadata-forensics")
    assert result["status"] == "completed", result["warnings"]
    assert any(
        flag["value"] == "BVAULT{document_fixture}" and flag["source"] == "metadata.pdf"
        for flag in result["flags"]
    )
    assert result["artifacts"] and result["presentation"]["sections"]
    artifact = result["artifacts"][0]
    assert client.get(f"/api/artifacts/{artifact['id']}/preview").status_code == 200
    assert hashlib.sha256(original.read_bytes()).hexdigest() == before
