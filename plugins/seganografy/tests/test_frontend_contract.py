"""Static UI guards for explicit log follow and structured filtering."""
from pathlib import Path
ROOT=Path(__file__).parents[3]
def test_completion_does_not_autoscroll_document_bottom():
 js=(ROOT/'frontend/js/app.js').read_text()
 assert 'window.scrollTo(0, document.body.scrollHeight)' not in js
 assert 'scrollIntoView(false)' not in js
 assert 'follow-logs' in js

def test_json_engine_has_technique_and_severity_filters():
 js=(ROOT/'frontend/js/presentation.js').read_text()
 assert '["technique", "severity"]' in js
