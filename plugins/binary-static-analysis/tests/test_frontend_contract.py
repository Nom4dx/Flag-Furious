"""Static regression checks for mapped filters and completion scroll behavior."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]

def test_mapped_tables_filter_severity_and_confidence():
    source=(ROOT/"frontend/js/presentation.js").read_text()
    assert '"technique", "severity"' in source
    assert "Confidenza minima" in source


def test_completion_does_not_follow_log_tail():
    source=(ROOT/"frontend/js/app.js").read_text()
    assert '$("follow-logs").checked && nearBottom' in source
    assert "logPanel.scrollHeight - logPanel.scrollTop" in source
    # Completion routing is expected to select the first meaningful result.
    assert "scrollToAnalysisTop" in source or "scrollTop = 0" in source
