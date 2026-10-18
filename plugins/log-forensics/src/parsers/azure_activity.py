"""Azure Activity and sign-in JSON parser."""
from .jsonl import parse as _parse
def parse(data,source,context):
    """Parse local Azure records while preserving nested claims and properties."""
    return [{**row,"parser":"azure_activity"} for row in _parse(data,source,context)]
