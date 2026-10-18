"""Graylog GELF JSON parser; chunked network transport is intentionally absent."""
from .jsonl import parse as _parse
def parse(data,source,context):
    """Parse local GELF JSON and identify canonical version/host/message fields."""
    return [{**row,"parser":"gelf"} for row in _parse(data,source,context)]
