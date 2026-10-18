"""Suricata EVE JSON parser retaining event_type and flow_id correlation keys."""
from .jsonl import parse as _parse
def parse(data,source,context):
    """Parse EVE records and label them without flattening protocol subobjects."""
    return [{**row,"parser":"suricata_eve"} for row in _parse(data,source,context)]
