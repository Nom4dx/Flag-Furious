"""Google Cloud Audit JSON parser preserving protoPayload and resource labels."""
from .jsonl import parse as _parse
def parse(data,source,context):
    """Parse local GCP audit records without external lookups."""
    return [{**row,"parser":"gcp_audit"} for row in _parse(data,source,context)]
