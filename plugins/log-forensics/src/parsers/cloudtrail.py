"""AWS CloudTrail JSON parser preserving account, region, request and identity."""
from .jsonl import parse as _parse
def parse(data,source,context):
    """Parse CloudTrail Records arrays without masking the authorized raw artifact."""
    return [{**row,"parser":"aws_cloudtrail"} for row in _parse(data,source,context)]
