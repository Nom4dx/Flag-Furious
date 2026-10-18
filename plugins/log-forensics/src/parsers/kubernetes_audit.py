"""Kubernetes audit JSON parser retaining user, objectRef, stage and request URI."""
from .jsonl import parse as _parse
def parse(data,source,context):
    """Parse audit events and preserve request/response objects as raw fields."""
    return [{**row,"parser":"kubernetes_audit"} for row in _parse(data,source,context)]
