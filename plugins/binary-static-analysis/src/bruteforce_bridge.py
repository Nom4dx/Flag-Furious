"""Password-request bridge to the shared ``bruteforce`` connector.

This module only creates password-free requests. It does not attempt keys and
does not persist secrets; user interaction occurs later in the connector workflow.
"""


def requests_from(indicators:list[dict],requests:list[dict])->list[dict]:
    """Deduplicate broker requests while retaining protected-format provenance."""
    unique={}
    for item in requests:
        key=(item.get("artifact_id"),item.get("protection_type"),item.get("metadata",{}).get("offset"));unique[key]={**item,"source_plugin":"binary-static-analysis","request_bruteforce":True}
    return list(unique.values())
