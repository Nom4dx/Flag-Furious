"""Read-only plugin metadata route; recovery jobs use the core broker API."""
def about(request,context):
    """Return capabilities without exposing secrets or host paths."""
    return {"id":"bruteforce","network":False,"remote_attacks":False,"secret_storage":"ephemeral-memory","wordlists":"configurable"}
