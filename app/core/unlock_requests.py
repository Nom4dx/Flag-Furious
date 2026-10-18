"""Shared contract for plugins requesting local password recovery."""


def request(artifact_id, protection_type, parent_plugin, adapters, **metadata):
    """Build a password-free request for the bruteforce broker/UI."""
    return {"artifact_id": artifact_id, "protection_type": protection_type,
            "supported_adapters": adapters, "parent_plugin": parent_plugin,
            "ui_required": True, "allow_wordlists": True,
            "status": "waiting_for_user", "metadata": metadata}
