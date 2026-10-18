"""Read-only capability endpoint; it never opens evidence or accepts secrets."""


def about(request: dict, context: dict) -> dict:
    """Return the public execution contract for UI capability discovery."""
    return {
        "plugin": "encrypted-volume-forensics",
        "priority_format": "BitLocker/FVE",
        "mode": "offline-read-only",
        "network": False,
        "secrets_persisted": False,
        "unlock_requires_explicit_action": True,
    }
