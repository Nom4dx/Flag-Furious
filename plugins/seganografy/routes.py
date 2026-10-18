"""Read-only custom route handlers declared by the plugin manifest."""


def about(request: dict, context: dict) -> dict:
    """Return capabilities, alias and security posture without accessing evidence."""
    return {"id":"seganografy","alias":"steganography-forensics","name":"Steganography Forensics","execution":"isolated, offline, static only","password_attacks":"only an explicitly supplied password; no unbounded brute force"}
