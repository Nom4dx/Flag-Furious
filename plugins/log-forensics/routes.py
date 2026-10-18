"""Read-only plugin capability routes; no evidence is opened here."""
def about(request: dict, context: dict) -> dict:
    """Return the offline execution and normalization contract."""
    return {"plugin":"log-forensics","mode":"offline-read-only","network":False,"event_model":"ECS-inspired with raw provenance","sigma":"local rules only"}
