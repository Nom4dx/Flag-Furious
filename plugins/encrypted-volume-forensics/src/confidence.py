"""Small evidence-based confidence helpers; values never encode certainty."""


def volume_confidence(valid_boot: bool, libbde: bool, metadata_copies: int) -> float:
    """Score independent structural confirmations with a conservative cap."""
    return min(.99,.5+(.25 if valid_boot else 0)+(.19 if libbde else 0)+min(.05,metadata_copies*.02))
