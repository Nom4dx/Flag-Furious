"""Confidence helpers keeping evidence quality separate from severity."""
def clamp(value: float) -> float:
    """Clamp a computed confidence to the normalized zero-to-one range."""
    return round(max(0.0,min(1.0,float(value))),3)

def combine(*values: float) -> float:
    """Combine independent bounded evidence without ever reaching certainty."""
    score=1.0
    for value in values: score*=1-clamp(value)
    return clamp(min(.99,1-score))
