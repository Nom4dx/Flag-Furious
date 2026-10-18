"""Integer range validation shared by binary parsers.

The helpers reject negative, wrapped or out-of-file intervals before a parser
seeks. They return plain integers/booleans, raise ``ValueError`` for malformed
declarations and never allocate according to an untrusted length.
"""


def checked_range(offset: int, length: int, size: int, label: str = "range") -> tuple[int, int]:
    """Validate ``[offset, offset+length)`` against a physical file size.

    Example: ``checked_range(64, 32, 4096)`` returns ``(64, 96)``. Negative
    values and ranges past EOF raise ``ValueError``. The function has no I/O.
    """
    if not all(isinstance(value, int) for value in (offset, length, size)):
        raise ValueError(f"{label}: valori non interi")
    if offset < 0 or length < 0 or size < 0 or offset > size or length > size - offset:
        raise ValueError(f"{label}: intervallo fuori dai limiti")
    return offset, offset + length


def aligned(value: int, alignment: int) -> bool:
    """Return whether an integer respects a positive alignment."""
    return alignment > 0 and value >= 0 and value % alignment == 0
