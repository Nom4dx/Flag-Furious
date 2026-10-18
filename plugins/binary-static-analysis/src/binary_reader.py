"""Read-only bounded random-access reader for untrusted binary structures.

Every read is checked against the physical size and a cumulative byte budget.
The reader never maps a writable view and never follows data-derived paths.
"""

from pathlib import Path
import struct

from .bounds import checked_range


class BinaryReader:
    """Provide bounded reads and endian-aware unpacking over one regular file.

    Input is a non-symlink path and a positive read budget. ``read`` and
    ``unpack`` raise ``ValueError`` for invalid ranges/budget exhaustion and
    ``OSError`` for filesystem failures. Callers must cap table counts too.
    """

    def __init__(self, path: Path, budget: int):
        self.path = Path(path)
        if not self.path.is_file() or self.path.is_symlink():
            raise ValueError("È richiesto un file regolare non simbolico")
        self.size = self.path.stat().st_size
        self.budget = max(0, int(budget))
        self.bytes_read = 0

    def read(self, offset: int, length: int) -> bytes:
        """Read an exact validated interval without changing the evidence."""
        checked_range(offset, length, self.size, "read")
        if length > self.budget - self.bytes_read:
            raise ValueError("Byte budget del parser esaurito")
        with self.path.open("rb") as source:
            source.seek(offset)
            value = source.read(length)
        if len(value) != length:
            raise ValueError("Lettura binaria troncata")
        self.bytes_read += length
        return value

    def unpack(self, fmt: str, offset: int) -> tuple:
        """Unpack one fixed-size structure after bounds checking.

        Example: ``reader.unpack('<I', 0)``. Variable-size strings are not
        accepted; ``struct.error`` is normalized to ``ValueError``.
        """
        try:
            return struct.unpack(fmt, self.read(offset, struct.calcsize(fmt)))
        except struct.error as exc:
            raise ValueError(f"Struttura non valida: {exc}") from exc

    def view(self, offset: int, length: int, maximum: int = 1024 * 1024) -> bytes:
        """Return a capped view for heuristics, never more than ``maximum``."""
        return self.read(offset, min(length, maximum))
