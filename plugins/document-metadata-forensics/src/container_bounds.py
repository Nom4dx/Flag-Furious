"""Preflight ZIP metadata before stdlib ZIP parsing allocates member objects."""
from __future__ import annotations

import io
import struct
import zipfile

MAX_CENTRAL_DIRECTORY_BYTES = 4 * 1024**2
MAX_CENTRAL_DIRECTORY_ENTRIES = 20_000


def central_directory_info(data: bytes) -> tuple[int, int] | None:
    """Return (central directory bytes, entries) from EOCD/Zip64 metadata."""
    try:
        end_record = zipfile._EndRecData(io.BytesIO(data))
        if end_record is None:
            return None
        return int(end_record[zipfile._ECD_SIZE]), int(end_record[zipfile._ECD_ENTRIES_TOTAL])
    except (IndexError, TypeError, ValueError, OverflowError, struct.error, OSError):
        return None
