"""Bounded artifact reads shared by local password adapters."""
import hashlib


class BoundedWriter:
    """Seekable file wrapper that rejects writes beyond a byte ceiling."""
    def __init__(self, stream, limit):
        self._stream = stream
        self._limit = max(0, int(limit))

    def write(self, data):
        if self._stream.tell() + len(data) > self._limit:
            raise ValueError('derived_output_limit')
        return self._stream.write(data)

    def seek(self, offset, whence=0):
        current = self._stream.tell()
        if whence == 0:
            target = offset
        elif whence == 1:
            target = current + offset
        elif whence == 2:
            self._stream.seek(0, 2)
            target = self._stream.tell() + offset
            self._stream.seek(current)
        else:
            raise ValueError('invalid_seek_origin')
        if target < 0 or target > self._limit:
            raise ValueError('derived_output_limit')
        return self._stream.seek(target)

    def tell(self):
        return self._stream.tell()

    def flush(self):
        return self._stream.flush()

    def truncate(self, size=None):
        target = self.tell() if size is None else size
        if target < 0 or target > self._limit:
            raise ValueError('derived_output_limit')
        return self._stream.truncate(target)

    def fileno(self):
        return self._stream.fileno()

    def writable(self):
        return True

    def seekable(self):
        return True


def digest_file(path, limit):
    """Hash a regular output file without reading it all into memory.

    Returns metadata only when the entire file fits in the caller's budget;
    oversized derived files are rejected so partial hashes are never presented
    as artifact identity.
    """
    digest = hashlib.sha256()
    size = 0
    with open(path, 'rb') as source:
        while True:
            chunk = source.read(min(1024 * 1024, limit - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise ValueError('derived_output_limit')
            digest.update(chunk)
    return {'sha256': digest.hexdigest(), 'size': size}


def read_bounded(path, limit):
    """Read at most limit bytes, rejecting oversized inputs."""
    with open(path, 'rb') as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError('artifact_input_limit')
    return data


def extracted(path, limit, detected_type='binary'):
    metadata = digest_file(path, limit)
    from pathlib import Path
    target = Path(path)
    return {'path': str(target), 'name': target.name, **metadata,
            'status': 'extracted', 'detected_type': detected_type}
