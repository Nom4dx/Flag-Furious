"""Bounded artifact reads shared by local password adapters."""
import hashlib


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
