"""Path and extraction safety helpers."""
import re,stat
from pathlib import Path,PurePosixPath
def local_file(path,allowed_roots=None):
    """Require a regular non-symlink local artifact, optionally beneath roots."""
    p=Path(path).resolve()
    if not p.is_file() or p.is_symlink():raise ValueError('artifact_not_local_regular_file')
    if allowed_roots and not any(p.is_relative_to(Path(r).resolve()) for r in allowed_roots):raise ValueError('artifact_outside_authorized_case')
    return p
def member_safe(name,mode=0):
    """Reject Zip Slip, drive paths, NUL and symlinks."""
    p=PurePosixPath(name.replace('\\','/'))
    return not (p.is_absolute() or '..' in p.parts or '\0' in name or re.match(r'^[A-Za-z]:',name) or stat.S_ISLNK(mode))
