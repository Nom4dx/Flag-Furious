"""Exec a child after applying per-file output and private-file limits.

This helper exists so worker threads never need ``preexec_fn``. Resource limits
are applied in this isolated process immediately before replacing it with the
requested tool.
"""
from __future__ import annotations

import os
import resource
import sys


def main() -> None:
    limit = max(0, int(sys.argv[1]))
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    ceiling = hard if hard != resource.RLIM_INFINITY else limit
    resource.setrlimit(resource.RLIMIT_FSIZE, (min(limit, ceiling), hard))
    os.umask(0o077)
    command = sys.argv[2:]
    if not command:
        raise SystemExit(127)
    os.execvpe(command[0], command, os.environ)


if __name__ == "__main__":
    main()
