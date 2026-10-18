"""Stable loader entrypoint for Document Metadata Forensics.

The hub imports this module inside its isolated worker. Keeping this shim small
allows the implementation package to evolve without changing the manifest.
"""

from .plugin import Plugin

__all__ = ["Plugin"]
