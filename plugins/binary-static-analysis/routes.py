"""Read-only metadata routes registered below the plugin namespace."""


def about(request, context):
    """Return static capabilities; accepts no path and performs no evidence I/O."""
    return {
        "plugin": "binary-static-analysis",
        "mode": "static-read-only",
        "network": False,
        "executes_samples": False,
        "graphs": ["file_structure", "code_analysis"],
    }
