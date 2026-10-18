"""Explain executable/script prefixes followed by a validated archive."""


def analyze_sfx(formats: list[dict]) -> list[dict]:
    """Return SFX relationships from validated executable and archive intervals."""
    executables = [x for x in formats if x["format"] in {"pe", "elf", "macho", "script", "shell_script", "python_script", "javascript", "powershell", "batch"}]
    archives = [x for x in formats if x["format"] in {"zip", "7z", "rar", "tar"}]
    return [{"type": "sfx", "prefix_format": exe["format"], "archive_format": arc["format"], "archive_offset": arc["start_offset"], "confidence": min(exe["confidence"], arc["confidence"]), "executed": False} for exe in executables for arc in archives if arc["start_offset"] > exe["start_offset"]]
