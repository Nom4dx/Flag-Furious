"""Naming, extension and risk metadata for recognized passive formats."""

FORMAT_EXTENSIONS = {
    "pdf": ".pdf", "zip": ".zip", "png": ".png", "jpeg": ".jpg",
    "gif": ".gif", "wav": ".wav", "webp": ".webp", "riff": ".riff",
    "gzip": ".gz", "bzip2": ".bz2", "xz": ".xz", "7z": ".7z",
    "rar": ".rar", "elf": ".elf", "pe": ".exe", "macho": ".macho",
    "sqlite": ".sqlite", "java_class": ".class", "wasm": ".wasm",
    "tar": ".tar", "cpio": ".cpio", "iso9660": ".iso", "ole": ".ole",
    "xml": ".xml", "html": ".html", "script": ".txt", "shell_script": ".sh", "python_script": ".py", "javascript": ".js", "powershell": ".ps1", "batch": ".bat",
}


def safe_extension(format_name: str) -> str:
    """Return a controlled suffix for carved output, never user-controlled text."""
    return FORMAT_EXTENSIONS.get(format_name, ".bin")
