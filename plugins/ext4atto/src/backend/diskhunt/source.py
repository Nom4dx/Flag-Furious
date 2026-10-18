from __future__ import annotations
import gzip
import ipaddress
import lzma
import shutil
import subprocess
import resource
from pathlib import Path
from urllib.parse import urlparse
import zstandard


COMPRESSED_SUFFIXES = {".gz", ".xz", ".zst"}


def _file_size_limit(max_output_bytes: int):
    """Apply a per-file output ceiling to disk-producing converter processes."""
    def apply():
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_output_bytes, max_output_bytes))
    return apply


def _copy_bounded(source, destination, limit: int, written: int = 0) -> int:
    while True:
        block = source.read(min(1024 * 1024, limit - written + 1))
        if not block:
            return written
        written += len(block)
        if written > limit:
            raise ValueError("prepared_image_budget_exceeded")
        destination.write(block)


def prepare_image(upload: Path, workdir: Path, max_output_bytes: int = 512 * 1024**2) -> tuple[Path, str]:
    """Return a local, immutable analysis source; decompress/merge without altering upload."""
    suffix = upload.suffix.lower()
    analysis_dir = workdir / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    for existing in (analysis_dir / "image.raw", analysis_dir / "segmented.raw"):
        if existing.exists():
            if existing.stat().st_size > max_output_bytes: raise ValueError("prepared_image_budget_exceeded")
            return existing, "prepared raw analysis image"
    if suffix in COMPRESSED_SUFFIXES:
        output = analysis_dir / "image.raw"
        if suffix == ".gz":
            source = gzip.open(upload, "rb")
        elif suffix == ".xz":
            source = lzma.open(upload, "rb")
        else:
            source = zstandard.open(upload, "rb")
        try:
            with source, output.open("xb") as dst:
                _copy_bounded(source, dst, max_output_bytes)
        except (OSError, ValueError):
            output.unlink(missing_ok=True)
            raise
        output.chmod(0o400)
        return output, f"compressed {suffix} raw image"
    if suffix == ".001":
        output = analysis_dir / "segmented.raw"
        stem = upload.with_suffix("")
        written = 0
        try:
            with output.open("xb") as dst:
                index = 1
                while (part := Path(f"{stem}.{index:03d}")).exists():
                    with part.open("rb") as src:
                        written = _copy_bounded(src, dst, max_output_bytes, written)
                    index += 1
        except (OSError, ValueError):
            output.unlink(missing_ok=True)
            raise
        if index == 1:
            output.unlink(missing_ok=True)
            raise ValueError("segmented_image_missing")
        output.chmod(0o400)
        return output, f"segmented raw image ({index - 1} parts)"
    if suffix in {".vhd", ".vmdk", ".qcow2"}:
        output = analysis_dir / "image.raw"
        binary = shutil.which("qemu-img")
        if not binary: raise RuntimeError("qemu-img is required for virtual disk conversion")
        try:
            subprocess.run([binary, "convert", "-f", suffix[1:], "-O", "raw", str(upload), str(output)], check=True, timeout=1800, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=_file_size_limit(max_output_bytes))
        except (OSError, subprocess.SubprocessError):
            output.unlink(missing_ok=True)
            raise
        if output.stat().st_size > max_output_bytes:
            output.unlink(missing_ok=True)
            raise ValueError("prepared_image_budget_exceeded")
        output.chmod(0o400); return output, f"{suffix[1:].upper()} converted to raw"
    if suffix == ".e01":
        binary = shutil.which("ewfexport")
        if not binary: raise RuntimeError("ewfexport is required for E01 conversion")
        target = analysis_dir / "ewf"
        try:
            subprocess.run([binary, "-u", "-t", str(target), str(upload)], check=True, timeout=1800, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=_file_size_limit(max_output_bytes))
        except (OSError, subprocess.SubprocessError):
            for generated in analysis_dir.glob("ewf*"):
                if generated.is_file(): generated.unlink(missing_ok=True)
            raise
        candidates = [target, Path(str(target) + ".raw")]
        output = next((path for path in candidates if path.exists()), None)
        if not output: raise RuntimeError("ewfexport did not produce a raw image")
        generated = [path for path in analysis_dir.glob("ewf*") if path.is_file()]
        if sum(path.stat().st_size for path in generated) > max_output_bytes:
            for path in generated: path.unlink(missing_ok=True)
            raise ValueError("prepared_image_budget_exceeded")
        output.chmod(0o400); return output, "E01 converted to raw"
    output = analysis_dir / "image.raw"
    try:
        with upload.open("rb") as src, output.open("xb") as dst:
            _copy_bounded(src, dst, max_output_bytes)
    except (OSError, ValueError):
        output.unlink(missing_ok=True)
        raise
    output.chmod(0o400)
    return output, "raw disk image"


def validate_nbd_url(url: str, allowlist: set[str], enabled: bool) -> tuple[str, int]:
    if not enabled:
        raise ValueError("NBD support is disabled")
    parsed = urlparse(url)
    if parsed.scheme not in {"nbd", "nbds"} or not parsed.hostname:
        raise ValueError("only nbd:// or nbds:// TCP endpoints are accepted")
    host = parsed.hostname
    try:
        address = ipaddress.ip_address(host)
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
            raise ValueError("private, local and reserved NBD targets are forbidden")
    except ValueError as exc:
        if str(exc).startswith("private"):
            raise
        if host not in allowlist:
            raise ValueError("DNS names must appear in the NBD allowlist") from exc
    if host not in allowlist:
        raise ValueError("NBD target is not allowlisted")
    return host, parsed.port or 10809
