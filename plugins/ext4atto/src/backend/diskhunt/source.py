from __future__ import annotations
import gzip
import ipaddress
import json
import lzma
import shutil
import subprocess
import resource
from pathlib import Path
from urllib.parse import urlparse
from .bounded_process import run_bounded
import zstandard


COMPRESSED_SUFFIXES = {".gz", ".xz", ".zst"}
QEMU_SUFFIXES = {".vhd", ".vhdx", ".vmdk", ".qcow", ".qcow2", ".vdi", ".qed"}
QEMU_FORMATS = {"vpc", "vhdx", "vmdk", "qcow", "qcow2", "vdi", "qed"}


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


def _qemu_info(path: Path) -> tuple[str | None, str | None]:
    binary = shutil.which("qemu-img")
    if not binary:
        return None, None
    result = run_bounded([binary, "info", "--output=json", str(path)], timeout=30,
                         max_stdout=64 * 1024, max_stderr=64 * 1024)
    if result["returncode"] or result["timed_out"] or result["truncated"]:
        raise RuntimeError("qemu-img could not identify the virtual image safely")
    try:
        info = json.loads(result["stdout"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("qemu-img returned invalid image metadata") from exc
    if info.get("backing-filename") or info.get("full-backing-filename"):
        raise RuntimeError("virtual disk backing files are not followed")
    image_format = info.get("format")
    if not isinstance(image_format, str) or not image_format:
        raise RuntimeError("qemu-img did not identify an image format")
    return binary, image_format


def _known_virtual_signature(path: Path) -> bool:
    with path.open("rb") as source:
        head = source.read(128)
        size = source.seek(0, 2)
        footer = b""
        if size >= 512:
            source.seek(-512, 2)
            footer = source.read(8)
    return (
        head.startswith((b"QFI\xfb", b"KDMV", b"vhdxfile", b"QED"))
        or b"<<< Oracle VM VirtualBox Disk Image >>>" in head
        or head.startswith(b"EVF\x09\x0d\x0a\xff\x00")
        or footer == b"conectix"
    )


def _convert_qemu(path: Path, output: Path, binary: str, image_format: str,
                  max_output_bytes: int) -> Path:
    if image_format not in QEMU_FORMATS:
        raise RuntimeError(f"unsupported qemu image format: {image_format or 'unknown'}")
    temporary = output.with_name(output.name + ".partial")
    if temporary.is_symlink():
        raise ValueError("unsafe virtual image output")
    temporary.unlink(missing_ok=True)
    try:
        subprocess.run(
            [binary, "convert", "-f", image_format, "-O", "raw", str(path), str(temporary)],
            check=True, timeout=1800, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, preexec_fn=_file_size_limit(max_output_bytes),
        )
        if not temporary.is_file() or temporary.stat().st_size > max_output_bytes:
            raise ValueError("prepared_image_budget_exceeded")
        temporary.chmod(0o400)
        temporary.replace(output)
    except (OSError, subprocess.SubprocessError, ValueError):
        temporary.unlink(missing_ok=True)
        raise
    return output


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
        unpacked = analysis_dir / "decompressed.img"
        if unpacked.is_symlink():
            raise ValueError("unsafe decompression output")
        unpacked.unlink(missing_ok=True)
        if suffix == ".gz":
            source = gzip.open(upload, "rb")
        elif suffix == ".xz":
            source = lzma.open(upload, "rb")
        else:
            source = zstandard.open(upload, "rb")
        try:
            with source, unpacked.open("xb") as dst:
                _copy_bounded(source, dst, max_output_bytes)
        except (OSError, EOFError, ValueError, lzma.LZMAError, zstandard.ZstdError):
            unpacked.unlink(missing_ok=True)
            raise
        try:
            binary, image_format = _qemu_info(unpacked)
        except Exception:
            unpacked.unlink(missing_ok=True)
            raise
        if image_format and image_format != "raw":
            if not binary:
                unpacked.unlink(missing_ok=True)
                raise RuntimeError("qemu-img is required for the compressed virtual disk format")
            try:
                _convert_qemu(unpacked, output, binary, image_format, max_output_bytes)
            finally:
                unpacked.unlink(missing_ok=True)
            return output, f"compressed {suffix} {image_format} converted to raw"
        if not binary and _known_virtual_signature(unpacked):
            unpacked.unlink(missing_ok=True)
            raise RuntimeError("qemu-img is required to identify or convert this compressed virtual image")
        unpacked.chmod(0o400)
        unpacked.replace(output)
        return output, f"compressed {suffix} raw image"
    if suffix == ".001":
        output = analysis_dir / "segmented.raw"
        stem = upload.with_suffix("")
        written = 0
        try:
            with output.open("xb") as dst:
                index = 1
                while (part := Path(f"{stem}.{index:03d}")).exists():
                    if part.is_symlink() or not part.is_file():
                        raise ValueError("unsafe_segmented_image_part")
                    if index > 10_000:
                        raise ValueError("segmented_image_part_limit")
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
    if suffix in QEMU_SUFFIXES:
        output = analysis_dir / "image.raw"
        binary, image_format = _qemu_info(upload)
        if image_format == "raw":
            return upload, "raw image validated by qemu-img despite virtual disk suffix"
        if not binary:
            raise RuntimeError("qemu-img is required for virtual disk conversion")
        converted = _convert_qemu(upload, output, binary, image_format, max_output_bytes)
        return converted, f"{image_format.upper()} converted to raw"
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
